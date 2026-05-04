/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024, Oracle and/or its affiliates.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/charset.h>
#include <grub/command.h>
#include <grub/err.h>
#include <grub/linux.h>
#include <grub/loader.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/efi/efi.h>
#include <grub/efi/memory.h>
#include <grub/x86_64/efi/memory.h>
#include <grub/i386/msr.h>
#include <grub/i386/mmio.h>
#include <grub/i386/memory.h>
#include <grub/i386/linux.h>
#include <grub/i386/txt.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE	0x8000
#define GRUB_EFI_MLE_AP_WAKE_BLOCK_SIZE		0x14000
#define OFFSET_OF(x, y) ((grub_size_t)((grub_uint8_t *)(&(y)->x) - (grub_uint8_t *)(y)))

static void *
sl_efi_txt_setup_slmem (struct grub_slaunch_params *slparams,
                        grub_efi_physical_address_t max_addr,
                        grub_uint32_t *slmem_size_out)
{
  grub_uint8_t *slmem;
  grub_uint32_t slmem_size =
     GRUB_EFI_PAGE_SIZE + GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE + GRUB_EFI_MLE_AP_WAKE_BLOCK_SIZE;

  slmem = grub_efi_allocate_pages_real (max_addr,
                                        GRUB_EFI_BYTES_TO_PAGES(slmem_size),
                                        GRUB_EFI_ALLOCATE_MAX_ADDRESS,
                                        GRUB_EFI_LOADER_DATA);
  if (!slmem)
    return NULL;

  grub_memset (slmem, 0, slmem_size);

  slparams->slr_table_base = (unsigned long) slmem;
  slparams->slr_table_size = GRUB_EFI_PAGE_SIZE;
  slparams->slr_table_mem = slmem;

  slparams->tpm_evt_log_base = (unsigned long) slmem + GRUB_EFI_PAGE_SIZE;
  slparams->tpm_evt_log_size = GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE;

  grub_txt_init_tpm_event_log ((void *)slparams->tpm_evt_log_base, slparams->tpm_evt_log_size);

  slparams->ap_wake_block = (unsigned long) slmem + GRUB_EFI_PAGE_SIZE + GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE;
  slparams->ap_wake_block_size = GRUB_EFI_MLE_AP_WAKE_BLOCK_SIZE;

  *slmem_size_out = slmem_size;
  return slmem;
}

static const grub_guid_t grub_slaunch_protocol_guid = GRUB_SLAUNCH_PROTOCOL_GUID;

static struct {
	struct grub_slaunch_protocol	protocol;
	struct grub_slaunch_params	*slparams;
} slaunch_protocol = {0};

static grub_efi_status_t __grub_efi_api
grub_slaunch_set_image (struct grub_slaunch_protocol *,
			grub_uint64_t dlme_base,
			grub_uint64_t dlme_header_offset,
			grub_uint64_t dlme_table)
{
  struct grub_slaunch_params *slparams = slaunch_protocol.slparams;
  struct grub_txt_mle_header *mle_header;
  grub_efi_physical_address_t requested;
  grub_uint32_t slmem_size = 0;
  grub_efi_status_t status;
  void *slmem = NULL;
  grub_err_t err;
  void *addr;

  mle_header = (struct grub_txt_mle_header *)(grub_addr_t) (dlme_base + dlme_header_offset);

  slparams->mle_start = dlme_base;
  slparams->mle_size = mle_header->mle_end;
  slparams->mle_header_offset = dlme_header_offset;

  slparams->boot_params = (struct linux_kernel_params *) dlme_table;;
  slparams->boot_params_base = (unsigned long) dlme_table;

  /* Allocate page tables for TXT just in front of the kernel image */
  slparams->mle_ptab_size = grub_txt_get_mle_ptab_size (slparams->mle_size);
  slparams->mle_ptab_size = ALIGN_UP (slparams->mle_ptab_size, GRUB_TXT_PMR_ALIGN);
  requested = ALIGN_DOWN ((dlme_base - slparams->mle_ptab_size), GRUB_TXT_PMR_ALIGN);

  addr = grub_efi_allocate_pages_real (requested,
                                       GRUB_EFI_BYTES_TO_PAGES(slparams->mle_ptab_size),
                                       GRUB_EFI_ALLOCATE_ADDRESS,
                                       GRUB_EFI_LOADER_DATA);
  if (!addr)
    {
      return GRUB_EFI_OUT_OF_RESOURCES;
    }

  slparams->mle_ptab_mem = addr;
  slparams->mle_ptab_target = (unsigned long) addr;

  /* Setup the TXT ACM page tables */
  grub_txt_setup_mle_ptab (slparams);

  /* Allocate a block of memory for Secure Launch entities */
  slmem = sl_efi_txt_setup_slmem (slparams, (unsigned long) addr,
                                  &slmem_size);
  if (!slmem)
    {
      status = GRUB_EFI_OUT_OF_RESOURCES;
      goto fail;
    }

  /* Final stage for secure launch, setup TXT and install the SLR table */
  err = grub_txt_boot_prepare (slparams);
  if (err != GRUB_ERR_NONE) {
    status = GRUB_EFI_LOAD_ERROR;
    goto fail;
  }

  err = grub_efi_install_slr_table (slparams);
  if (err != GRUB_ERR_NONE) {
    status = GRUB_EFI_LOAD_ERROR;
    goto fail;
  }

  grub_txt_boot_finalize (slparams);

  return GRUB_EFI_SUCCESS;

fail:

  if (slmem && slmem_size)
    grub_efi_free_pages ((grub_addr_t)slmem, slmem_size);

  grub_efi_free_pages ((grub_addr_t)addr, slparams->mle_ptab_size);

  return status;
}

static  grub_efi_status_t __grub_efi_api
grub_slaunch_launch(struct grub_slaunch_protocol *)
{
  struct grub_slaunch_params *slparams = slaunch_protocol.slparams;
  struct grub_slr_table *slrt = (struct grub_slr_table *)slparams->slr_table_mem;
  struct grub_slr_entry_dl_info *dlinfo;

  dlinfo = grub_slr_next_entry_by_tag (slrt, NULL, GRUB_SLR_ENTRY_DL_INFO);
  dl_entry ((grub_uint64_t)&dlinfo->bl_context);

  /* this should never return */
  return GRUB_EFI_LOAD_ERROR;
}

grub_err_t
grub_sl_efi_txt_setup (struct grub_slaunch_params *slparams,
		       grub_efi_handle_t image_handle)
{
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;

  slparams->boot_type = GRUB_SL_BOOT_TYPE_EFI;
  slparams->platform_type = grub_slaunch_platform_type ();

  slaunch_protocol.protocol.setup_dlem = grub_slaunch_set_image;
  slaunch_protocol.protocol.launch = grub_slaunch_launch;
  slaunch_protocol.slparams = slparams;

  b = grub_efi_system_table->boot_services;
  status = b->install_multiple_protocol_interfaces (&image_handle,
                                                    &grub_slaunch_protocol_guid,
                                                    &slaunch_protocol.protocol,
                                                    NULL);
  if (status != GRUB_EFI_SUCCESS)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("failed to install slaunch protocol"));
      return GRUB_ERR_BAD_ARGUMENT;
    }

  grub_dprintf ("slaunch", "Installed slaunch protocol\n");
  return GRUB_ERR_NONE;
}
