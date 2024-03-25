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

static struct linux_kernel_params boot_params = {0};

static grub_err_t
sl_efi_install_slr_table (struct grub_slaunch_params *slparams)
{
  grub_guid_t slrt_guid = GRUB_UEFI_SLR_TABLE_GUID;
  grub_efi_boot_services_t *b;
  grub_efi_status_t status;

  b = grub_efi_system_table->boot_services;
  status = b->install_configuration_table (&slrt_guid, (void *)slparams->slr_table_base);
  if (status != GRUB_EFI_SUCCESS)
    return grub_error (GRUB_ERR_BAD_OS, "cannot load image");

  return GRUB_ERR_NONE;
}

static grub_err_t
sl_efi_locate_mle_offset (struct grub_slaunch_params *slparams,
                          void *kernel_addr, grub_ssize_t kernel_start)
{
  struct linux_kernel_params *lh = (struct linux_kernel_params *)kernel_addr;
  struct linux_kernel_info kernel_info;

  /* Locate the MLE header offset in kernel_info section */
  grub_memcpy ((void *)&kernel_info,
               (char *)kernel_addr + kernel_start + grub_le_to_cpu32 (lh->kernel_info_offset),
               sizeof (struct linux_kernel_info));

  if (OFFSET_OF (mle_header_offset, &kernel_info) >= grub_le_to_cpu32 (kernel_info.size))
    return grub_error (GRUB_ERR_BAD_OS, N_("not slaunch kernel: lack of mle_header_offset"));

  slparams->mle_header_offset = grub_le_to_cpu32 (kernel_info.mle_header_offset);

  return GRUB_ERR_NONE;
}

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

  slparams->slr_table_base = (grub_uint64_t)slmem;
  slparams->slr_table_size = GRUB_EFI_PAGE_SIZE;
  slparams->slr_table_mem = slmem;

  slparams->tpm_evt_log_base = (grub_uint64_t)(slmem + GRUB_EFI_PAGE_SIZE);
  slparams->tpm_evt_log_size = GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE;

  slparams->ap_wake_block = (grub_uint32_t)(grub_uint64_t)(slmem + GRUB_EFI_PAGE_SIZE + GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE);
  slparams->ap_wake_block_size = GRUB_EFI_MLE_AP_WAKE_BLOCK_SIZE;

  *slmem_size_out = slmem_size;
  return slmem;
}

grub_err_t
grub_sl_efi_txt_setup (struct grub_slaunch_params *slparams, void *kernel_addr,
                       grub_efi_loaded_image_t *loaded_image)
{
  struct linux_kernel_params *lh = (struct linux_kernel_params *)kernel_addr;
  grub_uint64_t image_base = (grub_uint64_t)loaded_image->image_base;
  grub_efi_uint64_t image_size = loaded_image->image_size;
  grub_efi_physical_address_t requested;
  grub_ssize_t start;
  grub_err_t err;
  void *addr;
  void *slmem = NULL;
  grub_uint32_t slmem_size = 0;

  slparams->boot_type = GRUB_SL_BOOT_TYPE_EFI;
  slparams->platform_type = grub_slaunch_platform_type ();

  /*
   * Dummy empty boot params structure for now. EFI stub will create a boot params
   * and populate it. The SL code in EFI stub will update the boot params structure
   * in the OSMLE data and SLRT.
   */
  slparams->boot_params = &boot_params;
  slparams->boot_params_base = (grub_uint64_t)&boot_params;

  /*
   * Note that while the boot params on the zero page are not used or updated during a Linux
   * UEFI boot through the PE header, the values placed there in the bzImage during the build
   * are still valid and can be treated as boot params for certain things.
   */
  start = (lh->setup_sects + 1) * 512;

  /* Allocate page tables for TXT just in front of the kernel image */
  slparams->mle_ptab_size = grub_txt_get_mle_ptab_size (image_size);
  slparams->mle_ptab_size = ALIGN_UP (slparams->mle_ptab_size, GRUB_TXT_PMR_ALIGN);
  requested = ALIGN_DOWN ((image_base - slparams->mle_ptab_size),
                            GRUB_TXT_PMR_ALIGN);

  addr = grub_efi_allocate_pages_real (requested,
                                       GRUB_EFI_BYTES_TO_PAGES(slparams->mle_ptab_size),
                                       GRUB_EFI_ALLOCATE_ADDRESS,
                                       GRUB_EFI_LOADER_DATA);
  if (!addr)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  slparams->mle_ptab_mem = addr;
  slparams->mle_ptab_target = (grub_uint64_t)addr;

  /*
   * For the MLE, skip the zero page and startup section of the binary. The MLE
   * begins with the protected mode .text section which follows. The MLE header
   * and MLE entry point are RVA's from the beginning of .text where startup_32
   * begins.
   *
   * Note, to do the EFI boot, the entire bzImage binary is loaded since the PE
   * header is in the startup section before the protected mode piece begins.
   * In legacy world this part of the image would have been stripped off.
   */
  slparams->mle_start = image_base + start;
  slparams->mle_size = image_size - start;

  /* Setup the TXT ACM page tables */
  grub_txt_setup_mle_ptab (slparams);

  /* Allocate a block of memory for Secure Launch entities */
  slmem = sl_efi_txt_setup_slmem (slparams, (grub_efi_physical_address_t)addr,
                                  &slmem_size);
  if (!slmem)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      goto fail;
    }

  err = sl_efi_locate_mle_offset (slparams, kernel_addr, start);
  if (err != GRUB_ERR_NONE)
    goto fail;

  /* Final stage for secure launch, setup TXT and install the SLR table */
  err = grub_txt_boot_prepare (slparams);
  if (err != GRUB_ERR_NONE)
    goto fail;

  err = sl_efi_install_slr_table (slparams);
  if (err != GRUB_ERR_NONE)
    goto fail;

  return GRUB_ERR_NONE;

fail:

  if (slmem && slmem_size)
    grub_efi_free_pages ((grub_addr_t)slmem, slmem_size);

  grub_efi_free_pages ((grub_addr_t)addr, slparams->mle_ptab_size);

  return err;
}
