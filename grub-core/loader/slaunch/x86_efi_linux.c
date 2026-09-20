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
#include <grub/i386/skinit.h>

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

/* Traverses sections of a loaded EFI image to map an offset within a file to
 * an offset within the image. Returns appropriately casted -1 on error. */
static grub_efi_uint64_t
foffset_to_voffset(grub_efi_loaded_image_t *image, grub_uint32_t foffset)
{
  struct grub_msdos_image_header *header;
  struct grub_pe_image_header *pe_image_header;
  struct grub_pe32_coff_header *coff_header;
  struct grub_pe32_section_table *sections;
  struct grub_pe32_section_table *section;
  grub_uint16_t i;
  grub_uint32_t loaded_section;

  header = image->image_base;
  pe_image_header = (struct grub_pe_image_header *)
      ((char *) header + header->pe_image_header_offset);
  coff_header = &pe_image_header->coff_header;
  sections = (struct grub_pe32_section_table *)
      ((char *) coff_header + sizeof (*coff_header)
       + coff_header->optional_header_size);

  loaded_section = GRUB_PE32_SCN_CNT_CODE | GRUB_PE32_SCN_CNT_INITIALIZED_DATA;
  for (i = 0, section = sections; i < coff_header->num_sections; i++, section++)
    {
      grub_uint32_t fstart = section->raw_data_offset;
      grub_uint32_t fend = fstart + section->raw_data_size;

      if ((section->characteristics & loaded_section) != 0 &&
          foffset >= fstart && foffset < fend)
        {
          return section->virtual_address + (foffset - fstart);
        }
    }

  return ~(grub_efi_uint64_t)0;
}

static grub_err_t
sl_efi_load_mle_data (struct grub_slaunch_params *slparams,
                      void *kernel_addr, grub_ssize_t kernel_start,
                      grub_efi_loaded_image_t *loaded_image,
                      bool is_linux)
{
  struct linux_kernel_params *lh = (struct linux_kernel_params *)kernel_addr;
  struct linux_kernel_info kernel_info;
  struct grub_txt_mle_header *mle_hdr;
  grub_uint64_t mle_hdr_offset;

  if (is_linux)
    {
      /* Locate the MLE header offset in kernel_info section */
      grub_memcpy ((void *)&kernel_info,
                   (char *)kernel_addr + kernel_start + grub_le_to_cpu32 (lh->kernel_info_offset),
                   sizeof (struct linux_kernel_info));

      if (OFFSET_OF (mle_header_offset, &kernel_info) >= grub_le_to_cpu32 (kernel_info.size))
        {
          grub_dprintf ("slaunch", "not an slaunch kernel: lack of mle_header_offset\n");
          return GRUB_ERR_BAD_OS;
        }

      mle_hdr_offset = grub_le_to_cpu32 (kernel_info.mle_header_offset);
      mle_hdr = (struct grub_txt_mle_header *)((grub_addr_t)kernel_addr + kernel_start + mle_hdr_offset);

      if (grub_memcmp (mle_hdr->uuid, GRUB_TXT_MLE_UUID, 16) != 0)
        {
          grub_dprintf ("slaunch", "Not an MLE header at 0x%llx\n",
                        (unsigned long long)(grub_addr_t)mle_hdr);
          return GRUB_ERR_BAD_OS;
        }
    }
  else
    {
      for (mle_hdr_offset = 0; mle_hdr_offset < 0x1000; mle_hdr_offset += 16)
        {
          mle_hdr = (struct grub_txt_mle_header *)((grub_addr_t)kernel_addr + mle_hdr_offset);
          if (!grub_memcmp (mle_hdr->uuid, GRUB_TXT_MLE_UUID, 16))
            break;
        }

      if (mle_hdr_offset >= 0x1000)
        {
          grub_dprintf ("slaunch", "not an slaunch kernel: no MLE header found\n");
          return GRUB_ERR_BAD_ARGUMENT;
        }

      mle_hdr_offset = foffset_to_voffset (loaded_image, mle_hdr_offset);
      if (mle_hdr_offset >= (1ULL << 32))
        {
          grub_dprintf ("slaunch", "failed to map MLE header\n");
          return GRUB_ERR_BAD_ARGUMENT;
        }
    }

  slparams->mle_header_offset = mle_hdr_offset;
  slparams->mle_entry = mle_hdr->entry_point;

  if (!is_linux)
    {
      /*
       * The current value of the field covers the whole EFI image which can
       * include a lot of useless padding.  Limit the size used for measuring
       * MLE to that reported by the header.  Don't change the behaviour for
       * Linux in case it causes trouble (needs testing).
       */
      slparams->mle_size = mle_hdr->mle_end - mle_hdr->mle_start;
    }

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

  slparams->slr_table_base = (grub_addr_t)slmem;
  slparams->slr_table_size = GRUB_EFI_PAGE_SIZE;
  slparams->slr_table_mem = slmem;

  slparams->tpm_evt_log_base = (grub_addr_t)(slmem + GRUB_EFI_PAGE_SIZE);
  slparams->tpm_evt_log_size = GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE;
  grub_txt_init_tpm_event_log (slmem + GRUB_EFI_PAGE_SIZE,
                               slparams->tpm_evt_log_size);

  slparams->ap_wake_block = (grub_uint32_t)(grub_addr_t)(slmem + GRUB_EFI_PAGE_SIZE + GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE);
  slparams->ap_wake_block_size = GRUB_EFI_MLE_AP_WAKE_BLOCK_SIZE;

  *slmem_size_out = slmem_size;
  return slmem;
}

static void *
allocate_aligned_efi_pages (grub_efi_physical_address_t max_address,
                            grub_efi_uintn_t pages,
                            grub_efi_memory_type_t memtype,
                            grub_efi_uintn_t alignment)
{
  void *mem;
  grub_efi_uintn_t total_pages;
  grub_efi_uintn_t prefix;
  grub_efi_uintn_t suffix;
  grub_efi_status_t status;
  grub_efi_boot_services_t *b;
  grub_efi_physical_address_t address;

  b = grub_efi_system_table->boot_services;

  if (pages % alignment == 0)
  {
    total_pages = pages;
  }
  else
  {
    /* Overallocate and then free unused */
    total_pages = pages + alignment;
  }

  address = max_address;
  status = b->allocate_pages (GRUB_EFI_ALLOCATE_MAX_ADDRESS, memtype,
                              total_pages, &address);
  if (status != GRUB_EFI_SUCCESS)
    return NULL;

  if (address == 0)
    {
      address = max_address;
      status = b->allocate_pages (GRUB_EFI_ALLOCATE_MAX_ADDRESS, memtype,
                                  total_pages, &address);
      b->free_pages (0, total_pages);
      if (status != GRUB_EFI_SUCCESS)
        return NULL;
    }

  mem = alignment == 0
      ? (void*)address
      : (void *)ALIGN_UP (address, alignment * GRUB_EFI_PAGE_SIZE);

  prefix = GRUB_EFI_BYTES_TO_PAGES ((grub_addr_t)mem - address);
  if (prefix != 0)
    b->free_pages (address, prefix);

  suffix = total_pages - prefix - pages;
  if (suffix != 0)
    b->free_pages ((grub_addr_t)mem + pages * GRUB_EFI_PAGE_SIZE, suffix);

  return mem;
}

grub_err_t
grub_sl_efi_txt_setup (struct grub_slaunch_params *slparams, void *kernel_addr,
                       grub_efi_loaded_image_t *loaded_image, bool is_linux)
{
  struct linux_kernel_params *lh = (struct linux_kernel_params *)kernel_addr;
  grub_addr_t image_base = (grub_addr_t)loaded_image->image_base;
  grub_efi_uint64_t image_size = loaded_image->image_size;
  grub_efi_physical_address_t max_pmap_addr;
  grub_ssize_t start = 0;
  grub_err_t err;
  void *addr;
  void *slmem = NULL;
  grub_uint32_t slmem_size = 0;

  slparams->boot_type = GRUB_SL_BOOT_TYPE_EFI;
  slparams->platform_type = grub_slaunch_platform_type ();

  if (is_linux)
    {
      /*
       * Dummy empty boot params structure for now. EFI stub will create a boot
       * params and populate it. The SL code in EFI stub will update the boot
       * params structure in the OSMLE data and SLRT.
       */
      slparams->boot_params = &boot_params;
      slparams->boot_params_base = (grub_addr_t)&boot_params;

      /*
       * Note that while the boot params on the zero page are not used or
       * updated during a Linux UEFI boot through the PE header, the values
       * placed there in the bzImage during the build are still valid and can
       * be treated as boot params for certain things.
       */
      start = (lh->setup_sects + 1) * 512;
    }

  /* Allocate page tables for TXT somewhere below the kernel image */
  slparams->mle_ptab_size = grub_txt_get_mle_ptab_size (image_size);
  slparams->mle_ptab_size = ALIGN_UP (slparams->mle_ptab_size, GRUB_TXT_PMR_ALIGN);

  max_pmap_addr = ALIGN_DOWN (image_base - slparams->mle_ptab_size,
                              GRUB_TXT_PMR_ALIGN);
  addr = allocate_aligned_efi_pages (max_pmap_addr,
                                     GRUB_EFI_BYTES_TO_PAGES(slparams->mle_ptab_size),
                                     GRUB_EFI_LOADER_DATA,
                                     GRUB_EFI_BYTES_TO_PAGES(GRUB_TXT_PMR_ALIGN));
  if (!addr)
    {
      grub_dprintf ("slaunch", "failed to allocate pmap below 0x%llx\n",
                    (unsigned long long)max_pmap_addr);
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  slparams->mle_ptab_mem = addr;
  slparams->mle_ptab_target = (grub_addr_t)addr;

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

  err = sl_efi_load_mle_data (slparams, kernel_addr, start, loaded_image, is_linux);
  if (err != GRUB_ERR_NONE)
    {
      grub_dprintf ("slaunch", N_("failed to load MLE data\n"));
      goto fail;
    }

  /* Final stage for secure launch, setup TXT and install the SLR table */
  err = grub_txt_boot_prepare (slparams);
  if (err != GRUB_ERR_NONE)
    {
      grub_dprintf ("slaunch", N_("failed to prepare TXT\n"));
      goto fail;
    }

  err = sl_efi_install_slr_table (slparams);
  if (err != GRUB_ERR_NONE)
    {
      grub_dprintf ("slaunch", N_("failed to register SLRT with UEFI\n"));
      goto fail;
    }

  return GRUB_ERR_NONE;

fail:

  if (slmem && slmem_size)
    grub_efi_free_pages ((grub_addr_t)slmem, GRUB_EFI_BYTES_TO_PAGES(slmem_size));

  grub_efi_free_pages ((grub_addr_t)addr, GRUB_EFI_BYTES_TO_PAGES(slparams->mle_ptab_size));

  return err;
}

grub_err_t
grub_sl_efi_skinit_setup (struct grub_slaunch_params *slparams, void *kernel_addr,
                          grub_efi_loaded_image_t *loaded_image, bool is_linux)
{
  struct linux_kernel_params *lh = (struct linux_kernel_params *)kernel_addr;
  grub_addr_t image_base = (grub_addr_t)loaded_image->image_base;
  grub_efi_uint64_t image_size = loaded_image->image_size;
  grub_uint8_t *logmem;
  grub_addr_t max_addr;
  grub_ssize_t start = 0;
  grub_err_t err;

  slparams->boot_type = GRUB_SL_BOOT_TYPE_EFI;
  slparams->platform_type = grub_slaunch_platform_type();

  /* See comment in TXT setup function grub_sl_efi_txt_setup () */
  if (is_linux)
    {
      slparams->boot_params = &boot_params;
      slparams->boot_params_base = (grub_addr_t)&boot_params;

      start = (lh->setup_sects + 1) * 512;
    }

  /* See comment in TXT setup function grub_sl_efi_txt_setup () */
  slparams->mle_start = image_base + start;
  slparams->mle_size = image_size - start;

  max_addr = ALIGN_DOWN ((GRUB_EFI_MAX_USABLE_ADDRESS - GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE),
                          GRUB_PAGE_SIZE);

  logmem = grub_efi_allocate_pages_real (max_addr,
                                         GRUB_EFI_BYTES_TO_PAGES(GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE),
                                         GRUB_EFI_ALLOCATE_MAX_ADDRESS,
                                         GRUB_EFI_LOADER_DATA);
  if (!logmem)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  slparams->tpm_evt_log_base = (grub_addr_t)logmem;
  slparams->tpm_evt_log_size = GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE;
  /* It's OK to call this for AMD SKINIT because SKL erases the log before use. */
  grub_txt_init_tpm_event_log (logmem, slparams->tpm_evt_log_size);

  err = sl_efi_load_mle_data (slparams, kernel_addr, start, loaded_image, is_linux);
  if (err != GRUB_ERR_NONE)
    {
      grub_dprintf ("slaunch", N_("failed to load MLE data\n"));
      goto fail;
    }

  /*
   * AMD SKL final setup may relocate the SKL module. It is also what sets the SLRT and DCE
   * values in slparams so this must be done before final setup and launch below.
   */
  err = grub_skl_setup_module (slparams);
  if (err != GRUB_ERR_NONE)
    goto fail;

  err = grub_skl_prepare_bootloader_data (slparams);
  if (err != GRUB_ERR_NONE)
    goto fail;

  err = sl_efi_install_slr_table (slparams);
  if (err != GRUB_ERR_NONE)
    goto fail;

  return GRUB_ERR_NONE;

fail:
  grub_efi_free_pages ((grub_addr_t)logmem, GRUB_EFI_BYTES_TO_PAGES(GRUB_EFI_SLAUNCH_TPM_EVT_LOG_SIZE));

  return err;
}
