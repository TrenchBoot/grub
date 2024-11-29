/*
 * Copyright (c) 2024, Oracle and/or its affiliates.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <grub/types.h>
#include <grub/err.h>
#include <grub/loader.h>
#include <grub/relocator.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/i386/memory.h>
#include <grub/i386/linux.h>
#include <grub/i386/skinit.h>
#include <grub/efi/efi.h>
#include <grub/efi/memory.h>
#undef GRUB_MEMORY_CPU_HEADER
#include <grub/x86_64/efi/memory.h>

#define SLRT_SIZE GRUB_PAGE_SIZE

#define SLB_MIN_ALIGNMENT 0x10000
#define SLB_SIZE          0x10000

static struct grub_skl_info skl_info = {
  .uuid = {
    0x78, 0xf1, 0x26, 0x8e, 0x04, 0x92, 0x11, 0xe9,
    0x83, 0x2a, 0xc8, 0x5b, 0x76, 0xc4, 0xcc, 0x02,
  },
  .version = GRUB_SKL_VERSION,
  .msb_key_algo = 0x14,
  .msb_key_hash = { 0 },
};

static struct grub_sl_header *skl_module = NULL;
static grub_uint32_t skl_size = 0;

int
grub_skl_set_module (const void *skl_base, grub_uint32_t size)
{
  struct grub_skl_info *info;
  struct grub_sl_header *module = (struct grub_sl_header *) skl_base;

  /* We need unused space after the module to fit SLRT there. */
  const grub_uint32_t max_size = SLB_SIZE - SLRT_SIZE;

  if (size > max_size)
    {
      grub_dprintf ("slaunch", "Possible SKL module is too large: %u > %u\n",
                    size, max_size);
      return 0;
    }

  if (module->length > size)
    {
      grub_dprintf ("slaunch",
                    "Possible SKL module has wrong measured size: %u > %u\n",
                    module->length, size);
      return 0;
    }

  if (module->skl_entry_point >= module->length)
    {
      grub_dprintf ("slaunch",
                    "Possible SKL module doesn't measure its entry: %u >= %u\n",
                    module->skl_entry_point, module->length);
      return 0;
    }

  if (module->skl_info_offset > module->length - sizeof (info->uuid))
    {
      grub_dprintf ("slaunch",
                    "Possible SKL module doesn't measure info: %u > %u\n",
                    module->skl_info_offset,
                    module->length - sizeof (info->uuid));
      return 0;
    }

  if (SLB_SIZE - module->bootloader_data_offset < SLRT_SIZE)
    {
      grub_dprintf ("slaunch",
                    "Possible SKL module has not enough space for SLRT: %u < %u\n",
                    SLB_SIZE - module->bootloader_data_offset, SLRT_SIZE);
      return 0;
    }

  if (module->length > module->bootloader_data_offset)
    {
      grub_dprintf ("slaunch",
                    "Possible SKL module measures bootloader data: %u (measured prefix) > %u (data offset)\n",
                    module->length, module->bootloader_data_offset);
      return 0;
    }

  info = (struct grub_skl_info *) ((grub_uint8_t *) module + module->skl_info_offset);
  if (info->version != GRUB_SKL_VERSION)
    {
      grub_dprintf ("slaunch", "Possible SKL module has unexpected version\n");
      return 0;
    }

  if (grub_memcmp (info->uuid, skl_info.uuid, 16))
    {
      grub_dprintf ("slaunch", "Possible SKL module has unexpected UUID\n");
      return 0;
    }

  skl_module = module;
  skl_size = size;
  return 1;
}

grub_err_t
grub_skl_setup_module (struct grub_slaunch_params *slparams)
{
  grub_relocator_chunk_t ch;
  grub_phys_addr_t p_addr;
  grub_uint8_t *v_addr;
  grub_err_t err;
#ifdef GRUB_MACHINE_EFI
  grub_addr_t max_addr;
#endif

  if (slparams->boot_type == GRUB_SL_BOOT_TYPE_LINUX || slparams->boot_type == GRUB_SL_BOOT_TYPE_MB2)
    {
      err = grub_relocator_alloc_chunk_align (slparams->relocator, &ch,
					      0, UP_TO_TOP32(SLB_SIZE), SLB_SIZE,
					      SLB_MIN_ALIGNMENT,
					      GRUB_RELOCATOR_PREFERENCE_HIGH,
					      1);

      if (err != GRUB_ERR_NONE)
        return grub_error (err, N_("failed to allocate SLB"));

      v_addr = get_virtual_current_address (ch);
      p_addr = get_physical_target_address (ch);
    }
  else if (slparams->boot_type == GRUB_SL_BOOT_TYPE_EFI)
    {
#ifdef GRUB_MACHINE_EFI
      max_addr = ALIGN_DOWN ((GRUB_EFI_MAX_USABLE_ADDRESS - SLB_SIZE),
                             GRUB_PAGE_SIZE);

      v_addr = grub_efi_allocate_pages_real (max_addr,
                                             GRUB_EFI_BYTES_TO_PAGES(SLB_SIZE + SLB_MIN_ALIGNMENT),
                                             GRUB_EFI_ALLOCATE_MAX_ADDRESS,
                                             GRUB_EFI_LOADER_DATA);
      if (!v_addr)
        return GRUB_ERR_OUT_OF_MEMORY;

      v_addr = (grub_uint8_t *) ALIGN_UP ((grub_addr_t) v_addr, SLB_MIN_ALIGNMENT);
      p_addr = (grub_addr_t) v_addr;
#else
      return GRUB_ERR_BUG;
#endif
    }
  else
    {
      return grub_error (GRUB_ERR_BUG, N_("unknown dynamic launch boot type: %d"), slparams->boot_type);
    }

  grub_memcpy (v_addr, skl_module, skl_size);
  skl_module = (struct grub_sl_header *) v_addr;

  /* Once relocated, setup the DCE info in slparams */
  slparams->dce_size = skl_size;
  slparams->dce_base = (grub_uint64_t)p_addr;

  /* The SLRT resides in the relocated SKL bootloader_data section, set the values here */
  slparams->slr_table_base = (grub_uint64_t)p_addr + skl_module->bootloader_data_offset;
  slparams->slr_table_size = SLB_SIZE - skl_module->bootloader_data_offset;
  slparams->slr_table_mem = v_addr + skl_module->bootloader_data_offset;

  return GRUB_ERR_NONE;
}

void
grub_skl_link_amd_info (struct grub_slaunch_params *slparams)
{
  struct grub_slr_entry_amd_info *amd_info;

  amd_info = grub_slr_next_entry_by_tag ((struct grub_slr_table *)(grub_addr_t) slparams->slr_table_base,
                                         NULL,
                                         GRUB_SLR_ENTRY_AMD_INFO);

  amd_info->next = slparams->boot_params->setup_data;
  slparams->boot_params->setup_data = (grub_uint64_t)(grub_addr_t)amd_info + sizeof (struct grub_slr_entry_hdr);
}

grub_err_t
grub_skl_prepare_bootloader_data (struct grub_slaunch_params *slparams)
{
  struct grub_slr_table *slrt = (struct grub_slr_table *)slparams->slr_table_mem;
  struct grub_slr_entry_amd_info slr_amd_info_staging = {0};

  /* Setup the staging for AMD platform specific entry */
  slr_amd_info_staging.hdr.tag = GRUB_SLR_ENTRY_AMD_INFO;
  slr_amd_info_staging.hdr.size = sizeof (struct grub_slr_entry_amd_info);
  slr_amd_info_staging.type = GRUB_SETUP_SECURE_LAUNCH;
  slr_amd_info_staging.len = sizeof (struct grub_slr_entry_amd_info);
  slr_amd_info_staging.slrt_size = slparams->slr_table_size;
  slr_amd_info_staging.slrt_base = slparams->slr_table_base;
  slr_amd_info_staging.boot_params_base = slparams->boot_params_base;

  /* Setup the generic bits of the SLRT */
  grub_slr_init_table (slrt, GRUB_SLR_AMD_SKINIT, slparams->slr_table_size);

  /* Prepare SLR table staging area */
  grub_init_slrt_storage ();

  /* Create the SLR security policy */
  grub_setup_slrt_policy (slparams, NULL);

  /* Setup DL entry point, DCE and DLME information */
  grub_setup_slrt_dl_info (slparams);

  /* Setup the DRTM log info */
  grub_setup_slrt_log_info (slparams);

  /* Final move of staging information into the actual SLRT */
  grub_setup_slr_table (slparams, (struct grub_slr_entry_hdr *)&slr_amd_info_staging);

  return GRUB_ERR_NONE;
}
