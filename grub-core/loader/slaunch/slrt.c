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

#include <grub/loader.h>
#include <grub/normal.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/i386/linux.h>
#include <grub/i386/memory.h>
#include <grub/i386/tpm.h>
#include <grub/i386/mmio.h>
#include <grub/i386/txt.h>

#define SLR_MAX_POLICY_ENTRIES		7

/* Area to collect and build SLR Table information */
static grub_uint8_t slr_policy_buf[GRUB_PAGE_SIZE] = {0};
static struct grub_slr_entry_dl_info slr_dl_info_staging = {0};
static struct grub_slr_entry_log_info slr_log_info_staging = {0};
static struct grub_slr_entry_policy *slr_policy_staging =
    (struct grub_slr_entry_policy *)slr_policy_buf;

extern void dl_entry_trampoline(void);

void
grub_init_slrt_storage (void)
{
  slr_dl_info_staging.hdr.tag = GRUB_SLR_ENTRY_DL_INFO;
  slr_dl_info_staging.hdr.size = sizeof(struct grub_slr_entry_dl_info);

  slr_log_info_staging.hdr.tag = GRUB_SLR_ENTRY_LOG_INFO;
  slr_log_info_staging.hdr.size = sizeof(struct grub_slr_entry_log_info);

  slr_policy_staging->hdr.tag = GRUB_SLR_ENTRY_ENTRY_POLICY;
  slr_policy_staging->hdr.size = sizeof(struct grub_slr_entry_policy) +
    SLR_MAX_POLICY_ENTRIES*sizeof(struct grub_slr_policy_entry);
  slr_policy_staging->revision = GRUB_SLR_POLICY_REVISION;
  slr_policy_staging->nr_entries = SLR_MAX_POLICY_ENTRIES;
}

void
grub_setup_slrt_policy (struct grub_slaunch_params *slparams,
                        struct grub_slr_policy_entry *platform_entry)
{
  struct linux_kernel_params *boot_params = slparams->boot_params;
  struct grub_efi_info *efi_info;
  grub_uint64_t hi_val;
  int i = 0;

  /* A bit of work to extract the v2.08 EFI info from the linux params */
  efi_info = (struct grub_efi_info *)((grub_uint8_t *)&(boot_params->v0208)
                                       + 2*sizeof(grub_uint32_t));

  /* the SLR table should be measured too, at least parts of it */
  slr_policy_staging->policy_entries[i].pcr = 18;
  slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_SLRT;
  slr_policy_staging->policy_entries[i].entity = slparams->slr_table_base;
  slr_policy_staging->policy_entries[i].flags |= GRUB_SLR_POLICY_IMPLICIT_SIZE;
  grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, "Measured SLR Table");
  i++;

  /* boot params have everything needed to setup policy except OS2MLE data */
  slr_policy_staging->policy_entries[i].pcr = 18;
  slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_BOOT_PARAMS;
  slr_policy_staging->policy_entries[i].entity = (grub_uint64_t)boot_params;
  slr_policy_staging->policy_entries[i].size = GRUB_PAGE_SIZE;
  grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, "Measured boot parameters");
  i++;

  if (boot_params->setup_data)
    {
      slr_policy_staging->policy_entries[i].pcr = 18;
      slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_SETUP_DATA;
      slr_policy_staging->policy_entries[i].entity = boot_params->setup_data;
      slr_policy_staging->policy_entries[i].flags |= GRUB_SLR_POLICY_IMPLICIT_SIZE;
      grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, "Measured Kernel setup_data");
    }
  else
      slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_UNUSED;
  i++;

  if (boot_params->cmd_line_ptr)
    {
      slr_policy_staging->policy_entries[i].pcr = 18;
      slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_CMDLINE;
      slr_policy_staging->policy_entries[i].entity = boot_params->cmd_line_ptr;
      hi_val = boot_params->ext_cmd_line_ptr;
      slr_policy_staging->policy_entries[i].entity |= hi_val << 32;;
      slr_policy_staging->policy_entries[i].size = boot_params->cmdline_size;
      grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, "Measured Kernel command line");
    }
  else
      slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_UNUSED;
  i++;

  if (!grub_memcmp(&efi_info->efi_signature, "EL64", sizeof(grub_uint32_t)))
    {
      slr_policy_staging->policy_entries[i].pcr = 18;
      slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_UEFI_MEMMAP;
      slr_policy_staging->policy_entries[i].entity = efi_info->efi_mmap;
      hi_val = efi_info->efi_mmap_hi;
      slr_policy_staging->policy_entries[i].entity |= hi_val << 32;
      slr_policy_staging->policy_entries[i].size = efi_info->efi_mmap_size;
      grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, "Measured EFI memory map");
    }
  else
      slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_UNUSED;
  i++;

  if (boot_params->ramdisk_image)
    {
      slr_policy_staging->policy_entries[i].pcr = 17;
      slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_RAMDISK;
      slr_policy_staging->policy_entries[i].entity = boot_params->ramdisk_image;
      hi_val = boot_params->ext_ramdisk_image;
      slr_policy_staging->policy_entries[i].entity |= hi_val << 32;
      slr_policy_staging->policy_entries[i].size = boot_params->ramdisk_size;
      hi_val = boot_params->ext_ramdisk_size;
      slr_policy_staging->policy_entries[i].entity |= hi_val << 32;
      grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, "Measured Kernel initrd");
    }
  else
    slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_UNUSED;
  i++;

  if (platform_entry)
    {
      slr_policy_staging->policy_entries[i].pcr = platform_entry->pcr;
      slr_policy_staging->policy_entries[i].entity_type = platform_entry->entity_type;
      slr_policy_staging->policy_entries[i].flags = platform_entry->flags;
      slr_policy_staging->policy_entries[i].entity = platform_entry->entity;
      slr_policy_staging->policy_entries[i].size = platform_entry->size;
      grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, platform_entry->evt_info);
    }
  else
    slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_UNUSED;
}

void
grub_setup_slrt_dl_info (struct grub_slaunch_params *slparams)
{
  struct grub_txt_mle_header *mle_header;

  mle_header = (struct grub_txt_mle_header *)(grub_addr_t) (slparams->mle_start + slparams->mle_header_offset);

  /* Setup DL entry point, DCE and DLME information */
  slr_dl_info_staging.bl_context.bootloader = GRUB_SLR_BOOTLOADER_GRUB;
  slr_dl_info_staging.bl_context.context = (grub_uint64_t)slparams;
  slr_dl_info_staging.dl_handler = (grub_uint64_t)dl_entry_trampoline;
  slr_dl_info_staging.dlme_size = slparams->mle_size;
  slr_dl_info_staging.dlme_base = slparams->mle_start;
  slr_dl_info_staging.dlme_entry = mle_header->entry_point;
  slr_dl_info_staging.dce_base = slparams->dce_base;
  slr_dl_info_staging.dce_size = slparams->dce_size;
}

void
grub_setup_slrt_log_info (struct grub_slaunch_params *slparams)
{
  slr_log_info_staging.addr = slparams->tpm_evt_log_base;
  slr_log_info_staging.size = slparams->tpm_evt_log_size;
  slr_log_info_staging.format =
        (grub_get_tpm_ver () == GRUB_TPM_20) ?
        GRUB_SLR_DRTM_TPM20_LOG : GRUB_SLR_DRTM_TPM20_LOG;
}

void
grub_setup_slr_table (struct grub_slaunch_params *slparams,
                      struct grub_slr_entry_hdr *platform_info)
{
  grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                      (struct grub_slr_entry_hdr *)&slr_dl_info_staging);
  grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                      (struct grub_slr_entry_hdr *)&slr_log_info_staging);
  grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                      (struct grub_slr_entry_hdr *)slr_policy_staging);
  /* Add in any platform specific info if present */
  if (platform_info)
    grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                        platform_info);
}

void
grub_update_slrt_policy (struct grub_slaunch_params *slparams)
{
  struct linux_kernel_params *boot_params = slparams->boot_params;
  struct grub_slr_entry_policy *policy;
  struct grub_efi_info *efi_info;
  grub_uint64_t hi_val;
  int i, next = 0;

  policy = grub_slr_next_entry_by_tag ((struct grub_slr_table *)slparams->slr_table_base,
                                       NULL,
                                       GRUB_SLR_ENTRY_ENTRY_POLICY);

  /* First find the updated boot params */
  for (i = 0; i < policy->nr_entries; i++)
    {
      if (policy->policy_entries[i].entity_type == GRUB_SLR_ET_BOOT_PARAMS)
        {
          boot_params = (struct linux_kernel_params *)policy->policy_entries[i].entity;
          slparams->boot_params = boot_params;
          break;
        }
    }

  /* A bit of work to extract the v2.08 EFI info from the linux params */
  efi_info = (struct grub_efi_info *)((grub_uint8_t *)&(boot_params->v0208)
                                       + 2*sizeof(grub_uint32_t));

  for (i = 0; i < policy->nr_entries; i++)
    {
      if (policy->policy_entries[i].entity_type == GRUB_SLR_ET_UNUSED)
        {
          if (next == 0 && boot_params->setup_data)
            {
              policy->policy_entries[i].pcr = 18;
              policy->policy_entries[i].entity_type = GRUB_SLR_ET_SETUP_DATA;
              policy->policy_entries[i].entity = boot_params->setup_data;
              policy->policy_entries[i].flags |= GRUB_SLR_POLICY_IMPLICIT_SIZE;
              grub_strcpy (policy->policy_entries[i].evt_info, "Measured Kernel setup_data");
            }
          else if (next == 1 && boot_params->cmd_line_ptr)
            {
              policy->policy_entries[i].pcr = 18;
              policy->policy_entries[i].entity_type = GRUB_SLR_ET_CMDLINE;
              policy->policy_entries[i].entity = boot_params->cmd_line_ptr;
              hi_val = boot_params->ext_cmd_line_ptr;
              policy->policy_entries[i].entity |= hi_val << 32;;
              policy->policy_entries[i].size = boot_params->cmdline_size;
              grub_strcpy (policy->policy_entries[i].evt_info, "Measured Kernel command line");
            }
          else if (next == 2 && !grub_memcmp(&efi_info->efi_signature, "EL64", sizeof(grub_uint32_t)))
            {
              policy->policy_entries[i].pcr = 18;
              policy->policy_entries[i].entity_type = GRUB_SLR_ET_UEFI_MEMMAP;
              policy->policy_entries[i].entity = efi_info->efi_mmap;
              hi_val = efi_info->efi_mmap_hi;
              policy->policy_entries[i].entity |= hi_val << 32;
              policy->policy_entries[i].size = efi_info->efi_mmap_size;
              grub_strcpy (policy->policy_entries[i].evt_info, "Measured EFI memory map");
            }
          else if (next == 3 && boot_params->ramdisk_image)
            {
              policy->policy_entries[i].pcr = 17;
              policy->policy_entries[i].entity_type = GRUB_SLR_ET_RAMDISK;
              policy->policy_entries[i].entity = boot_params->ramdisk_image;
              hi_val = boot_params->ext_ramdisk_image;
              policy->policy_entries[i].entity |= hi_val << 32;
              policy->policy_entries[i].size = boot_params->ramdisk_size;
              hi_val = boot_params->ext_ramdisk_size;
              policy->policy_entries[i].entity |= hi_val << 32;
              grub_strcpy (policy->policy_entries[i].evt_info, "Measured Kernel initrd");
          }
          next++;
        }
    }
}
