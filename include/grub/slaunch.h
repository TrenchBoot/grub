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
 *
 *  Main secure launch definitions header file.
 */

#ifndef GRUB_I386_SLAUNCH_H
#define GRUB_I386_SLAUNCH_H 1

/* Secure launch platform types. */
#define SLP_NONE	0
#define SLP_INTEL_TXT	1

#define GRUB_SLAUNCH_TPM_EVT_LOG_SIZE	(8 * GRUB_PAGE_SIZE)

#ifndef ASM_FILE

#define GRUB_SL_BOOT_TYPE_INVALID	0
#define GRUB_SL_BOOT_TYPE_LINUX		1
#define GRUB_SL_BOOT_TYPE_EFI		2

#define GRUB_KERNEL_INFO_HEADER		"LToP"
#define GRUB_KERNEL_INFO_MIN_SIZE_TOTAL	12

struct linux_kernel_params;
struct linux_i386_kernel_header;
struct grub_relocator;

struct grub_slaunch_params
{
  grub_uint32_t boot_type;
  grub_uint32_t platform_type;
  struct linux_kernel_params *boot_params;
  grub_uint64_t boot_params_base;
  struct grub_relocator *relocator;
  grub_uint64_t slr_table_base;
  grub_uint32_t slr_table_size;
  void *slr_table_mem;
  grub_uint32_t mle_start;
  grub_uint32_t mle_size;
  grub_uint64_t mle_ptab_target;
  grub_uint32_t mle_ptab_size;
  void *mle_ptab_mem;
  grub_uint32_t mle_header_offset;
  grub_uint32_t ap_wake_block;
  grub_uint32_t ap_wake_block_size;
  grub_uint64_t dce_base;
  grub_uint32_t dce_size;
  grub_uint64_t tpm_evt_log_base;
  grub_uint32_t tpm_evt_log_size;
};

struct grub_efi_info
{
  grub_uint32_t efi_signature;
  grub_uint32_t efi_system_table;
  grub_uint32_t efi_mem_desc_size;
  grub_uint32_t efi_mem_desc_version;
  grub_uint32_t efi_mmap;
  grub_uint32_t efi_mmap_size;
  grub_uint32_t efi_system_table_hi;
  grub_uint32_t efi_mmap_hi;
};

extern grub_uint32_t grub_slaunch_platform_type (void);
extern void *grub_slaunch_module (void);

void dl_entry(grub_uint64_t dl_ctx);

/* SLRT setup functions */
void grub_init_slrt_storage (void);
void grub_setup_slrt_policy (struct grub_slaunch_params *slparams,
                             struct grub_slr_policy_entry *platform_entry);
void grub_setup_slrt_dl_info (struct grub_slaunch_params *slparams);
void grub_setup_slrt_log_info (struct grub_slaunch_params *slparams);
void grub_setup_slr_table (struct grub_slaunch_params *slparams,
                           struct grub_slr_entry_hdr *platform_info);
void grub_update_slrt_policy (struct grub_slaunch_params *slparams);

/* Linux i386 functions */
grub_err_t grub_sl_find_kernel_info (struct grub_slaunch_params *slparams,
                                     grub_file_t kernel_file,
                                     struct linux_i386_kernel_header *lh,
                                     grub_size_t real_size);
grub_err_t grub_sl_txt_prepare_mle_ptab (struct grub_slaunch_params *slparams,
                                         grub_size_t *prot_size,
                                         grub_uint64_t *preferred_address);
grub_err_t grub_sl_txt_setup_linux (struct grub_slaunch_params *slparams,
                                    struct grub_relocator *relocator,
                                    grub_size_t total_size, grub_size_t prot_size,
                                    void **prot_mode_mem, grub_addr_t *prot_mode_target);

#endif /* ASM_FILE */

#endif /* GRUB_I386_SLAUNCH_H */
