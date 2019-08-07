/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  Oracle and/or its affiliates.
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

#include <grub/i386/linux.h>
#include <grub/types.h>

struct grub_slaunch_params
{
  grub_uint32_t boot_params_addr;
  grub_uint32_t mle_start;
  grub_uint32_t mle_size;
  void *mle_ptab_mem;
  grub_uint64_t mle_ptab_target;
  grub_uint32_t mle_ptab_size;
  grub_uint32_t mle_header_offset;
  grub_uint32_t ap_wake_block;
  grub_uint32_t ap_wake_block_size;
  grub_uint32_t dce_base;
  grub_uint32_t dce_size;
  grub_uint64_t tpm_evt_log_base;
  grub_uint32_t tpm_evt_log_size;
};

extern grub_uint32_t grub_slaunch_platform_type (void);
extern void *grub_slaunch_module (void);
extern struct grub_slaunch_params *grub_slaunch_params (void);

#endif /* ASM_FILE */

#endif /* GRUB_I386_SLAUNCH_H */
