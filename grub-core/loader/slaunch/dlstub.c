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
#include <grub/memory.h>
#include <grub/normal.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/cpu/relocator.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/i386/cpuid.h>
#include <grub/i386/msr.h>
#include <grub/i386/mmio.h>
#include <grub/i386/txt.h>

GRUB_MOD_LICENSE ("GPLv3+");

extern void dl_trampoline(grub_uint32_t dce_base, grub_uint32_t dce_size);

void dl_entry (grub_uint64_t dl_ctx)
{
  struct grub_slr_bl_context *bl_ctx = (struct grub_slr_bl_context *)dl_ctx;
  struct grub_slaunch_params *slparams = (struct grub_slaunch_params *)bl_ctx->context;
  struct grub_relocator32_state state;
  grub_err_t err;

  state.edi = slparams->platform_type;

  if (state.edi == SLP_INTEL_TXT)
    {
      if (slparams->boot_type == GRUB_SL_BOOT_TYPE_EFI)
        grub_txt_update_slrt_policy (slparams);

      err = grub_set_mtrrs_for_acmod ((void *)slparams->dce_base);
      if (err)
        {
          grub_error (GRUB_ERR_BAD_DEVICE, N_("setting MTRRs for TXT SINIT failed"));
          return;
        }

      err = grub_txt_prepare_cpu ();
      if ( err )
        {
          grub_error (GRUB_ERR_BAD_DEVICE, N_("prepare CPU for TXT SENTER failed"));
          return;
        }
    }

  if (!(grub_rdmsr (GRUB_MSR_X86_APICBASE) & GRUB_MSR_X86_APICBASE_BSP))
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("x86 dynamic launch event must be performed on the BSP"));
      return;
    }

  if (slparams->boot_type == GRUB_SL_BOOT_TYPE_LINUX)
    {
      /* Configure relocator GETSEC[SENTER] call. */
      state.eax = GRUB_SMX_LEAF_SENTER;
      state.ebx = slparams->dce_base;
      state.ecx = slparams->dce_size;
      state.edx = 0;
      grub_relocator32_boot (slparams->relocator, state, 0);
    }
  else /* GRUB_SL_BOOT_TYPE_EFI */
    dl_trampoline (slparams->dce_base, slparams->dce_size);
}
