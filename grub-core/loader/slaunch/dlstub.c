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
#include <grub/time.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/cpu/relocator.h>
#include <grub/i386/msr.h>
#include <grub/i386/mmio.h>
#include <grub/i386/psp.h>
#include <grub/i386/tpm.h>
#include <grub/i386/txt.h>
#include <grub/i386/skinit.h>

GRUB_MOD_LICENSE ("GPLv3+");

extern void dl_trampoline(grub_uint32_t dce_base, grub_uint32_t dce_size, grub_uint32_t platform);

void dl_entry (grub_uint64_t dl_ctx)
{
  struct grub_slr_bl_context *bl_ctx = (struct grub_slr_bl_context *)(grub_addr_t)dl_ctx;
  struct grub_slaunch_params *slparams = (struct grub_slaunch_params *)(grub_addr_t)bl_ctx->context;
  struct grub_relocator32_state state = {0};
  grub_err_t err;

  state.edi = slparams->platform_type;

  /* This is done on both Intel and AMD platforms */
  if (slparams->boot_type == GRUB_SL_BOOT_TYPE_EFI)
    grub_update_slrt_policy (slparams);

  if (state.edi == SLP_INTEL_TXT)
    {
      err = grub_set_mtrrs_for_acmod ((void *)(grub_addr_t)slparams->dce_base);
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
  else if (state.edi == SLP_AMD_SKINIT)
    {
      grub_skl_link_amd_info (slparams);

      err = grub_psp_discover ();
      if (err == GRUB_ERR_NONE)
        {
          err = grub_skinit_psp_memory_protect (slparams);
          if (err != GRUB_ERR_NONE)
            {
              grub_error (GRUB_ERR_BAD_DEVICE, N_("setup PSP TMR memory protection failed"));
              return;
            }
        }
      else
        grub_tpm_relinquish_locality (0);

      err = grub_skinit_prepare_cpu ();
      if ( err )
        {
          grub_error (GRUB_ERR_BAD_DEVICE, N_("setup CPU for SKINIT failed"));
          return;
        }

      /* Have to do this after EBS or things blow up */
      grub_skinit_send_init_ipi_shorthand ();
    }
  else
    {
      grub_error (GRUB_ERR_BUG, N_("unknown dynamic launch platform: %d"), state.edi);
      return;
    }

  if (!(grub_rdmsr (GRUB_MSR_X86_APICBASE) & GRUB_MSR_X86_APICBASE_BSP))
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("x86 dynamic launch event must be performed on the BSP"));
      return;
    }

  if (slparams->boot_type == GRUB_SL_BOOT_TYPE_LINUX || slparams->boot_type == GRUB_SL_BOOT_TYPE_MB2)
    {
      if (state.edi == SLP_INTEL_TXT)
        {
          /* Configure relocator GETSEC[SENTER] call. */
          state.eax = GRUB_SMX_LEAF_SENTER;
          state.ebx = slparams->dce_base;
          state.ecx = slparams->dce_size;
          state.edx = 0;
        }
      else if (state.edi == SLP_AMD_SKINIT)
        {
          state.eax = slparams->dce_base;
        }

      grub_relocator32_boot (slparams->relocator, state, 0);
    }
  else if (slparams->boot_type == GRUB_SL_BOOT_TYPE_EFI)
    {
      dl_trampoline (slparams->dce_base, slparams->dce_size, state.edi);
    }
  else
    {
      grub_error (GRUB_ERR_BUG, N_("unknown dynamic launch boot type: %d"), slparams->boot_type);
    }
}
