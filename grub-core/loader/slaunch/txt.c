/*
 * txt.c: Intel(r) TXT support functions, including initiating measured
 *        launch, post-launch, AP wakeup, etc.
 *
 * Copyright (c) 2003-2011, Intel Corporation
 * All rights reserved.
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
 */

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
#include <grub/acpi.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/cpu/relocator.h>
#include <grub/i386/relocator.h>
#include <grub/i386/cpuid.h>
#include <grub/i386/msr.h>
#include <grub/i386/crfr.h>
#include <grub/i386/txt.h>
#include <grub/i386/linux.h>
#include <grub/i386/memory.h>
#include <grub/i386/tpm.h>

#define OS_SINIT_DATA_TPM_12_VER	6
#define OS_SINIT_DATA_TPM_20_VER	7

#define OS_SINIT_DATA_MIN_VER		OS_SINIT_DATA_TPM_12_VER

#define SLR_MAX_POLICY_ENTRIES		7

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

/* Area to collect and build SLR Table information */
static grub_uint8_t slr_policy_buf[GRUB_PAGE_SIZE] = {0};
static struct grub_slr_entry_dl_info slr_dl_info_staging = {0};
static struct grub_slr_entry_log_info slr_log_info_staging = {0};
static struct grub_slr_entry_policy *slr_policy_staging =
    (struct grub_slr_entry_policy *)slr_policy_buf;
static struct grub_slr_entry_intel_info slr_intel_info_staging = {0};

extern void dl_entry_trampoline(void);


static grub_err_t
enable_smx_mode (void)
{
  grub_uint32_t caps;

  /* Enable SMX mode. */
  grub_write_cr4 (grub_read_cr4 () | GRUB_CR4_X86_SMXE);

  caps = grub_txt_getsec_capabilities (0);

  if (!(caps & GRUB_SMX_CAPABILITY_CHIPSET_PRESENT))
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("TXT-capable chipset is not present"));
      goto fail;
    }

  if (!(caps & GRUB_SMX_CAPABILITY_SENTER))
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("GETSEC[SENTER] is not available"));
      goto fail;
    }

  if (!(caps & GRUB_SMX_CAPABILITY_PARAMETERS))
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("GETSEC[PARAMETERS] is not available"));
      goto fail;
    }

  return GRUB_ERR_NONE;

 fail:
  /* Disable SMX mode on failure. */
  grub_write_cr4 (grub_read_cr4 () & ~GRUB_CR4_X86_SMXE);

  return grub_errno;
}

static void
grub_txt_smx_parameters (struct grub_smx_parameters *params)
{
  grub_uint32_t index = 0, eax, ebx, ecx, param_type;

  grub_memset (params, 0, sizeof(struct grub_smx_supported_versions));

  params->max_acm_size = GRUB_SMX_DEFAULT_MAX_ACM_SIZE;
  params->acm_memory_types = GRUB_SMX_DEFAULT_ACM_MEMORY_TYPE;
  params->senter_controls = GRUB_SMX_DEFAULT_SENTER_CONTROLS;

  do
    {
      grub_txt_getsec_parameters (index, &eax, &ebx, &ecx);
      param_type = eax & GRUB_SMX_PARAMETER_TYPE_MASK;

      switch (param_type)
        {
        case GRUB_SMX_PARAMETER_NULL:
          break; /* This means done. */

        case GRUB_SMX_PARAMETER_ACM_VERSIONS:
          if (params->version_count == GRUB_SMX_PARAMETER_MAX_VERSIONS)
            {
	      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("Too many ACM versions"));
	      break;
            }
          params->versions[params->version_count].mask = ebx;
          params->versions[params->version_count++].version = ecx;
          break;

      case GRUB_SMX_PARAMETER_MAX_ACM_SIZE:
        params->max_acm_size = GRUB_SMX_GET_MAX_ACM_SIZE (eax);
        break;

      case GRUB_SMX_PARAMETER_ACM_MEMORY_TYPES:
        params->acm_memory_types = GRUB_SMX_GET_ACM_MEMORY_TYPES (eax);
        break;

      case GRUB_SMX_PARAMETER_SENTER_CONTROLS:
        params->senter_controls = GRUB_SMX_GET_SENTER_CONTROLS (eax);
        break;

      case GRUB_SMX_PARAMETER_TXT_EXTENSIONS:
        params->txt_feature_ext_flags = GRUB_SMX_GET_TXT_EXT_FEATURES (eax);
        break;

      default:
	grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Unknown SMX parameter"));
	param_type = GRUB_SMX_PARAMETER_NULL;
    }

    ++index;

  } while (param_type != GRUB_SMX_PARAMETER_NULL);

  /* If no ACM versions were found, set the default one. */
  if (!params->version_count)
    {
      params->versions[0].mask = GRUB_SMX_DEFAULT_VERSION_MASK;
      params->versions[0].version = GRUB_SMX_DEFAULT_VERSION;
      params->version_count++;
    }
}

grub_err_t
grub_txt_prepare_cpu (void)
{
  struct grub_smx_parameters params;
  grub_uint32_t i;
  grub_uint64_t mcg_cap, mcg_stat;
  unsigned long cr0;

  cr0 = grub_read_control_register (GRUB_CR0);

  /* Cache must be enabled (CR0.CD = CR0.NW = 0). */
  cr0 &= ~(GRUB_CR0_X86_CD | GRUB_CR0_X86_NW);

  /* Native FPU error reporting must be enabled for proper interaction behavior. */
  cr0 |= GRUB_CR0_X86_NE;

  grub_write_control_register (GRUB_CR0, cr0);

  /* Disable virtual-8086 mode (EFLAGS.VM = 0). */
  grub_write_flags_register (grub_read_flags_register () & ~GRUB_EFLAGS_X86_VM);

  /*
   * Verify all machine check status registers are clear (unless
   * support preserving them).
   */

  /* Is machine check in progress? */
  if ( grub_rdmsr (GRUB_MSR_X86_MCG_STATUS) & GRUB_MSR_MCG_STATUS_MCIP )
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("machine check in progress during secure launch"));

  grub_txt_smx_parameters (&params);

  if (params.txt_feature_ext_flags & GRUB_SMX_PROCESSOR_BASE_SCRTM)
    grub_dprintf ("slaunch", "CPU supports processor-based S-CRTM\n");

  if (params.txt_feature_ext_flags & GRUB_SMX_MACHINE_CHECK_HANLDING)
    grub_dprintf ("slaunch", "CPU supports preserving machine check errors\n");
  else
    {
      grub_dprintf ("slaunch", "CPU does not support preserving machine check errors\n");

      /* Check if all machine check registers are clear. */
      mcg_cap = grub_rdmsr (GRUB_MSR_X86_MCG_CAP);
      for (i = 0; i < (mcg_cap & GRUB_MSR_MCG_BANKCNT_MASK); ++i)
	{
	  mcg_stat = grub_rdmsr (GRUB_MSR_X86_MC0_STATUS + i * 4);
	  if (mcg_stat & (1ULL << 63))
	    return grub_error (GRUB_ERR_BAD_DEVICE,
			       N_("secure launch MCG[%u] = %lx ERROR"), i, mcg_stat);
        }
    }

  return GRUB_ERR_NONE;
}

static void
save_mtrrs (struct grub_slr_txt_mtrr_state *saved_bsp_mtrrs)
{
  grub_uint64_t i;

  saved_bsp_mtrrs->default_mem_type =
    grub_rdmsr (GRUB_MSR_X86_MTRR_DEF_TYPE);

  saved_bsp_mtrrs->mtrr_vcnt =
    grub_rdmsr (GRUB_MSR_X86_MTRRCAP) & GRUB_MSR_X86_VCNT_MASK;

  if (saved_bsp_mtrrs->mtrr_vcnt > GRUB_TXT_VARIABLE_MTRRS_LENGTH)
    {
      /* Print warning but continue saving what we can... */
      grub_printf ("WARNING: Actual number of variable MTRRs (%" PRIuGRUB_UINT64_T
		   ") > GRUB_SL_MAX_VARIABLE_MTRRS (%d)\n",
		   saved_bsp_mtrrs->mtrr_vcnt,
		   GRUB_TXT_VARIABLE_MTRRS_LENGTH);
      saved_bsp_mtrrs->mtrr_vcnt = GRUB_TXT_VARIABLE_MTRRS_LENGTH;
    }

  for (i = 0; i < saved_bsp_mtrrs->mtrr_vcnt; ++i)
    {
      saved_bsp_mtrrs->mtrr_pair[i].mtrr_physmask =
        grub_rdmsr (GRUB_MSR_X86_MTRR_PHYSMASK0 + i * 2);
      saved_bsp_mtrrs->mtrr_pair[i].mtrr_physbase =
        grub_rdmsr (GRUB_MSR_X86_MTRR_PHYSBASE0 + i * 2);
    }
}

static void
set_all_mtrrs (int enable)
{
  grub_uint64_t mtrr_def_type;

  mtrr_def_type = grub_rdmsr (GRUB_MSR_X86_MTRR_DEF_TYPE);

  if ( enable )
    mtrr_def_type |= GRUB_MSR_X86_MTRR_ENABLE;
  else
    mtrr_def_type &= ~GRUB_MSR_X86_MTRR_ENABLE;

  grub_wrmsr (GRUB_MSR_X86_MTRR_DEF_TYPE, mtrr_def_type);
}

#define SINIT_MTRR_MASK         0xFFFFFF  /* SINIT requires 36b mask */

union mtrr_physbase_t
{
  grub_uint64_t raw;
  struct
  {
    grub_uint64_t type      : 8;
    grub_uint64_t reserved1 : 4;
    grub_uint64_t base      : 52; /* Define as max width and mask w/ */
                                  /* MAXPHYADDR when using */
  };
} GRUB_PACKED;

union mtrr_physmask_t
{
  grub_uint64_t raw;
  struct
  {
    grub_uint64_t reserved1 : 11;
    grub_uint64_t v         : 1;      /* valid */
    grub_uint64_t mask      : 52;     /* define as max width and mask w/ */
                                      /* MAXPHYADDR when using */
  };
} GRUB_PACKED;

static inline grub_uint32_t
bsrl (grub_uint32_t mask)
{
  grub_uint32_t result;

  asm ("bsrl %1,%0" : "=r" (result) : "rm" (mask) : "cc");

  return result;
}

static inline int
fls (int mask)
{
  return (mask == 0 ? mask : (int)bsrl ((grub_uint32_t)mask) + 1);
}

/*
 * set the memory type for specified range (base to base+size)
 * to mem_type and everything else to UC
 */
static grub_err_t
set_mtrr_mem_type (const grub_uint8_t *base, grub_uint32_t size,
                   grub_uint32_t mem_type)
{
  grub_uint64_t mtrr_def_type;
  grub_uint64_t mtrr_cap;
  union mtrr_physbase_t mtrr_physbase;
  union mtrr_physmask_t mtrr_physmask;
  grub_uint32_t vcnt, pages_in_range;
  unsigned long ndx, base_v;
  int i = 0, j, num_pages, mtrr_s;

  /* Disable all fixed MTRRs, set default type to UC */
  mtrr_def_type = grub_rdmsr (GRUB_MSR_X86_MTRR_DEF_TYPE);
  mtrr_def_type &= ~(GRUB_MSR_X86_MTRR_ENABLE_FIXED | GRUB_MSR_X86_DEF_TYPE_MASK);
  mtrr_def_type |= GRUB_MTRR_MEMORY_TYPE_UC;
  grub_wrmsr (GRUB_MSR_X86_MTRR_DEF_TYPE, mtrr_def_type);

  /* Initially disable all variable MTRRs (we'll enable the ones we use) */
  mtrr_cap = grub_rdmsr (GRUB_MSR_X86_MTRRCAP);
  vcnt = (mtrr_cap & GRUB_MSR_X86_VCNT_MASK);

  for ( ndx = 0; ndx < vcnt; ndx++ )
    {
      mtrr_physmask.raw = grub_rdmsr (GRUB_MSR_X86_MTRR_PHYSMASK0 + ndx*2);
      mtrr_physmask.v = 0;
      grub_wrmsr (GRUB_MSR_X86_MTRR_PHYSMASK0 + ndx*2, mtrr_physmask.raw);
    }

  /* Map all AC module pages as mem_type */
  num_pages = GRUB_PAGE_UP(size) >> GRUB_PAGE_SHIFT;

  grub_dprintf ("slaunch", "setting MTRRs for acmod: base=%p, size=%x, num_pages=%d\n",
           base, size, num_pages);

  /* Each VAR MTRR base must be a multiple if that MTRR's Size */
  base_v = (unsigned long)base;
  /* MTRR size in pages */
  mtrr_s = 1;

  while ( (base_v & 0x01) == 0 )
    {
      i++;
      base_v = base_v >> 1;
    }

  for (j = i - 12; j > 0; j--)
     mtrr_s = mtrr_s*2; /* mtrr_s = mtrr_s << 1 */

  grub_dprintf ("slaunch", "The maximum allowed MTRR range size=%d Pages \n", mtrr_s);

  ndx = 0;

  while ( num_pages >= mtrr_s )
    {
      mtrr_physbase.raw = grub_rdmsr (GRUB_MSR_X86_MTRR_PHYSBASE0 + ndx*2);
      mtrr_physbase.base = ((unsigned long)base >> GRUB_PAGE_SHIFT) &
	                     SINIT_MTRR_MASK;
      mtrr_physbase.type = mem_type;
      grub_wrmsr (GRUB_MSR_X86_MTRR_PHYSBASE0 + ndx*2, mtrr_physbase.raw);

      mtrr_physmask.raw = grub_rdmsr (GRUB_MSR_X86_MTRR_PHYSMASK0 + ndx*2);
      mtrr_physmask.mask = ~(mtrr_s - 1) & SINIT_MTRR_MASK;
      mtrr_physmask.v = 1;
      grub_wrmsr (GRUB_MSR_X86_MTRR_PHYSMASK0 + ndx*2, mtrr_physmask.raw);

      base += (mtrr_s * GRUB_PAGE_SIZE);
      num_pages -= mtrr_s;
      ndx++;
      if ( ndx == vcnt )
          return grub_error (GRUB_ERR_BAD_DEVICE,
			     N_("exceeded number of var MTRRs when mapping range"));
    }

  while ( num_pages > 0 )
    {
      /* Set the base of the current MTRR */
      mtrr_physbase.raw = grub_rdmsr (GRUB_MSR_X86_MTRR_PHYSBASE0 + ndx*2);
      mtrr_physbase.base = ((unsigned long)base >> GRUB_PAGE_SHIFT) &
                            SINIT_MTRR_MASK;
      mtrr_physbase.type = mem_type;
      grub_wrmsr (GRUB_MSR_X86_MTRR_PHYSBASE0 + ndx*2, mtrr_physbase.raw);

      /*
       * Calculate MTRR mask
       * MTRRs can map pages in power of 2
       * may need to use multiple MTRRS to map all of region
       */
      pages_in_range = 1 << (fls (num_pages) - 1);

      mtrr_physmask.raw = grub_rdmsr (GRUB_MSR_X86_MTRR_PHYSMASK0 + ndx*2);
      mtrr_physmask.mask = ~(pages_in_range - 1) & SINIT_MTRR_MASK;
      mtrr_physmask.v = 1;
      grub_wrmsr (GRUB_MSR_X86_MTRR_PHYSMASK0 + ndx*2, mtrr_physmask.raw);

      /*
       * Prepare for the next loop depending on number of pages
       * We figure out from the above how many pages could be used in this
       * mtrr. Then we decrement the count, increment the base,
       * increment the mtrr we are dealing with, and if num_pages is
       * still not zero, we do it again.
       */
      base += (pages_in_range * GRUB_PAGE_SIZE);
      num_pages -= pages_in_range;
      ndx++;
      if ( ndx == vcnt )
          return grub_error (GRUB_ERR_BAD_DEVICE,
			     N_("exceeded number of var MTRRs when mapping range"));
    }

  return GRUB_ERR_NONE;
}

/*
 * this must be done for each processor so that all have the same
 * memory types
 */
grub_err_t
grub_set_mtrrs_for_acmod (struct grub_txt_acm_header *hdr)
{
  unsigned long eflags;
  unsigned long cr0, cr4;
  grub_err_t err;

  /*
   * need to do some things before we start changing MTRRs
   *
   * since this will modify some of the MTRRs, they should be saved first
   * so that they can be restored once the AC mod is done
   */

  /* Disable interrupts */
  eflags = grub_read_flags_register ();
  grub_write_flags_register (eflags & ~GRUB_EFLAGS_X86_IF);

  /* Save CR0 then disable cache (CRO.CD=1, CR0.NW=0) */
  cr0 = grub_read_control_register (GRUB_CR0);
  grub_write_control_register (GRUB_CR0,
                               (cr0 & ~GRUB_CR0_X86_NW) | GRUB_CR0_X86_CD);

  /* Flush caches */
  asm volatile ("wbinvd");

  /* Save CR4 and disable global pages (CR4.PGE=0) */
  cr4 = grub_read_control_register (GRUB_CR4);
  grub_write_control_register (GRUB_CR4, cr4 & ~GRUB_CR4_X86_PGE);

  /* Disable MTRRs */
  set_all_mtrrs (0);

  /* Set MTRRs for AC mod and rest of memory */
  err = set_mtrr_mem_type ((grub_uint8_t*)hdr, hdr->size*4,
                           GRUB_MTRR_MEMORY_TYPE_WB);
  if ( err )
    return err;

  /* Undo some of earlier changes and enable our new settings */

  /* Flush caches */
  asm volatile ("wbinvd");

  /* Enable MTRRs */
  set_all_mtrrs (1);

  /* Restore CR0 (cacheing) */
  grub_write_control_register (GRUB_CR0, cr0);

  /* Restore CR4 (global pages) */
  grub_write_control_register (GRUB_CR4, cr4);

  /* Restore flags */
  grub_write_flags_register (eflags);

  return GRUB_ERR_NONE;
}

static void
init_slrt_storage (void)
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

  slr_intel_info_staging.hdr.tag = GRUB_SLR_ENTRY_INTEL_INFO;
  slr_intel_info_staging.hdr.size = sizeof(struct grub_slr_entry_intel_info);
}

static void
setup_slrt_policy (struct grub_slaunch_params *slparams,
                   struct grub_txt_os_mle_data *os_mle_data)
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

  slr_policy_staging->policy_entries[i].pcr = 18;
  slr_policy_staging->policy_entries[i].entity_type = GRUB_SLR_ET_TXT_OS2MLE;
  slr_policy_staging->policy_entries[i].entity = (grub_uint64_t)os_mle_data;
  slr_policy_staging->policy_entries[i].size = sizeof(struct grub_txt_os_mle_data);
  grub_strcpy (slr_policy_staging->policy_entries[i].evt_info, "Measured TXT OS-MLE data");
}

static void
setup_slr_table (struct grub_slaunch_params *slparams)
{
  grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                      (struct grub_slr_entry_hdr *)&slr_dl_info_staging);
  grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                      (struct grub_slr_entry_hdr *)&slr_log_info_staging);
  grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                      (struct grub_slr_entry_hdr *)slr_policy_staging);
  grub_slr_add_entry ((struct grub_slr_table *)slparams->slr_table_base,
                      (struct grub_slr_entry_hdr *)&slr_intel_info_staging);
}

void
grub_txt_update_slrt_policy (struct grub_slaunch_params *slparams)
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

static void
set_txt_info_ptr (struct grub_slaunch_params *slparams,
                  struct grub_txt_os_mle_data *os_mle_data)
{
  struct grub_slr_entry_hdr *txt_info;

  txt_info = grub_slr_next_entry_by_tag ((struct grub_slr_table *)slparams->slr_table_base,
                                         NULL,
                                         GRUB_SLR_ENTRY_INTEL_INFO);
  os_mle_data->txt_info = (grub_uint64_t)txt_info;
}

static grub_err_t
init_txt_heap (struct grub_slaunch_params *slparams, struct grub_txt_acm_header *sinit)
{
  grub_uint8_t *txt_heap;
  grub_uint32_t os_sinit_data_ver, sinit_caps;
  grub_uint64_t *size;
  struct grub_txt_os_mle_data *os_mle_data;
  struct grub_txt_os_sinit_data *os_sinit_data;
  struct grub_txt_heap_end_element *heap_end_element;
  struct grub_txt_heap_event_log_pointer2_1_element *heap_event_log_pointer2_1_element;
#ifdef GRUB_MACHINE_EFI
  struct grub_acpi_rsdp_v20 *rsdp;
#endif
  struct grub_slr_txt_mtrr_state saved_mtrrs_state = {0};

  /* BIOS data already verified in grub_txt_verify_platform(). */

  txt_heap = grub_txt_get_heap ();

  /* Prepare SLR table staging area */
  init_slrt_storage ();

  /* OS/loader to MLE data. */

  os_mle_data = grub_txt_os_mle_data_start (txt_heap);
  size = (grub_uint64_t *) ((grub_addr_t) os_mle_data - sizeof (grub_uint64_t));
  *size = sizeof (*os_mle_data) + sizeof (grub_uint64_t);

  grub_memset (os_mle_data, 0, sizeof (*os_mle_data));

  os_mle_data->version = GRUB_SL_OS_MLE_STRUCT_VERSION;
  os_mle_data->boot_params_addr = (grub_uint32_t)(grub_addr_t) slparams->boot_params;
  os_mle_data->slrt = slparams->slr_table_base;

  os_mle_data->ap_wake_block = slparams->ap_wake_block;
  os_mle_data->ap_wake_block_size = slparams->ap_wake_block_size;

  slr_log_info_staging.addr = slparams->tpm_evt_log_base;
  slr_log_info_staging.size = slparams->tpm_evt_log_size;
  slr_log_info_staging.format =
        (grub_get_tpm_ver () == GRUB_TPM_20) ?
        GRUB_SLR_DRTM_TPM20_LOG : GRUB_SLR_DRTM_TPM20_LOG;

  /* Save the BSPs MTRR state so post launch can restore itt */
  save_mtrrs (&saved_mtrrs_state);

  /* Setup the TXT specific SLR information */
  slr_intel_info_staging.txt_heap = (grub_uint64_t)txt_heap;
  slr_intel_info_staging.saved_misc_enable_msr =
               grub_rdmsr (GRUB_MSR_X86_MISC_ENABLE);
  grub_memcpy (&(slr_intel_info_staging.saved_bsp_mtrrs), &saved_mtrrs_state,
               sizeof(struct grub_slr_txt_mtrr_state));

  /* Create the SLR security policy */
  setup_slrt_policy (slparams, os_mle_data);

  /* OS/loader to SINIT data. */

  os_sinit_data_ver = grub_txt_supported_os_sinit_data_ver (sinit);

  if (os_sinit_data_ver < OS_SINIT_DATA_MIN_VER)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("unsupported OS to SINIT data version in SINIT ACM: %d"
		       " expected >= %d"), os_sinit_data_ver, OS_SINIT_DATA_MIN_VER);

  os_sinit_data = grub_txt_os_sinit_data_start (txt_heap);
  size = (grub_uint64_t *) ((grub_addr_t) os_sinit_data - sizeof (grub_uint64_t));

  *size = sizeof(grub_uint64_t) + sizeof (struct grub_txt_os_sinit_data) +
	  sizeof (struct grub_txt_heap_end_element);

  if (grub_get_tpm_ver () == GRUB_TPM_12)
    *size += sizeof (struct grub_txt_heap_tpm_event_log_element);
  else if (grub_get_tpm_ver () == GRUB_TPM_20)
    *size += sizeof (struct grub_txt_heap_event_log_pointer2_1_element);
  else
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("unsupported TPM version"));

  grub_memset (os_sinit_data, 0, *size);

#ifdef GRUB_MACHINE_EFI
  rsdp = grub_acpi_get_rsdpv2 ();

  if (rsdp == NULL)
    return grub_printf ("WARNING: ACPI RSDP 2.0 missing\n");

  os_sinit_data->efi_rsdt_ptr = (grub_uint64_t)(grub_addr_t) rsdp;
#endif

  os_sinit_data->mle_ptab = slparams->mle_ptab_target;
  os_sinit_data->mle_size = slparams->mle_size;

  os_sinit_data->mle_hdr_base = slparams->mle_header_offset;

  /* TODO: Check low PMR with RMRR. Look at relevant tboot code too. */
  /* TODO: Kernel should not allocate any memory outside of PMRs regions!!! */
  os_sinit_data->vtd_pmr_lo_base = 0;
  os_sinit_data->vtd_pmr_lo_size = ALIGN_DOWN (grub_mmap_get_highest (0x100000000),
					       GRUB_TXT_PMR_ALIGN);

  os_sinit_data->vtd_pmr_hi_base = ALIGN_UP (grub_mmap_get_lowest (0x100000000),
					     GRUB_TXT_PMR_ALIGN);
  os_sinit_data->vtd_pmr_hi_size = ALIGN_DOWN (grub_mmap_get_highest (0xffffffffffffffff),
					       GRUB_TXT_PMR_ALIGN);
  os_sinit_data->vtd_pmr_hi_size -= os_sinit_data->vtd_pmr_hi_base;

  grub_dprintf ("slaunch",
		"vtd_pmr_lo_base: 0x%" PRIxGRUB_UINT64_T " vtd_pmr_lo_size: 0x%"
		PRIxGRUB_UINT64_T " vtd_pmr_hi_base: 0x%" PRIxGRUB_UINT64_T
		" vtd_pmr_hi_size: 0x%" PRIxGRUB_UINT64_T "\n",
		os_sinit_data->vtd_pmr_lo_base, os_sinit_data->vtd_pmr_lo_size,
		os_sinit_data->vtd_pmr_hi_base, os_sinit_data->vtd_pmr_hi_size);

  sinit_caps = grub_txt_get_sinit_capabilities (sinit);

  /* CBnT bits 5:4 must be 11b, since D/A mapping is the only one supported. */
  os_sinit_data->capabilities = GRUB_TXT_CAPS_TPM_12_NO_LEGACY_PCR_USAGE |
				GRUB_TXT_CAPS_TPM_12_AUTH_PCR_USAGE;

  /* Choose monitor RLP wakeup mechanism first. */
  if (sinit_caps & GRUB_TXT_CAPS_MONITOR_SUPPORT)
    os_sinit_data->capabilities |= GRUB_TXT_CAPS_MONITOR_SUPPORT;
  else if (sinit_caps & GRUB_TXT_CAPS_GETSEC_WAKE_SUPPORT)
    os_sinit_data->capabilities |= GRUB_TXT_CAPS_GETSEC_WAKE_SUPPORT;
  else
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("lack of RLP wakeup mechanism"));

  if (sinit_caps & GRUB_TXT_CAPS_ECX_PT_SUPPORT)
    os_sinit_data->capabilities |= GRUB_TXT_CAPS_ECX_PT_SUPPORT;

  if (grub_get_tpm_ver () == GRUB_TPM_12)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("TPM 1.2 is not supported"));
  else
    {
      if (!(sinit_caps & GRUB_TXT_CAPS_TPM_20_EVTLOG_SUPPORT))
	return grub_error (GRUB_ERR_BAD_ARGUMENT,
			   N_("original TXT TPM 2.0 event log format is not supported"));

      os_sinit_data->capabilities |= GRUB_TXT_CAPS_TPM_20_EVTLOG_SUPPORT;

      os_sinit_data->flags = GRUB_TXT_PCR_EXT_MAX_PERF_POLICY;

      os_sinit_data->version = OS_SINIT_DATA_TPM_20_VER;

      heap_event_log_pointer2_1_element =
	(struct grub_txt_heap_event_log_pointer2_1_element *) os_sinit_data->ext_data_elts;
      heap_event_log_pointer2_1_element->type = GRUB_TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1;
      heap_event_log_pointer2_1_element->size = sizeof (*heap_event_log_pointer2_1_element);

      /* FIXME: First option is correct way to do!!! */
#if 1
      heap_event_log_pointer2_1_element->phys_addr = slparams->tpm_evt_log_base;
      heap_event_log_pointer2_1_element->allocated_event_container_size = slparams->tpm_evt_log_size;
#else
      heap_event_log_pointer2_1_element->phys_addr = (grub_addr_t) &os_mle_data->event_log_buffer;
      heap_event_log_pointer2_1_element->allocated_event_container_size = sizeof (os_mle_data->event_log_buffer);
#endif

      heap_end_element = (struct grub_txt_heap_end_element *)
	((grub_addr_t) heap_event_log_pointer2_1_element + heap_event_log_pointer2_1_element->size);
      heap_end_element->type = GRUB_TXT_HEAP_EXTDATA_TYPE_END;
      heap_end_element->size = sizeof (*heap_end_element);
    }

  /*
   * TODO: TXT spec: Note: BiosDataSize + OsMleDataSize + OsSinitDataSize + SinitMleDataSize
   * must be less than or equal to TXT.HEAP.SIZE, TXT spec, p. 102.
   */

  return GRUB_ERR_NONE;
}

/*
 * TODO: Why 1 GiB limit? It does not seem that it is required by TXT spec.
 * If there is a limit then it should be checked before allocation and image load.
 *
 * If enough room is available in front of the MLE, the maximum size of an
 * MLE that can be covered is 1G. This is due to having 512 PDEs pointing
 * to 512 page tables with 512 PTEs each.
 */
grub_uint32_t
grub_txt_get_mle_ptab_size (grub_uint32_t mle_size)
{
  /*
   * #PT + 1 PT + #PD + 1 PD + 1 PDT
   *
   * Why do we need 2 extra PTEs and PDEs? Yes, because MLE image may not
   * start and end at PTE (page) and PDE (2 MiB) boundary...
   */
  return ((((mle_size / GRUB_PAGE_SIZE) + 2) / 512) + 1 +
	  (((mle_size / (512 * GRUB_PAGE_SIZE)) + 2) / 512) + 1 + 1) * GRUB_PAGE_SIZE;
}

/* Page directory and table entries only need Present set */
#define MAKE_PT_MLE_ENTRY(addr)  (((grub_uint64_t)(grub_addr_t)(addr) & GRUB_PAGE_MASK) | 0x01)

/*
 * The MLE page tables have to be below the MLE and have no special regions in
 * between them and the MLE (this is a bit of an unwritten rule).
 * 20 pages are carved out of memory below the MLE. That leave 18 page table
 * pages that can cover up to 36M .
 * can only contain 4k pages
 *
 * TODO: TXT Spec p.32; List section name and number with PT MLE requirments here.
 *
 * TODO: This function is not able to cover MLEs larger than 1 GiB. Fix it!!!
 * After fixing inrease GRUB_TXT_MLE_MAX_SIZE too.
 */
void
grub_txt_setup_mle_ptab (struct grub_slaunch_params *slparams)
{
  grub_uint8_t *pg_dir, *pg_dir_ptr_tab = slparams->mle_ptab_mem, *pg_tab;
  grub_uint32_t mle_off = 0, pd_off = 0;
  grub_uint64_t *pde, *pte;

  grub_memset (pg_dir_ptr_tab, 0, slparams->mle_ptab_size);

  pg_dir         = pg_dir_ptr_tab + GRUB_PAGE_SIZE;
  pg_tab         = pg_dir + GRUB_PAGE_SIZE;

  /* Only use first entry in page dir ptr table */
  *(grub_uint64_t *)pg_dir_ptr_tab = MAKE_PT_MLE_ENTRY(pg_dir);

  /* Start with first entry in page dir */
  *(grub_uint64_t *)pg_dir = MAKE_PT_MLE_ENTRY(pg_tab);

  pte = (grub_uint64_t *)pg_tab;
  pde = (grub_uint64_t *)pg_dir;

  do
    {
      *pte = MAKE_PT_MLE_ENTRY(slparams->mle_start + mle_off);

      pte++;
      mle_off += GRUB_PAGE_SIZE;

      if (!(++pd_off % 512))
        {
          /* Break if we don't need any additional page entries */
          if (mle_off >= slparams->mle_size)
            break;
          pde++;
          *pde = MAKE_PT_MLE_ENTRY(pte);
        }
    } while (mle_off < slparams->mle_size);
}

grub_err_t
grub_txt_init (void)
{
  grub_err_t err;

  err = grub_txt_verify_platform ();

  if (err != GRUB_ERR_NONE)
    return err;

  err = enable_smx_mode ();

  if (err != GRUB_ERR_NONE)
    return err;

  return GRUB_ERR_NONE;
}

void
grub_txt_shutdown (void)
{
  /* Disable SMX mode. */
  grub_write_cr4 (grub_read_cr4 () & ~GRUB_CR4_X86_SMXE);
}

void
grub_txt_state_show (void)
{
  grub_uint64_t data;
  grub_uint8_t *data8 = (grub_uint8_t *) &data;
  int i;

  data = grub_txt_reg_pub_readq (GRUB_TXT_STS);
  grub_printf ("  TXT.STS: 0x%016" PRIxGRUB_UINT64_T "\n"
	       "    SENTER.DONE.STS:        %d\n"
	       "    SEXIT.DONE.STS:         %d\n"
	       "    MEM-CONFIGLOCK.STS:     %d\n"
	       "    PRIVATEOPEN.STS:        %d\n"
	       "    TXT.LOCALITY1.OPEN.STS: %d\n"
	       "    TXT.LOCALITY2.OPEN.STS: %d\n",
	       data, !!(data & GRUB_TXT_STS_SENTER_DONE),
	       !!(data & GRUB_TXT_STS_SEXIT_DONE),
	       !!(data & GRUB_TXT_STS_MEM_CONFIG_LOCK),
	       !!(data & GRUB_TXT_STS_PRIVATE_OPEN),
	       !!(data & GRUB_TXT_STS_LOCALITY1_OPEN),
	       !!(data & GRUB_TXT_STS_LOCALITY2_OPEN));

  /* Only least significant byte has a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_ESTS) & 0x00000000000000ff;
  grub_printf ("  TXT.ESTS: 0x%02" PRIxGRUB_UINT64_T "\n"
	       "    TXT_RESET.STS: %d\n", data,
	       !!(data & GRUB_TXT_ESTS_TXT_RESET));

  data = grub_txt_reg_pub_readq (GRUB_TXT_E2STS);
  grub_printf ("  TXT.E2STS: 0x%016" PRIxGRUB_UINT64_T "\n"
	       "    SECRETS.STS: %d\n", data,
	       !!(data & GRUB_TXT_E2STS_SECRETS));

  /* Only least significant 4 bytes have a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_ERRORCODE) & 0x00000000ffffffff;
  grub_printf ("  TXT.ERRORCODE: 0x%08" PRIxGRUB_UINT64_T "\n", data);

  data = grub_txt_reg_pub_readq (GRUB_TXT_DIDVID);
  grub_printf ("  TXT.DIDVID: 0x%016" PRIxGRUB_UINT64_T "\n"
	       "    VID:    0x%04" PRIxGRUB_UINT64_T "\n"
	       "    DID:    0x%04" PRIxGRUB_UINT64_T "\n"
	       "    RID:    0x%04" PRIxGRUB_UINT64_T "\n"
	       "    ID-EXT: 0x%04" PRIxGRUB_UINT64_T "\n",
	       data, data & 0x000000000000ffff,
	       (data & 0x00000000ffff0000) >> 16,
	       (data & 0x0000ffff00000000) >> 32, data >> 48);

  /* Only least significant 4 bytes have a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_VER_FSBIF) & 0x00000000ffffffff;
  grub_printf ("  TXT.VER.FSBIF: 0x%08" PRIxGRUB_UINT64_T "\n", data);

  if ((data != 0x00000000) && (data != 0xffffffff))
    grub_printf ("    DEBUG.FUSE: %d\n", !!(data & GRUB_TXT_VER_FSBIF_DEBUG_FUSE));
  else
    {
      /* Only least significant 4 bytes have a meaning. */
      data = grub_txt_reg_pub_readq (GRUB_TXT_VER_QPIIF) & 0x00000000ffffffff;
      grub_printf ("  TXT.VER.QPIIF: 0x%08" PRIxGRUB_UINT64_T "\n"
		   "    DEBUG.FUSE: %d\n", data,
		   !!(data & GRUB_TXT_VER_QPIIF_DEBUG_FUSE));
    }

  /* Only least significant 4 bytes have a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_SINIT_BASE) & 0x00000000ffffffff;
  grub_printf ("  TXT.SINIT.BASE: 0x%08" PRIxGRUB_UINT64_T "\n", data);

  /* Only least significant 4 bytes have a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_SINIT_SIZE) & 0x00000000ffffffff;
  grub_printf ("  TXT.SINIT.SIZE: %" PRIuGRUB_UINT64_T
	       " B (0x%" PRIxGRUB_UINT64_T ")\n", data, data);

  /* Only least significant 4 bytes have a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_HEAP_BASE) & 0x00000000ffffffff;
  grub_printf ("  TXT.HEAP.BASE: 0x%08" PRIxGRUB_UINT64_T "\n", data);

  /* Only least significant 4 bytes have a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_HEAP_SIZE) & 0x00000000ffffffff;
  grub_printf ("  TXT.HEAP.SIZE: %" PRIuGRUB_UINT64_T
	       " B (0x%" PRIxGRUB_UINT64_T ")\n", data, data);

  /* Only least significant 4 bytes have a meaning. */
  data = grub_txt_reg_pub_readq (GRUB_TXT_DPR) & 0x00000000ffffffff;
  grub_printf ("  TXT.DPR: 0x%08" PRIxGRUB_UINT64_T "\n"
	       "    LOCK: %d\n"
	       "    TOP:  0x%08" PRIxGRUB_UINT64_T "\n"
	       "    SIZE: %" PRIuGRUB_UINT64_T " MiB\n",
	       data, !!(data & (1 << 0)), (data & 0xfff00000),
	       (data & 0x00000ff0) >> 4);

  grub_printf ("  TXT.PUBLIC.KEY:\n");

  for (i = 0; i < 4; ++i)
    {
      /* TODO: Check relevant MSRs on SGX platforms. */
      data = grub_txt_reg_pub_readq (GRUB_TXT_PUBLIC_KEY + i * sizeof (grub_uint64_t));
      grub_printf ("    %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x%s", data8[0], data8[1],
		   data8[2], data8[3], data8[4], data8[5], data8[6], data8[7],
		   (i < 3) ? ":\n" : "\n");
    }
}

grub_err_t
grub_txt_boot_prepare (struct grub_slaunch_params *slparams)
{
  grub_err_t err;
  grub_uint8_t *txt_heap;
  struct grub_txt_os_mle_data *os_mle_data;
  struct grub_txt_mle_header *mle_header;
  struct grub_txt_acm_header *sinit_base;
  struct grub_slr_table *slrt = slparams->slr_table_mem;

  /* Setup the generic bits of the SLRT */
  grub_slr_init_table(slrt, GRUB_SLR_INTEL_TXT, slparams->slr_table_size);

  slparams->platform_type = grub_slaunch_platform_type ();

  sinit_base = grub_txt_sinit_select (grub_slaunch_module ());

  if (sinit_base == NULL)
    return grub_errno;

  err = init_txt_heap (slparams, sinit_base);

  if (err != GRUB_ERR_NONE)
    return err;

  /* Update the MLE header. */
  mle_header = (struct grub_txt_mle_header *)(grub_addr_t) (slparams->mle_start + slparams->mle_header_offset);
  mle_header->first_valid_page = 0;
  mle_header->mle_end = slparams->mle_size;

  slparams->dce_base = (grub_uint32_t)(grub_addr_t) sinit_base;
  slparams->dce_size = sinit_base->size * 4;

  /* Setup DL entry point, DCE and DLME information */
  slr_dl_info_staging.bl_context.bootloader = GRUB_SLR_BOOTLOADER_GRUB;
  slr_dl_info_staging.bl_context.context = (grub_uint64_t)slparams;
  slr_dl_info_staging.dl_handler = (grub_uint64_t)dl_entry_trampoline;
  slr_dl_info_staging.dlme_size = slparams->mle_size;
  slr_dl_info_staging.dlme_base = slparams->mle_start;
  slr_dl_info_staging.dlme_entry = mle_header->entry_point;
  slr_dl_info_staging.dce_base = slparams->dce_base;
  slr_dl_info_staging.dce_size = slparams->dce_size;

  /* Final setup of SLR table */
  txt_heap = grub_txt_get_heap ();
  os_mle_data = grub_txt_os_mle_data_start (txt_heap);
  setup_slr_table (slparams);
  set_txt_info_ptr (slparams, os_mle_data);

  grub_tpm_relinquish_locality (0);

  return GRUB_ERR_NONE;
}
