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
#include <grub/cpu/relocator.h>
#include <grub/i386/cpuid.h>
#include <grub/i386/msr.h>
#include <grub/i386/crfr.h>
#include <grub/i386/txt.h>
#include <grub/i386/linux.h>
#include <grub/i386/memory.h>
#include <grub/i386/slaunch.h>
#include <grub/i386/tpm.h>

#define OS_SINIT_DATA_TPM_12_VER	6
#define OS_SINIT_DATA_TPM_20_VER	7

#define OS_SINIT_DATA_MIN_VER		OS_SINIT_DATA_TPM_12_VER

static struct grub_slr_entry_intel_info slr_intel_info_staging = {0};

static grub_err_t
enable_smx_mode (void)
{
  grub_uint32_t caps;
  grub_uint64_t feat_ctrl = grub_rdmsr (GRUB_MSR_X86_FEATURE_CONTROL);

  if (!(feat_ctrl & GRUB_MSR_X86_FEATURE_CTRL_LOCK))
    {
      grub_dprintf ("slaunch", "Firmware didn't lock FEATURE_CONTROL MSR,"
		    "locking it now\n");
      /* Not setting SENTER_FUNCTIONS and SENTER_ENABLE because they were tested
       * in grub_txt_verify_platform() */
      feat_ctrl |= GRUB_MSR_X86_FEATURE_CTRL_LOCK | GRUB_MSR_X86_ENABLE_VMX_IN_SMX;
      grub_wrmsr (GRUB_MSR_X86_FEATURE_CONTROL, feat_ctrl);
    }

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

  cr0 = grub_read_cr0 ();

  /* Cache must be enabled (CR0.CD = CR0.NW = 0). */
  cr0 &= ~(GRUB_CR0_X86_CD | GRUB_CR0_X86_NW);

  /* Native FPU error reporting must be enabled for proper interaction behavior. */
  cr0 |= GRUB_CR0_X86_NE;

  grub_write_cr0 (cr0);

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
			       N_("secure launch MCG[%u] = %Lx ERROR"), i, mcg_stat);
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
  /* Zero unused array items. */
  for ( ; i < GRUB_TXT_VARIABLE_MTRRS_LENGTH; ++i)
    {
      saved_bsp_mtrrs->mtrr_pair[i].mtrr_physmask = 0;
      saved_bsp_mtrrs->mtrr_pair[i].mtrr_physbase = 0;
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
static grub_err_t
set_mtrrs_for_acmod (struct grub_txt_acm_header *hdr)
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
  cr0 = grub_read_cr0 ();
  grub_write_cr0 ( (cr0 & ~GRUB_CR0_X86_NW) | GRUB_CR0_X86_CD );

  /* Flush caches */
  asm volatile ("wbinvd");

  /* Save CR4 and disable global pages (CR4.PGE=0) */
  cr4 = grub_read_cr4 ();
  grub_write_cr4 (cr4 & ~GRUB_CR4_X86_PGE);

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

  /* Restore CR0 (caching) */
  grub_write_cr0 (cr0);

  /* Restore CR4 (global pages) */
  grub_write_cr4 (cr4);

  /* Restore flags */
  grub_write_flags_register (eflags);

  return GRUB_ERR_NONE;
}

void
grub_txt_init_tpm_event_log (void *buf, grub_size_t size)
{
  struct event_log_container *elog;

  if (buf == NULL || size == 0)
    return;

  /* For TPM2 just clear the area, only TPM12 requires initialization. */
  grub_memset (buf, 0, size);

  if (grub_get_tpm_ver () != GRUB_TPM_12)
    return;

  elog = (struct event_log_container *) buf;

  grub_memcpy((void *)elog->signature, EVTLOG_SIGNATURE, sizeof(elog->signature));
  elog->container_ver_major = EVTLOG_CNTNR_MAJOR_VER;
  elog->container_ver_minor = EVTLOG_CNTNR_MINOR_VER;
  elog->pcr_event_ver_major = EVTLOG_EVT_MAJOR_VER;
  elog->pcr_event_ver_minor = EVTLOG_EVT_MINOR_VER;
  elog->size = size;
  elog->pcr_events_offset = sizeof(*elog);
  elog->next_event_offset = sizeof(*elog);
}

static void
setup_txt_slrt_entry (struct grub_slaunch_params *slparams,
                      struct grub_txt_os_mle_data *os_mle_data)
{
  struct grub_slr_table *slr_table = slparams->slr_table_mem;
  struct grub_slr_entry_hdr *txt_info;

  grub_slr_add_entry (slr_table, &slr_intel_info_staging.hdr);

  txt_info = grub_slr_next_entry_by_tag (slr_table, NULL, GRUB_SLR_ENTRY_INTEL_INFO);
  os_mle_data->txt_info = (grub_addr_t) slparams->slr_table_base
      + ((grub_addr_t) txt_info - (grub_addr_t) slparams->slr_table_mem);
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
  struct grub_txt_heap_tpm_event_log_element *heap_tpm_event_log_element;
  struct grub_txt_heap_event_log_pointer2_1_element *heap_event_log_pointer2_1_element;
#ifdef GRUB_MACHINE_EFI
  struct grub_acpi_rsdp_v20 *rsdp;
#endif

  /* BIOS data already verified in grub_txt_verify_platform(). */

  txt_heap = grub_txt_get_heap ();

  grub_dprintf ("slaunch", "TXT heap %p\n", txt_heap);

  /* OS/loader to MLE data. */

  os_mle_data = grub_txt_os_mle_data_start (txt_heap);
  grub_dprintf ("slaunch", "OS MLE data: %p\n", os_mle_data);
  size = (grub_uint64_t *) ((grub_addr_t) os_mle_data - sizeof (grub_uint64_t));
  *size = sizeof (*os_mle_data) + sizeof (grub_uint64_t);

  grub_memset (os_mle_data, 0, sizeof (*os_mle_data));

  os_mle_data->version = GRUB_SL_OS_MLE_STRUCT_VERSION;
  os_mle_data->boot_params_addr = slparams->boot_params_addr;
  os_mle_data->slrt = slparams->slr_table_base;

  os_mle_data->ap_wake_block = slparams->ap_wake_block;
  os_mle_data->ap_wake_block_size = slparams->ap_wake_block_size;

  /* Setup the TXT specific SLR information */
  slr_intel_info_staging.hdr.tag = GRUB_SLR_ENTRY_INTEL_INFO;
  slr_intel_info_staging.hdr.size = sizeof(struct grub_slr_entry_intel_info);
  slr_intel_info_staging.saved_misc_enable_msr =
               grub_rdmsr (GRUB_MSR_X86_MISC_ENABLE);

  /* Save the BSPs MTRR state so post launch can restore it. */
  grub_dprintf ("slaunch", "Saving MTRRs to OS MLE data\n");
  save_mtrrs (&slr_intel_info_staging.saved_bsp_mtrrs);

  /* OS/loader to SINIT data. */
  grub_dprintf ("slaunch", "Get supported OS SINIT data version\n");
  os_sinit_data_ver = grub_txt_supported_os_sinit_data_ver (sinit);

  if (os_sinit_data_ver < OS_SINIT_DATA_MIN_VER)
    return grub_error (GRUB_ERR_BAD_DEVICE,
		       N_("unsupported OS to SINIT data version in SINIT ACM: %d"
		       " expected >= %d"), os_sinit_data_ver, OS_SINIT_DATA_MIN_VER);

  os_sinit_data = grub_txt_os_sinit_data_start (txt_heap);
  grub_dprintf ("slaunch", "OS SINIT data: %p\n", os_sinit_data);
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
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("ACPI RSDP 2.0 missing\n"));

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

  grub_dprintf ("slaunch", "SINIT capabilities %08x\n", sinit_caps);

  os_sinit_data->capabilities = GRUB_TXT_CAPS_TPM_12_AUTH_PCR_USAGE;

  if (grub_get_tpm_ver () == GRUB_TPM_20)
    {
      /* CBnT bits 5:4 must be 11b, since D/A mapping is the only one supported. */
      if ((sinit_caps & os_sinit_data->capabilities) != os_sinit_data->capabilities)
        return grub_error (GRUB_ERR_BAD_ARGUMENT,
               N_("Details/authorities PCR usage is not supported"));
    }
  else
    {
      if (!(sinit_caps & GRUB_TXT_CAPS_TPM_12_AUTH_PCR_USAGE))
	{
	  grub_dprintf ("slaunch", "Details/authorities PCR usage is not supported. Trying legacy");
	  if (sinit_caps & GRUB_TXT_CAPS_TPM_12_NO_LEGACY_PCR_USAGE)
	    return grub_error (GRUB_ERR_BAD_ARGUMENT,
		N_("Not a single PCR usage available in SINIT capabilities"));

	  os_sinit_data->capabilities = 0;
	}
    }

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
    {
      grub_dprintf ("slaunch", "TPM 1.2 detected\n");
      grub_dprintf ("slaunch", "Setting up TXT HEAP TPM event log element\n");
      os_sinit_data->flags = GRUB_TXT_PCR_EXT_MAX_PERF_POLICY;
      os_sinit_data->version = OS_SINIT_DATA_TPM_12_VER;

      heap_tpm_event_log_element = (struct grub_txt_heap_tpm_event_log_element *)
                                   os_sinit_data->ext_data_elts;
      heap_tpm_event_log_element->type = GRUB_TXT_HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR;
      heap_tpm_event_log_element->size = sizeof (*heap_tpm_event_log_element);
      heap_tpm_event_log_element->event_log_phys_addr = slparams->tpm_evt_log_base;

      heap_end_element = (struct grub_txt_heap_end_element *)
  ((grub_addr_t) heap_tpm_event_log_element + heap_tpm_event_log_element->size);
      heap_end_element->type = GRUB_TXT_HEAP_EXTDATA_TYPE_END;
      heap_end_element->size = sizeof (*heap_end_element);
    }
  else
    {
      grub_dprintf ("slaunch", "TPM 2.0 detected\n");
      grub_dprintf ("slaunch", "Setting up TXT HEAP TPM event log element\n");
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
      heap_event_log_pointer2_1_element->phys_addr = slparams->tpm_evt_log_base;
      heap_event_log_pointer2_1_element->allocated_event_container_size = slparams->tpm_evt_log_size;

      heap_end_element = (struct grub_txt_heap_end_element *)
	((grub_addr_t) heap_event_log_pointer2_1_element + heap_event_log_pointer2_1_element->size);
      heap_end_element->type = GRUB_TXT_HEAP_EXTDATA_TYPE_END;
      heap_end_element->size = sizeof (*heap_end_element);
    }
  grub_dprintf ("slaunch", "TXT HEAP init done\n");
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
  union {
    grub_uint64_t d64;
    grub_uint32_t d32;
    grub_uint8_t d8;
    grub_uint8_t a8[8];
  } data;
  int i;
  union grub_txt_didvid didvid;

  data.d64 = grub_txt_reg_pub_readq (GRUB_TXT_STS);
  grub_printf ("  TXT.STS: 0x%016" PRIxGRUB_UINT64_T "\n"
	       "    SENTER.DONE.STS:        %d\n"
	       "    SEXIT.DONE.STS:         %d\n"
	       "    MEM-CONFIGLOCK.STS:     %d\n"
	       "    PRIVATEOPEN.STS:        %d\n"
	       "    TXT.LOCALITY1.OPEN.STS: %d\n"
	       "    TXT.LOCALITY2.OPEN.STS: %d\n",
	       data.d64, !!(data.d64 & GRUB_TXT_STS_SENTER_DONE),
	       !!(data.d64 & GRUB_TXT_STS_SEXIT_DONE),
	       !!(data.d64 & GRUB_TXT_STS_MEM_CONFIG_LOCK),
	       !!(data.d64 & GRUB_TXT_STS_PRIVATE_OPEN),
	       !!(data.d64 & GRUB_TXT_STS_LOCALITY1_OPEN),
	       !!(data.d64 & GRUB_TXT_STS_LOCALITY2_OPEN));

  /* Only least significant byte has a meaning. */
  data.d8 = grub_txt_reg_pub_readb (GRUB_TXT_ESTS);
  grub_printf ("  TXT.ESTS: 0x%02x\n"
	       "    TXT_RESET.STS: %d\n", data.d8,
	       !!(data.d8 & GRUB_TXT_ESTS_TXT_RESET));

  data.d64 = grub_txt_reg_pub_readq (GRUB_TXT_E2STS);
  grub_printf ("  TXT.E2STS: 0x%016" PRIxGRUB_UINT64_T "\n"
	       "    SECRETS.STS: %d\n", data.d64,
	       !!(data.d64 & GRUB_TXT_E2STS_SECRETS));

  /* Only least significant 4 bytes have a meaning. */
  data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_ERRORCODE);
  grub_printf ("  TXT.ERRORCODE: 0x%08" PRIxGRUB_UINT32_T "\n", data.d32);

  didvid.value = grub_txt_reg_pub_readq (GRUB_TXT_DIDVID);
  grub_printf ("  TXT.DIDVID: 0x%016" PRIxGRUB_UINT64_T "\n"
	       "    VID:    0x%04x\n"
	       "    DID:    0x%04x\n"
	       "    RID:    0x%04x\n"
	       "    ID-EXT: 0x%04x\n",
	       didvid.value, didvid.vid, didvid.did, didvid.rid, didvid.id_ext);

  /* Only least significant 4 bytes have a meaning. */
  data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_VER_FSBIF);
  grub_printf ("  TXT.VER.FSBIF: 0x%08" PRIxGRUB_UINT32_T "\n", data.d32);

  if ((data.d32 != 0x00000000) && (data.d32 != 0xffffffff))
    grub_printf ("    DEBUG.FUSE: %d\n", !!(data.d32 & GRUB_TXT_VER_FSBIF_DEBUG_FUSE));
  else
    {
      /* Only least significant 4 bytes have a meaning. */
      data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_VER_QPIIF);
      grub_printf ("  TXT.VER.QPIIF: 0x%08" PRIxGRUB_UINT32_T "\n"
		   "    DEBUG.FUSE: %d\n", data.d32,
		   !!(data.d32 & GRUB_TXT_VER_QPIIF_DEBUG_FUSE));
    }

  /* Only least significant 4 bytes have a meaning. */
  data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_SINIT_BASE);
  grub_printf ("  TXT.SINIT.BASE: 0x%08" PRIxGRUB_UINT32_T "\n", data.d32);

  /* Only least significant 4 bytes have a meaning. */
  data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_SINIT_SIZE);
  grub_printf ("  TXT.SINIT.SIZE: %" PRIuGRUB_UINT32_T
	       " B (0x%" PRIxGRUB_UINT32_T ")\n", data.d32, data.d32);

  /* Only least significant 4 bytes have a meaning. */
  data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_HEAP_BASE);
  grub_printf ("  TXT.HEAP.BASE: 0x%08" PRIxGRUB_UINT32_T "\n", data.d32);

  /* Only least significant 4 bytes have a meaning. */
  data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_HEAP_SIZE);
  grub_printf ("  TXT.HEAP.SIZE: %" PRIuGRUB_UINT32_T
	       " B (0x%" PRIxGRUB_UINT32_T ")\n", data.d32, data.d32);

  /* Only least significant 4 bytes have a meaning. */
  data.d32 = grub_txt_reg_pub_readl (GRUB_TXT_DPR);
  grub_printf ("  TXT.DPR: 0x%08" PRIxGRUB_UINT32_T "\n"
	       "    LOCK: %d\n"
	       "    TOP:  0x%08" PRIxGRUB_UINT32_T "\n"
	       "    SIZE: %" PRIuGRUB_UINT32_T " MiB\n",
	       data.d32, !!(data.d32 & (1 << 0)), (data.d32 & 0xfff00000),
	       (data.d32 & 0x00000ff0) >> 4);

  grub_printf ("  TXT.PUBLIC.KEY:\n");

  for (i = 0; i < 4; ++i)
    {
      /* TODO: Check relevant MSRs on SGX platforms. */
      data.d64 = grub_txt_reg_pub_readq (GRUB_TXT_PUBLIC_KEY + i * sizeof (grub_uint64_t));
      grub_printf ("    %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x%s", data.a8[0], data.a8[1],
		   data.a8[2], data.a8[3], data.a8[4], data.a8[5], data.a8[6], data.a8[7],
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

  sinit_base = grub_txt_sinit_select (grub_slaunch_module ());

  if (sinit_base == NULL)
    return grub_errno;

  grub_dprintf ("slaunch", "Init TXT heap\n");
  err = init_txt_heap (slparams, sinit_base);

  if (err != GRUB_ERR_NONE)
    return err;

  grub_dprintf ("slaunch", "TXT heap successfully prepared\n");

  /* Update the MLE header. */
  mle_header =
      (struct grub_txt_mle_header *) ((grub_uint8_t *) slparams->mle_mem + slparams->mle_header_offset);
  mle_header->first_valid_page = 0;
  mle_header->mle_end = slparams->mle_size;

  slparams->dce_base = (grub_uint32_t)(grub_addr_t) sinit_base;
  slparams->dce_size = sinit_base->size * 4;

  /* Setup of SLR table. */
  grub_slaunch_init_slrt_storage (GRUB_SLR_INTEL_TXT);
  txt_heap = grub_txt_get_heap ();
  os_mle_data = grub_txt_os_mle_data_start (txt_heap);
  setup_txt_slrt_entry (slparams, os_mle_data);

  grub_tpm_relinquish_locality (0);
  grub_dprintf ("slaunch", "Relinquished TPM locality 0\n");

  err = set_mtrrs_for_acmod (sinit_base);
  if (err)
    return grub_error (err, N_("secure launch failed to set MTRRs for ACM"));

  grub_dprintf ("slaunch", "MTRRs set for ACMOD\n");

  err = grub_txt_prepare_cpu ();
  if ( err )
    return err;

  grub_dprintf ("slaunch", "CPU prepared for secure launch\n");

  if (!(grub_rdmsr (GRUB_MSR_X86_APICBASE) & GRUB_MSR_X86_APICBASE_BSP))
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("secure launch must run on BSP"));

  return GRUB_ERR_NONE;
}

void
grub_txt_add_slrt_policy_entries (void)
{
  struct grub_txt_os_mle_data *os_mle_data;
  grub_uint8_t *txt_heap;

  txt_heap = grub_txt_get_heap ();
  os_mle_data = grub_txt_os_mle_data_start (txt_heap);

  grub_slaunch_add_slrt_policy_entry (18,
                                      GRUB_SLR_ET_TXT_OS2MLE,
                                      /*flags=*/0,
                                      (grub_addr_t) os_mle_data,
                                      sizeof(*os_mle_data),
                                      "Measured TXT OS-MLE data");
}
