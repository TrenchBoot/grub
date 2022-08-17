/*
 * verify.c: verify that platform and processor supports Intel(r) TXT
 *
 * Copyright (c) 2003-2010, Intel Corporation
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
 *
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
#include <grub/cpu/relocator.h>
#include <grub/i386/cpuid.h>
#include <grub/i386/msr.h>
#include <grub/i386/txt.h>

/* Current max that the secure launch can handle */
#define TXT_MAX_CPUS	512

static grub_err_t
verify_bios_spec_ver_elt (struct grub_txt_heap_ext_data_element *elt)
{
  grub_uint8_t *ptr = (grub_uint8_t *)elt;
  struct grub_txt_heap_bios_spec_ver_element *bios_spec_ver_elt =
         (struct grub_txt_heap_bios_spec_ver_element *)ptr;

  if ( elt->size != sizeof(*elt) + sizeof(*bios_spec_ver_elt) )
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                N_("HEAP_BIOS_SPEC_VER element has wrong size (%d)"),
                elt->size);

  /* Any values are allowed */
  return GRUB_ERR_NONE;
}

static grub_err_t
verify_acm_elt (struct grub_txt_heap_ext_data_element *elt)
{
  grub_uint8_t *ptr = ((grub_uint8_t *)elt + sizeof(*elt));
  struct grub_txt_heap_acm_element *acm_elt =
         (struct grub_txt_heap_acm_element *)ptr;
  grub_uint64_t *acm_addrs;
  grub_uint32_t i;

  if ( elt->size != sizeof(*elt) + sizeof(*acm_elt) +
       acm_elt->num_acms*sizeof(grub_uint64_t) )
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                N_("HEAP_ACM element has wrong size (%d)"),
                elt->size);

  /* No addrs is not error, but print warning. */
  if ( acm_elt->num_acms == 0 )
    grub_printf ("WARNING: HEAP_ACM element has no ACM addrs\n");

  acm_addrs = (grub_uint64_t *)(ptr + sizeof(*acm_elt));
  for ( i = 0; i < acm_elt->num_acms; i++ )
    {
      if ( acm_addrs[i] == 0 )
        return grub_error (GRUB_ERR_OUT_OF_RANGE,
                    N_("HEAP_ACM element ACM addr (%d) is NULL"), i);

      if ( acm_addrs[i] >= 0x100000000UL )
        return grub_error (GRUB_ERR_OUT_OF_RANGE,
                    N_("HEAP_ACM element ACM addr (%d) is >4GB"), i);

      /* Not going to check if ACM addrs are valid ACMs */
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
verify_custom_elt (struct grub_txt_heap_ext_data_element *elt)
{
  grub_uint8_t *ptr = (grub_uint8_t *)elt;
  struct grub_txt_heap_custom_element *custom_elt =
         (struct grub_txt_heap_custom_element *)ptr;

  if ( elt->size < sizeof(*elt) + sizeof(*custom_elt) )
     return grub_error (GRUB_ERR_OUT_OF_RANGE,
                 N_("HEAP_CUSTOM element has wrong size (%d)"),
                 elt->size);

  /* Any values are allowed */

  return GRUB_ERR_NONE;
}

static grub_err_t
verify_evt_log_ptr_elt (struct grub_txt_heap_ext_data_element *elt)
{
  grub_uint8_t *ptr = (grub_uint8_t *)elt;
  struct grub_txt_heap_tpm_event_log_element *elog_elt =
         (struct grub_txt_heap_tpm_event_log_element *)ptr;

  if ( elt->size != sizeof(*elt) + sizeof(*elog_elt) )
     return grub_error (GRUB_ERR_OUT_OF_RANGE,
                 N_("HEAP_EVENT_LOG_POINTER element has wrong size (%d)"),
                 elt->size);

  /* TODO: Sort out how to do this verifier once the event log handling is in place
   *
   * return verify_evt_log((event_log_container_t *)(unsigned long)
   *                       elog_elt->event_log_phys_addr);
   */

  return GRUB_ERR_NONE;
}

static grub_err_t
verify_ext_data_elts(struct grub_txt_heap_ext_data_element *elts,
                     grub_uint64_t elts_size)
{
  struct grub_txt_heap_ext_data_element *elt = elts;
  grub_err_t err;

  if ( elts_size < sizeof(*elt) )
     return grub_error (GRUB_ERR_OUT_OF_RANGE,
                 N_("TXT heap ext data elements too small"));

  for ( ; ; )
    {
      if ( elts_size < elt->size || elt->size == 0 )
        return grub_error (GRUB_ERR_OUT_OF_RANGE,
                    N_("TXT heap invalid element size: type: %d, size: %d"),
                    elt->type, elt->size);

      switch ( elt->type )
        {
          case GRUB_TXT_HEAP_EXTDATA_TYPE_END:
            return GRUB_ERR_NONE;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_BIOS_SPEC_VER:
            err = verify_bios_spec_ver_elt (elt);
            if ( err )
              return err;
            break;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_ACM:
            err = verify_acm_elt (elt);
            if ( err )
              return err;
            break;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_STM:
            /* Nothing to check, platform specific */
            break;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_CUSTOM:
            err = verify_custom_elt (elt);
            if ( err )
              return err;
            break;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR:
            err = verify_evt_log_ptr_elt (elt);
            if ( err )
              return err;
            break;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_MADT:
            /* Copy of ACPI MADT, not validating */
            break;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1:
            /* TODO TBOOT did not verify this, not sure why or how to do it */
            break;
          case GRUB_TXT_HEAP_EXTDATA_TYPE_MCFG:
            /* Copy of ACPI MCFG, not validating */
            break;
          default:
	    /* TODO: What kind of element??? Improve the message. */
	    grub_printf ("WARNING: unknown element: type: %u, size: %u\n", elt->type, elt->size);
            break;
        }

      elts_size -= elt->size;
      elt = (struct grub_txt_heap_ext_data_element *)((grub_uint8_t *)elt + elt->size);
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_txt_verify_platform (void)
{
  grub_uint8_t *txt_heap;
  grub_uint32_t eax, ebx, ecx, edx;
  grub_uint64_t bios_size, heap_base, heap_size, msr;
  grub_err_t err = GRUB_ERR_NONE;
  struct grub_txt_bios_data *bios_data;
  struct grub_txt_heap_ext_data_element *elts;

  grub_cpuid (GRUB_X86_CPUID_FEATURES, eax, ebx, ecx, edx);

  if (!(ecx & GRUB_SMX_CPUID_FEATURE))
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("CPU does not support SMX"));

  msr = grub_rdmsr (GRUB_MSR_X86_FEATURE_CONTROL);

  if ((msr & (GRUB_MSR_X86_SENTER_FUNCTIONS | GRUB_MSR_X86_SENTER_ENABLE)) !=
      (GRUB_MSR_X86_SENTER_FUNCTIONS | GRUB_MSR_X86_SENTER_ENABLE))
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("GETSEC[SENTER] is not enabled"));

  /*
   * TODO
   * TXT Specification
   * 4.5 SGX Requirement for TXT Platform
   * Secure Launch currently does not support interop with SGX since it does
   * not have TPM support to write the SE NVRAM index.
   * Eventually need the verify_IA32_se_svn_status routine to be called here.
   */

  if (grub_txt_reg_pub_readq (GRUB_TXT_ESTS) & GRUB_TXT_ESTS_TXT_RESET)
     return grub_error (GRUB_ERR_BAD_DEVICE,
			N_("TXT_RESET.STS is set and GETSEC[SENTER] is disabled"));

  /*
   * Verify that the BIOS information in the TXT heap that was setup by the
   * BIOS ACM is sane.
   */

  txt_heap = grub_txt_get_heap ();
  heap_base = grub_txt_reg_pub_readq (GRUB_TXT_HEAP_BASE);
  heap_size = grub_txt_reg_pub_readq (GRUB_TXT_HEAP_SIZE);

  if ( txt_heap == NULL || heap_base == 0 || heap_size == 0 )
     return grub_error (GRUB_ERR_BAD_DEVICE,
                 N_("TXT heap is not configured correctly"));

  bios_size = grub_txt_bios_data_size (txt_heap);
  if ( bios_size == 0 || bios_size > heap_size )
     return grub_error (GRUB_ERR_OUT_OF_RANGE,
                 N_("invalid size of the TXT heap BIOS data table"));

  bios_data = grub_txt_bios_data_start (txt_heap);

  /* Check version */
  if ( bios_data->version < 3 )
     return grub_error (GRUB_ERR_OUT_OF_RANGE,
                 N_("unsupported BIOS data version (%d)"), bios_data->version);

  if ( bios_data->num_logical_procs > TXT_MAX_CPUS )
     return grub_error (GRUB_ERR_OUT_OF_RANGE,
                 N_("BIOS reports too many CPUs for secure launch (%d)"),
                 bios_data->num_logical_procs);

  if ( bios_data->version >= 4 && bios_size > sizeof(*bios_data) + sizeof(bios_size) )
    {
      elts = (struct grub_txt_heap_ext_data_element *) ((grub_uint8_t *)bios_data + sizeof(*bios_data));
      err = verify_ext_data_elts(elts, bios_size - sizeof(*bios_data));
    }

  return err;
}
