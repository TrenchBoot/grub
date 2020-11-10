/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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

#include <grub/cpu/relocator.h>
#include <grub/dl.h>
#include <grub/i386/skinit.h>
#include <grub/i386/tpm.h>
#include <grub/mm.h>
#include <grub/slr_table.h>
#include <grub/types.h>

#define SLRT_SIZE  GRUB_PAGE_SIZE

/* Offset to entry point. */
#define SLB_ENTRY(slb)    ((const grub_uint16_t *) (slb))[0]
/* Amount of data actually measured for DRTM. */
#define SLB_MEASURED(slb) ((const grub_uint16_t *) (slb))[1]
/* Offset to structure with extra info. */
#define SLB_INFO(slb)     ((const grub_uint16_t *) (slb))[2]
/* Offset to area for passing data to SKL. */
#define SLB_PARAM(slb)    ((const grub_uint16_t *) (slb))[3]

grub_err_t
grub_skinit_boot_prepare (struct grub_relocator *rel,
                          struct grub_slaunch_params *slparams)
{
  grub_uint32_t *apic = (grub_uint32_t *) 0xfee00300ULL;
  const void *slb = grub_slaunch_module ();
  grub_relocator_chunk_t ch;
  grub_err_t err;
  void *dce_mem;

  if (slb == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "SLB module is missing");

  /*
   * Contrary to the TXT, on AMD we do not have vendor-provided blobs in
   * reserved memory, we are using normal RAM
   */
  err = grub_relocator_alloc_chunk_align (rel, &ch, 0,
                                          0xffffffff - GRUB_SKINIT_SLB_SIZE,
                                          GRUB_SKINIT_SLB_SIZE,
                                          GRUB_SKINIT_SLB_ALIGN,
                                          GRUB_RELOCATOR_PREFERENCE_LOW, 1);

  if (err != GRUB_ERR_NONE)
    return grub_error (err, "cannot alloc memory for SLB");

  /*
   * Send INIT IPI to all APs (CPUs other than this one).
   *
   * "AMD64 Architecture Programmer’s Manual, Rev. 3.42, Vol. 2" says "Depending
   * on processor implementation, a fixed delay of no more than 1000 processor
   * cycles may be necessary before executing SKINIT to ensure reliable sensing
   * of APIC INIT state by the SKINIT."
   *
   * However, in tests it wasn't always enough (sometimes up to 7000 cycles
   * were necessary), so send the IPIs before grub_memcpy()/grub_memset() to
   * increase the delay before SKINIT is executed.
   */
  grub_dprintf ("slaunch", "broadcasting INIT\r\n");
  *apic = 0x000c0500;

  slparams->dce_base = get_physical_target_address (ch);
  slparams->dce_size = SLB_MEASURED (slb);

  dce_mem = get_virtual_current_address (ch);
  grub_memcpy (dce_mem, slb, slparams->dce_size);

  slparams->slr_table_base = slparams->dce_base + SLB_PARAM (slb);
  slparams->slr_table_size = SLRT_SIZE;
  slparams->slr_table_mem = (grub_uint8_t *) dce_mem + SLB_PARAM (slb);
  grub_memset (slparams->slr_table_mem, 0, SLRT_SIZE);

  grub_slaunch_init_slrt_storage (GRUB_SLR_AMD_SKINIT);

  grub_dprintf ("slaunch", "grub_tpm_relinquish_locality\r\n");
  grub_tpm_relinquish_locality (0);

  grub_dprintf ("slaunch", "Invoke SKINIT\r\n");

  return GRUB_ERR_NONE;
}
