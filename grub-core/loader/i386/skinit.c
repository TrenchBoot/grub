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

int
grub_skinit_is_slb (const void *slb_base, grub_uint32_t slb_size)
{
  const grub_uint8_t skl_uuid[16] = {
    0x78, 0xf1, 0x26, 0x8e, 0x04, 0x92, 0x11, 0xe9,
    0x83, 0x2a, 0xc8, 0x5b, 0x76, 0xc4, 0xcc, 0x02,
  };
  /* We need space after SLB to pass SLRT to it. */
  const grub_ssize_t max_size = GRUB_SKINIT_SLB_SIZE - SLRT_SIZE;

  const grub_uint8_t *uuid;

  if (slb_size > max_size)
    {
      grub_dprintf ("slaunch", "SLB is too large: %d > %d\n",
                    slb_size, max_size);
      return 0;
    }

  if (SLB_MEASURED (slb_base) > slb_size)
    {
      grub_dprintf ("slaunch", "SLB measured size is too large: %d > %d\n",
                    SLB_MEASURED (slb_base), slb_size);
      return 0;
    }

  if (SLB_ENTRY (slb_base) >= SLB_MEASURED (slb_base))
    {
      grub_dprintf ("slaunch", "SLB entry is not measured: %d >= %d\n",
                    SLB_ENTRY (slb_base), SLB_MEASURED (slb_base));
      return 0;
    }

  if (SLB_INFO (slb_base) > SLB_MEASURED (slb_base) - sizeof(skl_uuid))
    {
      grub_dprintf ("slaunch", "SLB info is not measured: %d > %d\n",
                    SLB_INFO (slb_base),
                    SLB_MEASURED (slb_base) - sizeof(skl_uuid));
      return 0;
    }

  if (SLB_PARAM (slb_base) > max_size)
    {
      grub_dprintf ("slaunch", "SLB bootloader data offset is too large: %d > %d\n",
                    SLB_PARAM (slb_base), max_size);
      return 0;
    }

  uuid = (const grub_uint8_t *) slb_base + SLB_INFO (slb_base);
  if (grub_memcmp (uuid, skl_uuid, sizeof(skl_uuid)) != 0)
    {
      grub_dprintf ("slaunch", "SLB has unexpected UUID\n");
      return 0;
    }

  return 1;
}

grub_err_t
grub_skinit_boot_prepare (struct grub_relocator *rel,
                          struct grub_slaunch_params *slparams)
{
  grub_uint32_t *apic = (grub_uint32_t *)0xfee00300ULL;
  const void *slb = grub_slaunch_module ();
  grub_relocator_chunk_t ch;
  grub_err_t err;
  void *dce_mem;

  if (slb == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "SLB module is missing");

  err = grub_relocator_alloc_chunk_align_safe (rel, &ch, 0x1000000,
                                               UP_TO_TOP32(GRUB_SLAUNCH_TPM_EVT_LOG_SIZE),
                                               GRUB_SLAUNCH_TPM_EVT_LOG_SIZE, GRUB_PAGE_SIZE,
                                               GRUB_RELOCATOR_PREFERENCE_HIGH, 1);

  if (err != GRUB_ERR_NONE)
    return grub_error (err, "cannot alloc memory for TPM event log");

  slparams->tpm_evt_log_base = get_physical_target_address (ch);
  slparams->tpm_evt_log_size = GRUB_SLAUNCH_TPM_EVT_LOG_SIZE;
  grub_memset (get_virtual_current_address (ch), 0, slparams->tpm_evt_log_size);

  grub_dprintf ("slaunch", "tpm_evt_log_base = %lx, tpm_evt_log_size = %x\n",
                (unsigned long) slparams->tpm_evt_log_base,
                (unsigned) slparams->tpm_evt_log_size);

  /* Contrary to the TXT, on AMD we do not have vendor-provided blobs in
   * reserved memory, we are using normal RAM */
  err = grub_relocator_alloc_chunk_align (rel, &ch, 0,
                                          0xffffffff - GRUB_SKINIT_SLB_SIZE,
                                          GRUB_SKINIT_SLB_SIZE,
                                          GRUB_SKINIT_SLB_ALIGN,
                                          GRUB_RELOCATOR_PREFERENCE_LOW, 1);

  if (err != GRUB_ERR_NONE)
    return grub_error (err, "cannot alloc memory for SLB");

  slparams->dce_base = get_physical_target_address (ch);
  slparams->dce_size = SLB_MEASURED (slb);

  dce_mem = get_virtual_current_address (ch);
  grub_memcpy (dce_mem, slb, slparams->dce_size);

  slparams->slr_table_base = slparams->dce_base + SLB_PARAM (slb);
  slparams->slr_table_size = SLRT_SIZE;
  slparams->slr_table_mem = (grub_uint8_t *) dce_mem + SLB_PARAM (slb);
  grub_memset (slparams->slr_table_mem, 0, SLRT_SIZE);

  grub_slaunch_init_slrt_storage (GRUB_SLR_AMD_SKINIT);

  grub_dprintf ("slaunch", "broadcasting INIT\r\n");
  *apic = 0x000c0500;               // INIT, all excluding self
  grub_dprintf ("slaunch", "grub_tpm_relinquish_locality\r\n");
  grub_tpm_relinquish_locality (0);

  grub_dprintf ("slaunch", "Invoke SKINIT\r\n");

  return GRUB_ERR_NONE;
}
