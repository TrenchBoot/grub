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

#include <grub/loader.h>
#include <grub/memory.h>
#include <grub/normal.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/slaunch.h>

static inline grub_uint32_t *get_bootloader_data_addr (struct grub_slaunch_module *mod)
{
  grub_uint16_t *ptr = (grub_uint16_t *)mod->addr;
  return (grub_uint32_t *)(mod->addr + ptr[1]);
}

grub_err_t
grub_slaunch_boot_skinit (struct grub_slaunch_params *slparams)
{
  if (grub_slaunch_get_modules()) {
    grub_uint32_t *boot_data = get_bootloader_data_addr(grub_slaunch_get_modules());
    grub_uint32_t *apic = (grub_uint32_t *)0xfee00300ULL;

    grub_dprintf ("slaunch", "real_mode_target: 0x%x\r\n",
                  slparams->real_mode_target);
    grub_dprintf ("slaunch", "prot_mode_target: 0x%x\r\n",
                  slparams->prot_mode_target);
    grub_dprintf ("slaunch", "params: %p\r\n", slparams->params);

    // TODO: save kernel size for measuring in LZ
    boot_data[GRUB_SL_ZEROPAGE_OFFSET/4] = (grub_uint32_t)slparams->real_mode_target;
    grub_dprintf ("slaunch", "broadcasting INIT\r\n");
    *apic = 0x000c0500;               // INIT, all excluding self

    grub_dprintf ("slaunch", "grub_tis_init\r\n");
    grub_tis_init();
    grub_dprintf ("slaunch", "grub_tis_request_locality\r\n");
    grub_tis_request_locality(0xff);  // relinquish all localities

    grub_dprintf("linux", "Invoke SKINIT\r\n");
    return grub_relocator_skinit_boot (slparams->relocator, grub_slaunch_get_modules()->target, 0);
  } else {
    grub_dprintf("linux", "Secure Loader module not loaded, run slaunch_module\r\n");
  }
  return GRUB_ERR_NONE;
}
