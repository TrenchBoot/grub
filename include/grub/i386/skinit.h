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

#ifndef GRUB_I386_SKINIT_H
#define GRUB_I386_SKINIT_H 1

// SLB is 64k, 64k-aligned
#define GRUB_SKINIT_SLB_SIZE  0x10000
#define GRUB_SKINIT_SLB_ALIGN 0x10000

#ifndef ASM_FILE

#include <grub/i386/slaunch.h>

grub_err_t grub_skinit_boot_prepare (struct grub_slaunch_params *slparams);

static inline grub_uint16_t grub_skinit_get_sl_size (void)
{
  grub_uint16_t *ptr = (grub_uint16_t *)grub_slaunch_module ();

  if (ptr == NULL)
    return 0;

  return ptr[1];
}

#endif /* ASM_FILE */

#endif /* GRUB_I386_SKINIT_H */
