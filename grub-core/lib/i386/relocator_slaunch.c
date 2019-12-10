/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
 *  Copyright (C) 2019 3mdeb Embedded Systems Consulting
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

#include <grub/mm.h>
#include <grub/misc.h>

#include <grub/types.h>
#include <grub/err.h>
#include <grub/term.h>

#include <grub/i386/relocator.h>
#include <grub/relocator_private.h>
#include <grub/i386/relocator_private.h>
#include <grub/i386/pc/int.h>

extern grub_uint8_t grub_relocator_skinit_start;
extern grub_uint8_t grub_relocator_skinit_end;
extern grub_uint32_t *grub_relocator_skinit_slb;


#define RELOCATOR_SIZEOF(x)	(&grub_relocator##x##_end - &grub_relocator##x##_start)

grub_err_t
grub_relocator_skinit_boot (struct grub_relocator *rel,
		       grub_uint32_t *slb,
		       int avoid_efi_bootservices)
{
  grub_err_t err;
  void *relst;
  grub_relocator_chunk_t ch;

  err = grub_relocator_alloc_chunk_align (rel, &ch, 0x1000,
					  0x100000000 - RELOCATOR_SIZEOF (_skinit),
					  RELOCATOR_SIZEOF (_skinit), 16,
					  GRUB_RELOCATOR_PREFERENCE_LOW,
					  avoid_efi_bootservices);
  if (err)
    return err;

  grub_relocator_skinit_slb = slb;

  grub_memmove (get_virtual_current_address (ch), &grub_relocator_skinit_start,
		RELOCATOR_SIZEOF (_skinit));

  err = grub_relocator_prepare_relocs (rel, get_physical_target_address (ch),
				       &relst, NULL);
  if (err)
    return err;

  asm volatile ("cli");
  ((void (*) (void)) relst) ();

  /* Not reached.  */
  return GRUB_ERR_NONE;
}
