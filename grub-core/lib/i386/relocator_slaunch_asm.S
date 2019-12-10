/*
 *  GRUB  --  GRand Unified Bootloader
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

/*
 * skinit resets the CPU state. Assuming we are already in protected mode
 * (doesn't matter if it is legacy, compatibility or long mode) with CPL=0,
 * there is no additional setup to be done.
 */

#include <grub/symbol.h>

	.p2align	4	/* force 16-byte alignment */

VARIABLE(grub_relocator_skinit_start)

	/* mov imm32, %eax */
	.byte	0xb8
VARIABLE(grub_relocator_skinit_slb)
	.long	0

	skinit
VARIABLE(grub_relocator_skinit_end)
