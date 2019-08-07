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
 *  along with GRUB.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GRUB_CRFR_H
#define GRUB_CRFR_H 1

#include <grub/types.h>

/* Routines for R/W of control and flags registers */

#define GRUB_CR0_X86_PE		0x00000001 /* Enable Protected Mode */
#define GRUB_CR0_X86_MP		0x00000002 /* "Math" (FPU) Present */
#define GRUB_CR0_X86_EM		0x00000004 /* EMulate FPU */
#define GRUB_CR0_X86_TS		0x00000008 /* Task Switched */
#define GRUB_CR0_X86_PG		0x80000000 /* Enable PaGing */

#define GRUB_CR0_X86_NE		0x00000020 /* Numeric Error enable (EX16 vs IRQ13) */
#define GRUB_CR0_X86_WP		0x00010000 /* Write Protect */
#define GRUB_CR0_X86_AM		0x00040000 /* Alignment Mask */
#define GRUB_CR0_X86_NW		0x20000000 /* Not Write-through */
#define GRUB_CR0_X86_CD		0x40000000 /* Cache Disable */

#define GRUB_CR4_X86_VME	0x00000001 /* Virtual 8086 mode extensions */
#define GRUB_CR4_X86_PVI	0x00000002 /* Protected-mode virtual interrupts */
#define GRUB_CR4_X86_TSD	0x00000004 /* Time stamp disable */
#define GRUB_CR4_X86_DE		0x00000008 /* Debugging extensions */
#define GRUB_CR4_X86_PSE	0x00000010 /* Page size extensions */
#define GRUB_CR4_X86_PAE	0x00000020 /* Physical address extension */
#define GRUB_CR4_X86_MCE	0x00000040 /* Enable Machine check enable */
#define GRUB_CR4_X86_PGE	0x00000080 /* Enable Page global */
#define GRUB_CR4_X86_PCE	0x00000100 /* Enable Performance monitoring counter */
#define GRUB_CR4_X86_FXSR	0x00000200 /* Fast FPU save/restore */
#define GRUB_CR4_X86_XMM	0x00000400 /* Generate #XM instead of #UD for SIMD */
#define GRUB_CR4_X86_VMXE	0x00002000 /* Enable VMX */
#define GRUB_CR4_X86_SMXE	0x00004000 /* Enable SMX */
#define GRUB_CR4_X86_PCIDE	0x00020000 /* Enable PCID */

static inline unsigned long
grub_read_cr0 (void)
{
  unsigned long val;

  asm volatile ("mov %%cr0, %0" : "=r" (val) : : "memory");

  return val;
}

static inline void
grub_write_cr0 (unsigned long val)
{
  asm volatile ("mov %0, %%cr0" : : "r" (val) : "memory");
}

static inline unsigned long
grub_read_cr4 (void)
{
  unsigned long val;

  asm volatile ("mov %%cr4, %0" : "=r" (val) : : "memory");

  return val;
}

static inline void
grub_write_cr4 (unsigned long val)
{
  asm volatile ("mov %0, %%cr4" : : "r" (val) : "memory");
}

#define GRUB_EFLAGS_X86_CF	0x00000001 /* Carry Flag */
#define GRUB_EFLAGS_X86_PF	0x00000004 /* Parity Flag */
#define GRUB_EFLAGS_X86_AF	0x00000010 /* Auxillary carry Flag */
#define GRUB_EFLAGS_X86_ZF	0x00000040 /* Zero Flag */
#define GRUB_EFLAGS_X86_SF	0x00000080 /* Sign Flag */
#define GRUB_EFLAGS_X86_TF	0x00000100 /* Trap Flag */
#define GRUB_EFLAGS_X86_IF	0x00000200 /* Interrupt Flag */
#define GRUB_EFLAGS_X86_DF	0x00000400 /* Direction Flag */
#define GRUB_EFLAGS_X86_OF	0x00000800 /* Overflow Flag */
#define GRUB_EFLAGS_X86_IOPL	0x00003000 /* IOPL mask */
#define GRUB_EFLAGS_X86_NT	0x00004000 /* Nested Task */
#define GRUB_EFLAGS_X86_RF	0x00010000 /* Resume Flag */
#define GRUB_EFLAGS_X86_VM	0x00020000 /* Virtual Mode */
#define GRUB_EFLAGS_X86_AC	0x00040000 /* Alignment Check */
#define GRUB_EFLAGS_X86_VIF	0x00080000 /* Virtual Interrupt Flag */
#define GRUB_EFLAGS_X86_VIP	0x00100000 /* Virtual Interrupt Pending */
#define GRUB_EFLAGS_X86_ID	0x00200000 /* CPUID detection flag */

static inline unsigned long
grub_read_flags_register (void)
{
  unsigned long flags;

#ifdef __x86_64__
  asm volatile ("pushfq; popq %0" : "=r" (flags));
#else
  asm volatile ("pushfl; popl %0" : "=r" (flags));
#endif

  return flags;
}

static inline void
grub_write_flags_register (unsigned long flags)
{
#ifdef __x86_64__
  asm volatile ("pushq %0; popfq" : : "r" (flags));
#else
  asm volatile ("pushl %0; popfl" : : "r" (flags));
#endif
}

#endif
