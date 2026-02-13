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

#include <config.h>
#include <grub/symbol.h>
#include <grub/i386/crfr.h>

#define GRUB_SMX_LEAF_SENTER	4
#define CS_SEL32		0x0008
#define DS_SEL			0x0010

	.file	"x86_dltrampoline.S"
	.text

	.code64
	.globl	dl_entry_trampoline
dl_entry_trampoline:
#ifndef __x86_64__
	call	dl_enter_compat_mode

	.code32
	movl	%edi, %eax
	movl	%esi, %ecx

	/* Disable paging */
	mov	%cr0, %esi
	andl	$~GRUB_CR0_X86_PG, %esi
	movl	%esi, %cr0
#endif
	call	EXT_C(grub_slaunch_callback)
	ud2

	.globl	dl_trampoline
dl_trampoline:
#ifdef __x86_64__
	call	dl_enter_compat_mode

	.code32
	movl	%edi, %ebx
	movl	%esi, %ecx
#else
	movl	%eax, %ebx
#endif

	movl	$GRUB_SMX_LEAF_SENTER, %eax
	xorl	%edx, %edx
	getsec

	.code64
dl_enter_compat_mode:
	cli
	leaq	dl_gdt(%rip), %r8
	pushq	%r8
	pushw	$(dl_gdt_end - dl_gdt - 1)
	lgdt	(%rsp)
	addq	$10, %rsp

	movw	$DS_SEL, %r8w
	movw	%r8w, %ds
	movw	%r8w, %es
	movw	%r8w, %ss
	movw	%r8w, %fs
	movw	%r8w, %gs

	/* Setup target to ret to compat mode */
	pushq	(%rsp)
	movq	$CS_SEL32, 8(%rsp)
	lretq

	.align 8
dl_gdt:
	/* Null Segment */
	.quad	0
	/* 32b Code Segment */
	.word	0xffff /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x9b   /* P=1 DPL=0 S=1 Type=0010 C=0 W=1 A=1 */
	.byte	0xcf   /* G=1 D=1 L=0 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
	/* Data Segment, can be used both in 32b and 64b */
	.word	0xffff /* Limit 1 */
	.word	0x0000 /* Base 1 */
	.byte	0x00   /* Base 2 */
	.byte	0x93   /* P=1 DPL=0 S=1 Type=0010 C=0 W=1 A=1 */
	.byte	0xcf   /* G=1 D=1 L=0 AVL=0 Limit 2 */
	.byte	0x00   /* Base 3 */
dl_gdt_end:
