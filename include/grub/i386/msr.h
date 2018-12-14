/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 *  The definitions in this header are extracted from the Trusted Computing
 *  Group's "TPM Main Specification", Parts 1-3.
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

#ifndef GRUB_X86_MSR_H
#define GRUB_X86_MSR_H 1

/* General */

#define GRUB_MSR_X86_APICBASE		0x0000001b
#define GRUB_MSR_X86_APICBASE_BSP	(1<<8)
#define GRUB_MSR_X86_APICBASE_ENABLE	(1<<11)
#define GRUB_MSR_X86_APICBASE_BASE	(0xfffff<<12)

#define GRUB_MSR_X86_FEATURE_CONTROL	0x0000003a
#define GRUB_MSR_X86_ENABLE_VMX_IN_SMX	(1<<1)

#define GRUB_MSR_X86_MCG_CAP		0x00000179
#define GRUB_MSR_MCG_BANKCNT_MASK	0xff      /* Number of banks  */
#define GRUB_MSR_X86_MCG_STATUS		0x0000017a
#define GRUB_MSR_MCG_STATUS_MCIP	(1ULL<<2) /* MC in progress  */

#define GRUB_MSR_X86_MC0_STATUS		0x00000401

#define GRUB_MSR_X86_EFER		0xc0000080 /* Extended features  */
#define GRUB_MSR_EFER_SVME		(1<<12)    /* Enable virtualization  */

/* AMD Specific */

#define GRUB_MSR_AMD64_PATCH_LEVEL	0x0000008b
#define GRUB_MSR_AMD64_PATCH_CLEAR	0xc0010021 /* AMD-specific microcode
						      patch clear  */
#define GRUB_MSR_AMD64_VM_CR		0xc0010114
#define GRUB_MSR_SVM_VM_CR_SVM_DISABLE	4

static inline grub_uint64_t
grub_rdmsr(grub_uint32_t msr)
{
  grub_uint64_t val = 0;

#ifdef __x86_64__
  asm volatile("rdmsr" : "=A" (val) : "c" (msr));
#else
  grub_uint32_t low, high;
  asm volatile("rdmsr"  : "=a" (low), "=d" (high) : "c" (msr));
  val = ((low) | (grub_uint64_t)(high) << 32);
#endif

  return val;
}

static inline void
grub_wrmsr(grub_uint32_t msr, grub_uint64_t val)
{
#ifdef __x86_64__
  asm volatile("wrmsr" : "=A" (val) : "c" (msr));
#else
  grub_uint32_t low, high;
  high = (grub_uint32_t) ((val & 0xFFFFFFFF00000000LL) >> 32);
  low = (grub_uint32_t) (val & 0xFFFFFFFFLL);
  asm volatile("wrmsr"  : "=a" (low), "=d" (high) : "c" (msr));
#endif
}

#endif
