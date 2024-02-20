/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2019  Free Software Foundation, Inc.
 *
 *  Some definitions in this header are extracted from the Trusted Computing
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
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_I386_MSR_H
#define GRUB_I386_MSR_H 1

/* General */
#define GRUB_MSR_X86_PLATFORM_ID	0x00000017

#define GRUB_MSR_X86_APICBASE		0x0000001b
#define GRUB_MSR_X86_APICBASE_BSP	(1<<8)
#define GRUB_MSR_X86_APICBASE_ENABLE	(1<<11)
#define GRUB_MSR_X86_APICBASE_BASE	(0xfffff<<12) /* Mask for APIC base address */

#define GRUB_MSR_X86_FEATURE_CONTROL	0x0000003a
#define GRUB_MSR_X86_FEATURE_CTRL_LOCK	(1<<0)     /* Lock writes to this register */
#define GRUB_MSR_X86_ENABLE_VMX_IN_SMX	(1<<1)     /* Enable VMX inside SMX */
#define GRUB_MSR_X86_ENABLE_VMX_OUT_SMX	(1<<2)     /* Enable VMX outside SMX */
#define GRUB_MSR_X86_SENTER_FUNCTIONS	(0x7f<<8)  /* Bitmap of SENTER function enables */
#define GRUB_MSR_X86_SENTER_ENABLE	(1<<15)    /* SENTER global enable */

#define GRUB_MSR_X86_MTRRCAP		0x000000fe
#define GRUB_MSR_X86_VCNT_MASK		0xff       /* Number of variable MTRRs */

#define GRUB_MSR_X86_MCG_CAP		0x00000179
#define GRUB_MSR_MCG_BANKCNT_MASK	0xff       /* Number of banks */
#define GRUB_MSR_X86_MCG_STATUS		0x0000017a
#define GRUB_MSR_MCG_STATUS_MCIP	(1ULL<<2)  /* MC in progress */

#define GRUB_MSR_X86_MISC_ENABLE	0x000001a0
#define GRUB_MSR_X86_ENABLE_MONITOR_FSM	(1<<18)

#define GRUB_MSR_X86_MTRR_PHYSBASE0	0x00000200
#define GRUB_MSR_X86_MTRR_PHYSMASK0	0x00000201
#define GRUB_MSR_X86_MTRR_PHYSBASE(n)	(GRUB_MSR_X86_MTRR_PHYSBASE0 + 2 * (n))
#define GRUB_MSR_X86_MTRR_PHYSMASK(n)	(GRUB_MSR_X86_MTRR_PHYSMASK0 + 2 * (n))
#define GRUB_MSR_X86_BASE_DEF_TYPE_MASK	0xff
#define GRUB_MSR_X86_MASK_VALID		(1<<11)

#define GRUB_MSR_X86_MTRR_DEF_TYPE	0x000002ff
#define GRUB_MSR_X86_DEF_TYPE_MASK	0xff
#define GRUB_MSR_X86_MTRR_ENABLE_FIXED	(1<<10)
#define GRUB_MSR_X86_MTRR_ENABLE	(1<<11)

#define GRUB_MSR_X86_MC0_STATUS		0x00000401

#define GRUB_MSR_X86_EFER		0xc0000080 /* Extended features */
#define GRUB_MSR_EFER_LME		(1<<8)     /* Enable Long Mode/IA-32e */
#define GRUB_MSR_EFER_LMA		(1<<10)    /* Long Mode/IA-32e Active */
#define GRUB_MSR_EFER_SVME		(1<<12)    /* Enable SVM (AMD-V) */

/* AMD Specific */
#define GRUB_MSR_AMD64_VM_CR		0xc0010114 /* SVM control register */
#define GRUB_MSR_SVM_VM_CR_SVM_DISABLE	(1<<4)     /* Disable writes to EFER.SVME */

/* MTRR Specific */
#define GRUB_MTRR_MEMORY_TYPE_UC	0
#define GRUB_MTRR_MEMORY_TYPE_WC	1
#define GRUB_MTRR_MEMORY_TYPE_WT	4
#define GRUB_MTRR_MEMORY_TYPE_WP	5
#define GRUB_MTRR_MEMORY_TYPE_WB	6

#ifndef ASM_FILE

#include <grub/err.h>
#include <grub/i386/cpuid.h>
#include <grub/types.h>

static inline grub_err_t
grub_cpu_is_msr_supported (void)
{
  grub_uint32_t eax, ebx, ecx, edx;

  /*
   * The CPUID instruction should be used to determine whether MSRs
   * are supported, CPUID.01H:EDX[5] = 1.
   */
  if (!grub_cpu_is_cpuid_supported ())
    return GRUB_ERR_BAD_DEVICE;

  grub_cpuid (0, eax, ebx, ecx, edx);

  if (eax < 1)
    return GRUB_ERR_BAD_DEVICE;

  grub_cpuid (1, eax, ebx, ecx, edx);

  if (!(edx & (1 << 5)))
    return GRUB_ERR_BAD_DEVICE;

  return GRUB_ERR_NONE;
}

/*
 * TODO: Add a general protection exception handler.
 *       Accessing a reserved or unimplemented MSR address results in a GP#.
 */

static inline grub_uint64_t
grub_rdmsr (grub_uint32_t msr_id)
{
  grub_uint32_t low, high;

  asm volatile ("rdmsr" : "=a" (low), "=d" (high) : "c" (msr_id));

  return ((grub_uint64_t) high << 32) | low;
}

static inline void
grub_wrmsr (grub_uint32_t msr_id, grub_uint64_t msr_value)
{
  grub_uint32_t low = msr_value, high = msr_value >> 32;

  asm volatile ("wrmsr" : : "c" (msr_id), "a" (low), "d" (high));
}

#endif /* ASM_FILE */

#endif /* GRUB_I386_MSR_H */
