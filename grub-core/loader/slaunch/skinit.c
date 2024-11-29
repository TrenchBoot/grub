/*
 * Copyright (c) 2024, Oracle and/or its affiliates.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <grub/loader.h>
#include <grub/memory.h>
#include <grub/normal.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/time.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/slr_table.h>
#include <grub/slaunch.h>
#include <grub/efi/efi.h>
#include <grub/i386/msr.h>
#include <grub/i386/mmio.h>
#include <grub/i386/crfr.h>
#include <grub/i386/linux.h>
#include <grub/i386/psp.h>
#include <grub/i386/skinit.h>

grub_err_t
grub_skinit_is_supported (void)
{
  grub_uint32_t eax, ebx, ecx, edx;

  grub_cpuid (GRUB_AMD_CPUID_FEATURES, eax, ebx, ecx, edx);

  if (ecx & GRUB_SKINIT_CPUID_FEATURE)
    {
      grub_dprintf ("slaunch", "SKINIT CPU and all needed capabilities present\n");
      return GRUB_ERR_NONE;
    }
  return grub_error (GRUB_ERR_BAD_DEVICE, N_("CPU does not support SKINIT"));
}

grub_err_t
grub_skinit_prepare_cpu (void)
{
  unsigned long eflags, cr0;
  grub_uint64_t mcg_cap, mcg_stat;
  grub_uint32_t i;

  cr0 = grub_read_control_register (GRUB_CR0);

  /* Cache must be enabled (CR0.CD = CR0.NW = 0). */
  if (!(cr0 & GRUB_CR0_X86_CD))
    cr0 &= ~GRUB_CR0_X86_CD;
  if (cr0 & GRUB_CR0_X86_NW)
    cr0 &= ~GRUB_CR0_X86_NW;

  /*
   * Native FPU error reporting must be enable for proper
   * iteraction behavior
   */
  if (!(cr0 & GRUB_CR0_X86_NE))
    cr0 |= GRUB_CR0_X86_NE;

  grub_write_control_register (GRUB_CR0, cr0);

  /* Cannot be in virtual-8086 mode (EFLAGS.VM=0) */
  eflags = grub_read_flags_register ();
  if (eflags & GRUB_EFLAGS_X86_VM)
    grub_write_flags_register (eflags & ~GRUB_EFLAGS_X86_VM);

  /*
   * Verify all machine check status registers are clear (unless
   * support preserving them)
   */

  /* No machine check in progress (IA32_MCG_STATUS.MCIP=1) */
  mcg_stat = grub_rdmsr (GRUB_MSR_X86_MCG_STATUS);
  if (mcg_stat & 0x04)
    return -1;

  /* Check if all machine check regs are clear */
  mcg_cap = grub_rdmsr (GRUB_MSR_X86_MCG_CAP);
  for (i = 0; i < (mcg_cap & GRUB_MSR_MCG_BANKCNT_MASK); i++)
    {
      mcg_stat = grub_rdmsr (GRUB_MSR_X86_MC0_STATUS + i * 4);
      if (mcg_stat & (1ULL << 63))
        return grub_error (GRUB_ERR_BAD_DEVICE, N_("secure launch MCG[%u] = %llx ERROR"),
                           i, (unsigned long long)mcg_stat);
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_skinit_psp_memory_protect (struct grub_slaunch_params *slparams)
{
  struct linux_kernel_params *boot_params = slparams->boot_params;
  grub_efi_memory_descriptor_t *memory_map_end;
  grub_efi_memory_descriptor_t *desc;
  struct grub_efi_info *efi_info;
  grub_uint64_t efi_memmap, hi_val, tmr_end = 0;
  grub_err_t err;

  /* A bit of work to extract the v2.08 EFI info from the linux params */
  efi_info = (struct grub_efi_info *)((grub_uint8_t *)&(boot_params->v0208)
                                      + 2*sizeof(grub_uint32_t));

  if (slparams->boot_type == GRUB_SL_BOOT_TYPE_EFI)
    {
      /*
       * On EFI stub boots, the EFI memory map is fetched from the stub code so it
       * needs to be gotten from the boot params on re-entry to the DL stub. The EFI
       * info in boot params has physical addresses but everything is identity mapped.
       */
      efi_memmap = efi_info->efi_mmap;
      hi_val = efi_info->efi_mmap_hi;
      efi_memmap |= (hi_val << 32);
    }
  else
    {
      /*
       * On legacy Linux boots, the relocator is used to map the EFI memory map buffer
       * and return a virtual address to use. This virtual address is stashed in slparams.
       */
      efi_memmap = (grub_uint64_t)(grub_addr_t)slparams->efi_memmap_mem;
    }

  desc = (grub_efi_memory_descriptor_t *)(grub_addr_t) efi_memmap;
  memory_map_end = (grub_efi_memory_descriptor_t *)(grub_addr_t) (efi_memmap + efi_info->efi_mmap_size);
  for (; desc < memory_map_end; desc = (grub_efi_memory_descriptor_t *) ((char *) desc + efi_info->efi_mem_desc_size))
    {
      tmr_end = desc->physical_start + (desc->num_pages << 12);
    }

  grub_drtm_kick_psp ();

  err = grub_drtm_get_capability ();
  if (err != GRUB_ERR_NONE)
    return err;

  err = grub_drtm_setup_tmrs (tmr_end);
  if ( err != GRUB_ERR_NONE)
    return err;

  return GRUB_ERR_NONE;
}

/* Broadcast INIT to all APs except self */
void
grub_skinit_send_init_ipi_shorthand (void)
{
  grub_uint32_t *icr_reg;
  grub_uint32_t apic_base = (grub_uint32_t) grub_rdmsr (GRUB_MSR_X86_APICBASE);

  /* accessing the ICR depends on the APIC mode */
  if (apic_base & GRUB_MSR_X86_X2APICBASE_ENABLE)
    {
      grub_mb ();

      /* access ICR through MSR */
      grub_wrmsr (GRUB_MSR_X86_X2APICBASE_ICR, (GRUB_MSR_X86_ICR_DELIVER_EXCL_SELF|GRUB_MSR_X86_ICR_MODE_INIT));
    }
  else
    {
      /* mask off low order bits to get base address */
      apic_base &= GRUB_MSR_X86_APICBASE_BASE;
      /* access ICR through MMIO */
      icr_reg = (grub_uint32_t *)(grub_addr_t)(apic_base + GRUB_MSR_X86_LAPIC_ICR_LO);

      grub_writel ((GRUB_MSR_X86_ICR_DELIVER_EXCL_SELF|GRUB_MSR_X86_ICR_MODE_INIT), icr_reg);
    }

  grub_millisleep (1000);
}
