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
#include <grub/multiboot2.h>

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

/* Highest end address of any descriptor in an EFI memory map. */
grub_uint64_t
grub_skinit_efi_mmap_end (grub_addr_t map, grub_size_t map_size, grub_size_t desc_size)
{
  grub_efi_memory_descriptor_t *desc = (grub_efi_memory_descriptor_t *) map;
  grub_addr_t map_end = map + map_size;
  grub_uint64_t end = 0, desc_end;

  if (map == 0 || desc_size < sizeof (*desc))
    return 0;

  for (; (grub_addr_t) desc + desc_size <= map_end;
       desc = (grub_efi_memory_descriptor_t *) ((char *) desc + desc_size))
    {
      desc_end = desc->physical_start + (desc->num_pages << 12);
      if (desc_end > end)
        end = desc_end;
    }

  return end;
}

/*
 * Highest end address in the memory map tags of a finished Multiboot2
 * information structure. The EFI memory map tag is written after
 * ExitBootServices, so it is present on EFI and the basic map on legacy BIOS.
 */
static grub_uint64_t
mb2_mmap_end (grub_uint64_t mbi_base)
{
  grub_addr_t mbi = (grub_addr_t) mbi_base;
  grub_addr_t mbi_end;
  struct multiboot_tag *tag;
  grub_uint64_t end = 0, tag_end;

  if (mbi == 0)
    return 0;

  mbi_end = mbi + *(grub_uint32_t *) mbi;

  for (tag = (struct multiboot_tag *) (mbi + 2 * sizeof (grub_uint32_t));
       (grub_addr_t) tag + sizeof (*tag) <= mbi_end
       && tag->type != MULTIBOOT_TAG_TYPE_END;
       tag = (struct multiboot_tag *) ((grub_addr_t) tag
                                       + ALIGN_UP (tag->size, MULTIBOOT_TAG_ALIGN)))
    {
      tag_end = 0;

      if (tag->type == MULTIBOOT_TAG_TYPE_EFI_MMAP)
        {
          struct multiboot_tag_efi_mmap *efi = (struct multiboot_tag_efi_mmap *) tag;

          tag_end = grub_skinit_efi_mmap_end ((grub_addr_t) efi->efi_mmap,
                                              efi->size - sizeof (*efi),
                                              efi->descr_size);
        }
      else if (tag->type == MULTIBOOT_TAG_TYPE_MMAP)
        {
          struct multiboot_tag_mmap *mmap = (struct multiboot_tag_mmap *) tag;
          grub_addr_t entry = (grub_addr_t) mmap->entries;
          grub_addr_t entries_end = (grub_addr_t) tag + tag->size;

          if (mmap->entry_size < sizeof (struct multiboot_mmap_entry))
            continue;

          for (; entry + mmap->entry_size <= entries_end; entry += mmap->entry_size)
            {
              struct multiboot_mmap_entry *e = (struct multiboot_mmap_entry *) entry;

              if (e->addr + e->len > tag_end)
                tag_end = e->addr + e->len;
            }
        }

      if (tag_end > end)
        end = tag_end;
    }

  return end;
}

/*
 * Highest end address in the e820 table of the Linux boot params, the map a
 * legacy BIOS boot carries. The loader fills it before the DL stub runs.
 */
static grub_uint64_t
boot_params_e820_end (struct linux_kernel_params *boot_params)
{
  grub_uint64_t end = 0;
  unsigned int i;

  for (i = 0; i < boot_params->mmap_size && i < ARRAY_SIZE (boot_params->e820_map); i++)
    {
      struct grub_e820_mmap *e = &boot_params->e820_map[i];

      /* The firmware marks MMIO as reserved, so only RAM types count. */
      if (e->type != GRUB_E820_RAM && e->type != GRUB_E820_ACPI
          && e->type != GRUB_E820_NVS)
        continue;

      if (e->addr + e->size > end)
        end = e->addr + e->size;
    }

  return end;
}

/*
 * Highest end address in the memory map the Linux boot params carry: the EFI
 * memory map on an EFI boot, the e820 table on a legacy BIOS boot.
 */
static grub_uint64_t
boot_params_mmap_end (struct grub_slaunch_params *slparams)
{
  struct linux_kernel_params *boot_params = slparams->boot_params;
  struct grub_efi_info *efi_info;
  grub_uint64_t efi_memmap, hi_val, end;

  if (boot_params == NULL)
    return 0;

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

  end = grub_skinit_efi_mmap_end ((grub_addr_t) efi_memmap, efi_info->efi_mmap_size,
                                  efi_info->efi_mem_desc_size);
  if (end == 0)
    end = boot_params_e820_end (boot_params);

  return end;
}

grub_err_t
grub_skinit_psp_memory_protect (struct grub_slaunch_params *slparams)
{
  grub_uint64_t tmr_end;
  grub_err_t err;

  /*
   * The TMR has to cover every address the PSP may be asked about, the SKL
   * included, so it runs from 0 to the top of the memory map. Which map is
   * available depends on the boot path: Linux boots carry boot params, a
   * Multiboot2 boot carries a finished MBI, and a chainloaded EFI image carries
   * neither, so the top recorded before ExitBootServices is used there.
   */
  if (slparams->boot_type == GRUB_SL_BOOT_TYPE_MB2)
    tmr_end = mb2_mmap_end (slparams->boot_params_base);
  else
    tmr_end = boot_params_mmap_end (slparams);

  if (tmr_end == 0)
    tmr_end = slparams->psp_tmr_end;

  if (tmr_end == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("DRTM: no memory map to size the TMR from"));

  grub_dprintf ("slaunch", "DRTM: TMR 0x0-0x%" PRIxGRUB_UINT64_T ", SKL at 0x%"
                PRIxGRUB_UINT64_T "\n", tmr_end, slparams->dce_base);

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
  grub_addr_t icr_reg;
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
      icr_reg = apic_base + GRUB_MSR_X86_LAPIC_ICR_LO;

      grub_write32 ((GRUB_MSR_X86_ICR_DELIVER_EXCL_SELF|GRUB_MSR_X86_ICR_MODE_INIT), icr_reg);
    }

  grub_millisleep (1000);
}
