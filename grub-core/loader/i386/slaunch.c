#include <grub/loader.h>
#include <grub/memory.h>
#include <grub/normal.h>
#include <grub/file.h>
#include <grub/disk.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/acpi.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/command.h>
#include <grub/i386/relocator.h>
#include <grub/i386/cpuid.h>
#include <grub/lib/cmdline.h>

#include "msr-index.h"


static grub_dl_t my_mod;
static struct grub_relocator *rel;
static grub_addr_t slb;

#define TARGET_ADDRESS 0x1000000

struct cpu {
  grub_uint32_t lapic_id;
  grub_uint32_t lapic_ver;
  grub_uint32_t lapic_base;
  grub_uint32_t isbsp;
} __attribute__((packed));

#define SIZE_STRUCT_CPU  (sizeof(struct cpu))

static grub_uint64_t
rdmsr(grub_uint32_t msr)
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

static void
wrmsr(grub_uint32_t msr, grub_uint64_t val)
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

/* AMD-specific microcode patch clear */
#define MSR_AMD64_PATCH_CLEAR 0xc0010021

/* CPUs must all have their microcode cleared for SKINIT to be successful */
static void
amd_clear_microcode(struct cpu *cpu)
{
  grub_uint32_t ucode_rev;
  grub_uint64_t zero = 0;

  // Current microcode patch level available via MSR read
  ucode_rev = rdmsr(MSR_AMD64_PATCH_LEVEL) & 0xFFFFFFFFLL;
  grub_printf("\nCPU(0x%02x): existing microcode version 0x%08x", cpu->lapic_id, ucode_rev);

  if(ucode_rev != 0)
    {
      wrmsr(MSR_AMD64_PATCH_CLEAR, zero);
      grub_printf("\nCPU(0x%02x): microcode CLEARED", cpu->lapic_id);
    }
}

static grub_uint32_t
scan_cpus(struct cpu *cpus, grub_uint32_t *n_cpu) 
{
  grub_uint32_t ret = 0;
  struct grub_acpi_rsdp_v10 *rsdp1 = grub_machine_acpi_get_rsdpv1();
  if (!rsdp1)
    {
      grub_printf ("no rsdpv1\n");
    }
  else
    {
      struct grub_acpi_table_header *rsdt;
      grub_uint32_t len, *entry_ptr;

      rsdt = (struct grub_acpi_table_header *) (grub_addr_t) rsdp1->rsdt_addr;
      for (entry_ptr = (grub_uint32_t *) (rsdt + 1);
           entry_ptr < (grub_uint32_t *) (((grub_uint8_t *) rsdt)
                                          + rsdt->length);
           entry_ptr++)
        {
          if (grub_memcmp ((void *) (grub_addr_t) *entry_ptr, "APIC", 4) == 0)
            {
              struct grub_acpi_madt *t
                = ((struct grub_acpi_madt *) (grub_addr_t) *entry_ptr);
              struct grub_acpi_madt_entry_header *d;

              *n_cpu = 0;

              len = t->hdr.length - sizeof (struct grub_acpi_madt);
              d = t->entries;
              for (;len > 0; len -= d->len,
                    d = (void *) ((grub_uint8_t *) d + d->len))
                {
                  if (d->type == GRUB_ACPI_MADT_ENTRY_TYPE_LAPIC)
                    {
                      struct grub_acpi_madt_entry_lapic *e;
                      int i = *n_cpu;

                      e = (struct grub_acpi_madt_entry_lapic *) d;

                      cpus[i].lapic_id = e->apicid;
                      cpus[i].lapic_ver = 0;
                      cpus[i].lapic_base = t->lapic_addr;

                      if(i == 0)
                        {
                          /* ACPI spec says that first processor entry MUST be BSP */
                          cpus[i].isbsp = 1;
                          /* Found at least the BSP, able to return success */
                          ret = 1;
                        }
                      else
                        {
                          cpus[i].isbsp = 0;
                        }
    
                      *n_cpu += 1;
                    }
                }
            }
        }
    }

  return ret;
}

static grub_err_t
prepare_tpm(void)
{
  int l, rc;

  rc = grub_tpm_open();
  if (rc != GRUB_ERR_NONE)
    return rc;

  for (l=0; l <= 5; l++)
    grub_tpm_release_locality(l);

  return GRUB_ERR_NONE;
}

/*processor*/
#define SVM_CPUID_FUNC 0x8000000a

#define SVM_CPUID_FEATURE       (1 << 2)

/*msr*/
#define SVM_VM_CR_SVM_DISABLE 4

/* MCG_CAP register defines */
#define MCG_BANKCNT_MASK  0xff         /* Number of Banks */

/* MCG_STATUS register defines */
#define MCG_STATUS_MCIP  (1ULL<<2)   /* machine check in progress */



static grub_err_t
amd_prepare_cpu(void)
{
  grub_uint64_t mcg_cap, mcg_stat;
  grub_uint64_t apicbase;
  grub_uint32_t i, bound;


  /* make sure the APIC is enabled */
  apicbase = rdmsr(MSR_IA32_APICBASE);
  if (!(apicbase & MSR_IA32_APICBASE_ENABLE))
    return grub_error(GRUB_ERR_BAD_DEVICE, "APIC disabled");

  /* no machine check in progress */
  mcg_stat = rdmsr(MSR_IA32_MCG_STATUS);
  if (mcg_stat & MCG_STATUS_MCIP)
    return grub_error(GRUB_ERR_BAD_DEVICE, "machine check in progress");

  /* all machine check regs are clear */
  mcg_cap = rdmsr(MSR_IA32_MCG_CAP);
  bound = (grub_uint32_t)mcg_cap & MCG_BANKCNT_MASK;
  for (i = 0; i < bound; i++)
    {
      mcg_stat = rdmsr(MSR_IA32_MC0_STATUS + 4*i);
      if (mcg_stat & (1ULL << 63))
        return grub_error(GRUB_ERR_BAD_DEVICE, "machine check reg %d not clear");
    }

  /* clear microcode on all the APs handled in mp_cstartup() */
  /* put all APs in INIT handled in do_drtm() */

  return GRUB_ERR_NONE;
}

static grub_err_t
amd_prepare_platform(void)
{   
  grub_uint32_t eax, edx, ebx, ecx;
  grub_uint64_t msr_value;

  grub_cpuid(0x80000001, eax, ebx, ecx, edx);

  if ((ecx & SVM_CPUID_FEATURE) == 0)
    return grub_error(GRUB_ERR_BAD_DEVICE, "CPU does not support AMD SVM");

  /* Check whether SVM feature is disabled in BIOS */
  msr_value = rdmsr(MSR_VM_CR); 
  if (msr_value & SVM_VM_CR_SVM_DISABLE)
    return grub_error(GRUB_ERR_BAD_DEVICE, "BIOS has AMD SVM disabled");

  /* Turn on SVM */
  msr_value = rdmsr(MSR_EFER);
  wrmsr(MSR_EFER, msr_value | EFER_SVME);
  msr_value = rdmsr(MSR_EFER);
  if ((msr_value & EFER_SVME) == 0)
    return grub_error(GRUB_ERR_BAD_DEVICE, "Could not enalbe AMD SVM");

  grub_cpuid(SVM_CPUID_FUNC, eax, ebx, ecx, edx); 
  grub_printf("AMD SVM version %d enabled\n", eax & 0xff);

  return amd_prepare_cpu();
}

static grub_err_t
grub_slaunch_boot (void)
{
  struct grub_relocator32_state state;
  struct cpu cpus[8]; /* demo is only quad core */
  grub_uint32_t cpu_count;

  scan_cpus(&cpus[0], &cpu_count);
  amd_clear_microcode(&cpus[0]);

  prepare_tpm();

  amd_prepare_platform();

  state.eax = slb;
  return grub_relocatorSVM_boot (rel, state, 0);
}

static grub_err_t
grub_slaunch_unload (void)
{
    grub_relocator_unload (rel);
    rel = NULL;
    grub_dl_unref (my_mod);
    return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_slaunch (grub_command_t cmd __attribute__ ((unused)),
                int argc, char *argv[])
{
  grub_file_t file = 0;
  grub_err_t err;
  void  *kernel;
  grub_size_t kernelsize;

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  grub_dl_ref (my_mod);

  rel = grub_relocator_new ();
  if (!rel)
    goto fail;

  file = grub_file_open (argv[0]);
  if (! file)
    goto fail;

  kernelsize = grub_file_size (file);

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_addr (rel, &ch, TARGET_ADDRESS,
                                           kernelsize);
    if (err)
      goto fail;
    kernel = get_virtual_current_address (ch);
    slb = get_physical_target_address (ch);
  }

  if (grub_file_read (file, kernel, kernelsize) != (grub_ssize_t) kernelsize)
    goto fail;

  grub_loader_set (grub_slaunch_boot, grub_slaunch_unload, 0);
  return GRUB_ERR_NONE;

 fail:

  if (file)
    grub_file_close (file);

  grub_slaunch_unload ();

  return grub_errno;
}


static grub_command_t cmd;

GRUB_MOD_INIT(slaunch)
{ 
    cmd = grub_register_command ("slaunch", grub_cmd_slaunch,
                                       0, N_("Launch Secure Loader"));
      my_mod = mod;
}

GRUB_MOD_FINI(slaunch)
{       
    grub_unregister_command (cmd); 
}   

GRUB_MOD_LICENSE("GPLv2+");
