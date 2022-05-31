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
 */

#include <grub/loader.h>
#include <grub/memory.h>
#include <grub/normal.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/cpu/relocator.h>
#include <grub/i386/cpuid.h>
#include <grub/i386/msr.h>
#include <grub/i386/mmio.h>
#include <grub/i386/slaunch.h>
#include <grub/i386/txt.h>
#include <grub/acpi.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_ACPI_DRTM_SIGNATURE "DRTM"

static grub_uint32_t slp = SLP_NONE;

static void *slaunch_module = NULL;

grub_uint32_t
grub_slaunch_platform_type (void)
{
  return slp;
}

void *
grub_slaunch_module (void)
{
  return slaunch_module;
}

static grub_err_t
grub_cmd_slaunch (grub_command_t cmd __attribute__ ((unused)),
		  int argc __attribute__ ((unused)),
		  char *argv[] __attribute__ ((unused)))
{
  grub_uint32_t manufacturer[3];
  grub_uint32_t eax, ebx, ecx, edx;
  grub_uint64_t msr_value;
  grub_err_t err;

  if (!grub_cpu_is_cpuid_supported ())
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("CPUID is unsupported"));

  err = grub_cpu_is_msr_supported ();

  if (err != GRUB_ERR_NONE)
    return grub_error (err, N_("MSRs are unsupported"));

  grub_cpuid (0, eax, manufacturer[0], manufacturer[2], manufacturer[1]);

  if (!grub_memcmp (manufacturer, "GenuineIntel", 12))
    {
      err = grub_txt_init ();

      if (err != GRUB_ERR_NONE)
	return err;

      slp = SLP_INTEL_TXT;
    }
  else if (!grub_memcmp (manufacturer, "AuthenticAMD", 12))
    {

      grub_cpuid (GRUB_AMD_CPUID_FEATURES, eax, ebx, ecx, edx);
      if (! (ecx & GRUB_SVM_CPUID_FEATURE) )
        return grub_error (GRUB_ERR_BAD_DEVICE, N_("CPU does not support AMD SVM"));

      /* Check whether SVM feature is disabled in BIOS */
      msr_value = grub_rdmsr (GRUB_MSR_AMD64_VM_CR);
      if (msr_value & GRUB_MSR_SVM_VM_CR_SVM_DISABLE)
        return grub_error (GRUB_ERR_BAD_DEVICE, N_("BIOS has AMD SVM disabled"));

      slp = SLP_AMD_SKINIT;
    }
  else
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("CPU is unsupported"));

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_slaunch_module (grub_command_t cmd __attribute__ ((unused)),
			 int argc, char *argv[])
{
  grub_file_t file;
  grub_ssize_t size;

  if (!argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  if (slp == SLP_NONE)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("secure launch not enabled"));

  grub_errno = GRUB_ERR_NONE;

  file = grub_file_open (argv[0], GRUB_FILE_TYPE_SLAUNCH_MODULE);

  if (file == NULL)
    return grub_errno;

  size = grub_file_size (file);

  if (!size)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("file size is zero"));
      goto fail;
    }

  slaunch_module = grub_malloc (size);

  if (slaunch_module == NULL)
    goto fail;

  if (grub_file_read (file, slaunch_module, size) != size)
    {
      if (grub_errno == GRUB_ERR_NONE)
	grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file: %s"),
		    argv[0]);
      goto fail;
    }

  if (slp == SLP_INTEL_TXT)
    {
      if (!grub_txt_is_sinit_acmod (slaunch_module, size))
	{
	  grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("it does not look like SINIT ACM"));
	  goto fail;
	}

      if (!grub_txt_acmod_match_platform (slaunch_module))
	{
	  grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("SINIT ACM does not match platform"));
	  goto fail;
	}
    }

  grub_file_close (file);

  return GRUB_ERR_NONE;

 fail:
  grub_error_push ();

  grub_free (slaunch_module);
  grub_file_close (file);

  slaunch_module = NULL;

  grub_error_pop ();

  return grub_errno;
}

static grub_err_t
grub_cmd_slaunch_state (grub_command_t cmd __attribute__ ((unused)),
			int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
  if (slp == SLP_NONE)
    grub_printf ("Secure launcher: Disabled\n");
  else if (slp == SLP_INTEL_TXT)
    {
      grub_printf ("Secure launcher: Intel TXT\n");
      grub_txt_state_show ();
    }
  else if (slp == SLP_AMD_SKINIT)
    {
      grub_printf ("Secure launcher: AMD SKINIT\n");
    }

  return GRUB_ERR_NONE;
}

/*
 * See section 4.2.2 of TCG D-RTM Architecture Specification
 * https://trustedcomputinggroup.org/wp-content/uploads/TCG_D-RTM_Architecture_v1-0_Published_06172013.pdf
 */
struct drtm_t {
  struct grub_acpi_table_header hdr;
  grub_uint64_t DL_Entry_Base;
  grub_uint64_t DL_Entry_Length;
  grub_uint32_t DL_Entry32;
  grub_uint64_t DL_Entry64;
  grub_uint64_t DLME_Exit;
  grub_uint64_t Log_Area_Start;
  grub_uint32_t Log_Area_Length;
  grub_uint64_t Architecture_Dependent;
  grub_uint32_t DRT_Flags;
  grub_uint8_t  var_len_fields[];
} __attribute__ (( packed ));

static struct drtm_t *
search_drtm_in_rsdt (struct grub_acpi_table_header *t)
{
  grub_uint32_t len;
  grub_uint32_t *desc;

  len = t->length - sizeof (*t);
  desc = (grub_uint32_t *) (t + 1);

  for (; len >= sizeof (*desc); desc++, len -= sizeof (*desc)) {

    t = (struct grub_acpi_table_header *) (grub_addr_t) *desc;

    if (t == NULL)
      continue;

    if (grub_memcmp (t->signature, GRUB_ACPI_DRTM_SIGNATURE,
		     sizeof (t->signature)) == 0)
      return (struct drtm_t *)t;
  }

  return NULL;
}

static struct drtm_t *
search_drtm_in_xsdt (struct grub_acpi_table_header *t)
{
  grub_uint32_t len;
  grub_uint64_t *desc;

  len = t->length - sizeof (*t);
  desc = (grub_uint64_t *) (t + 1);

  for (; len >= sizeof (*desc); desc++, len -= sizeof (*desc)) {

#if GRUB_CPU_SIZEOF_VOID_P == 4
    if (*desc >= (1ULL << 32))
      {
	grub_printf ("Unreachable table\n");
	continue;
      }
#endif

    t = (struct grub_acpi_table_header *) (grub_addr_t) *desc;

    if (t == NULL)
      continue;

    if (grub_memcmp (t->signature, GRUB_ACPI_DRTM_SIGNATURE,
		     sizeof (t->signature)) == 0)
      return (struct drtm_t *)t;
  }

  return NULL;
}

static struct drtm_t *
get_drtm_acpi_table (void)
{
  struct drtm_t *drtm = NULL;
  struct grub_acpi_rsdp_v10 *rsdp1 = grub_acpi_get_rsdpv1();

  if (rsdp1)
    drtm = search_drtm_in_rsdt ((void *) (grub_addr_t) rsdp1->rsdt_addr);

  if (!drtm) {
    struct grub_acpi_rsdp_v20 *rsdp2 = grub_acpi_get_rsdpv2 ();
    if (!rsdp2)
      grub_dprintf ("slaunch", "No RSDP\n");
    else
      drtm = search_drtm_in_xsdt ((void *) (grub_addr_t) rsdp2->xsdt_addr);
  }

  return drtm;
}

void grub_get_drtm_evt_log (struct grub_slaunch_params *slparams)
{
  struct drtm_t *drtm = get_drtm_acpi_table ();

  slparams->tpm_evt_log_base = 0;
  slparams->tpm_evt_log_size = 0;

  if (drtm != NULL)
  {
    slparams->tpm_evt_log_base = drtm->Log_Area_Start;
    slparams->tpm_evt_log_size = drtm->Log_Area_Length;

    grub_memset ((void *)(grub_addr_t)drtm->Log_Area_Start, 0, drtm->Log_Area_Length);
  }
}

static grub_command_t cmd_slaunch, cmd_slaunch_module, cmd_slaunch_state;

GRUB_MOD_INIT (slaunch)
{
  cmd_slaunch = grub_register_command ("slaunch", grub_cmd_slaunch,
				       NULL, N_("Enable secure launcher"));
  cmd_slaunch_module = grub_register_command ("slaunch_module", grub_cmd_slaunch_module,
					      NULL, N_("Secure launcher module command"));
  cmd_slaunch_state = grub_register_command ("slaunch_state", grub_cmd_slaunch_state,
					     NULL, N_("Display secure launcher state"));
}

GRUB_MOD_FINI (slaunch)
{
  grub_unregister_command (cmd_slaunch_state);
  grub_unregister_command (cmd_slaunch_module);
  grub_unregister_command (cmd_slaunch);

  if (slp == SLP_INTEL_TXT)
    grub_txt_shutdown ();
}
