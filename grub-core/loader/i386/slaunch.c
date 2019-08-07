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

GRUB_MOD_LICENSE ("GPLv3+");

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
  grub_uint32_t eax;
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

  return GRUB_ERR_NONE;
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
