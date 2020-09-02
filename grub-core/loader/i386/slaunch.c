/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
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
#include <grub/slaunch.h>

GRUB_MOD_LICENSE("GPLv3+");

static grub_dl_t my_mod;
static struct grub_slaunch_module *modules = NULL, *modules_last = NULL;
static struct grub_relocator *relocator = NULL;

struct grub_slaunch_module*
grub_slaunch_get_modules( void)
{
  return modules;
}

static grub_err_t
grub_slaunch_add_module (void *addr, grub_addr_t target, grub_size_t size)
{
  struct grub_slaunch_module *newmod;

  newmod = grub_malloc (sizeof (*newmod));
  if (!newmod)
    return grub_errno;
  newmod->addr = (grub_uint8_t*)addr;
  newmod->target = target;
  newmod->size = size;
  newmod->next = 0;

  if (modules_last)
    modules_last->next = newmod;
  else
    modules = newmod;
  modules_last = newmod;

  return GRUB_ERR_NONE;
}

static void
grub_slaunch_free (void)
{
  struct grub_slaunch_module *cur, *next;

  for (cur = modules; cur; cur = next)
    {
      next = cur->next;
      grub_free (cur);
    }
  modules = NULL;
  modules_last = NULL;

  grub_relocator_unload (relocator);
  relocator = NULL;
}

static grub_err_t
grub_cmd_slaunch (grub_command_t cmd __attribute__ ((unused)),
                int argc, char *argv[])
{
  grub_uint32_t manufacturer[3];
  grub_uint32_t eax, edx, ebx, ecx;
  grub_uint64_t msr_value;

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("argument expected"));

  /* Should be executing on the BSP  */
  msr_value = grub_rdmsr (GRUB_MSR_X86_APICBASE);
  if (! (msr_value & GRUB_MSR_X86_APICBASE_BSP))
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("secure launch must run on BSP"));

  if (! grub_cpu_is_cpuid_supported ())
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("CPUID not supported"));

  grub_cpuid (0, eax, manufacturer[0], manufacturer[2], manufacturer[1]);

  if (grub_memcmp (argv[0], "txt", 3) == 0)
    {
      if (grub_memcmp (manufacturer, "GenuineIntel", 12) != 0)
        return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Intel platform required for TXT"));

      grub_cpuid(GRUB_X86_CPUID_FEATURES, eax, ebx, ecx, edx);
      if (! (ecx & GRUB_VMX_CPUID_FEATURE) || ! (ecx & GRUB_SMX_CPUID_FEATURE) )
        return grub_error (GRUB_ERR_BAD_DEVICE,
			   N_("CPU does not support Intel TXT"));

      msr_value = grub_rdmsr (GRUB_MSR_X86_FEATURE_CONTROL);
      if (! (msr_value & GRUB_MSR_X86_ENABLE_VMX_IN_SMX))
        return grub_error (GRUB_ERR_BAD_DEVICE,
			   N_("Intel TXT is not enabled"));

      grub_linux_slaunch_set (grub_slaunch_boot_txt);
    }
  else if (grub_memcmp (argv[0], "skinit", 6) == 0)
    {
      grub_dprintf ("slaunch", "check for manufacturer\r\n");
      if (grub_memcmp (manufacturer, "AuthenticAMD", 12) != 0)
        return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("AMD platform required for SKINIT"));

      grub_dprintf ("slaunch", "check for cpuid\r\n");
      grub_cpuid (GRUB_AMD_CPUID_FEATURES, eax, ebx, ecx, edx);
      if (! (ecx & GRUB_SVM_CPUID_FEATURE) )
        return grub_error (GRUB_ERR_BAD_DEVICE, N_("CPU does not support AMD SVM"));

      /* Check whether SVM feature is disabled in BIOS */
      msr_value = grub_rdmsr (GRUB_MSR_AMD64_VM_CR);
      if (msr_value & GRUB_MSR_SVM_VM_CR_SVM_DISABLE)
        return grub_error (GRUB_ERR_BAD_DEVICE, "BIOS has AMD SVM disabled");

      grub_dprintf ("slaunch", "set slaunch\r\n");
      grub_linux_slaunch_set (grub_slaunch_boot_skinit);
    }
  else
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("invalid argument"));

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_slaunch_module (grub_command_t cmd __attribute__ ((unused)),
                int argc, char *argv[])
{
  grub_file_t file;
  grub_ssize_t size;
  grub_err_t err;
  grub_relocator_chunk_t ch;
  void *addr = NULL;
  grub_addr_t target;

  grub_dprintf ("slaunch", "check argc\r\n");

  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  grub_dprintf ("slaunch", "check relocator\r\n");

  if (! relocator)
    {
      relocator = grub_relocator_new ();
      if (! relocator)
        return grub_errno;
    }

  grub_dprintf ("slaunch", "open slaunch module file\r\n");
  file = grub_file_open (argv[0], GRUB_FILE_TYPE_SLAUNCH_MODULE);
  if (! file)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("slaunch module file is missing"));

  grub_dprintf ("slaunch", "get slaunch module size\r\n");
  size = grub_file_size (file);
  if (size == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("file size is zero"));

  grub_dprintf ("slaunch", "allocate memory\r\n");
  err = grub_relocator_alloc_chunk_align (relocator, &ch,
					  0, (0xffffffff - size) + 1,
					  size > 0x10000 ? size : 0x10000, /* Alloc at least 64k */
					  0x10000,	/* SLB must be 64k aligned */
					  GRUB_RELOCATOR_PREFERENCE_LOW, 1);
  if (err)
    {
       grub_file_close (file);
       return err;
    }

  addr = get_virtual_current_address (ch);
  grub_dprintf ("slaunch", "addr: %p\r\n", addr);
  target = get_physical_target_address (ch);
  grub_dprintf ("slaunch", "target: %p\r\n", (void*) target);

  grub_dprintf ("slaunch", "add module\r\n");
  err = grub_slaunch_add_module (addr, target, size);
  if (err)
    {
      grub_file_close (file);
      return err;
    }


  grub_dprintf ("slaunch", "read file\r\n");
  if (grub_file_read (file, addr, size) != size)
    {
      grub_file_close (file);
      if (!grub_errno)
	grub_error (GRUB_ERR_FILE_READ_ERROR, N_("premature end of file %s"),
		    argv[0]);
      return grub_errno;
    }

  grub_dprintf ("slaunch", "close file\r\n");
  grub_file_close (file);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_slaunch, cmd_slaunch_module;

GRUB_MOD_INIT(slaunch)
{
  cmd_slaunch =
	grub_register_command ("slaunch", grub_cmd_slaunch,
				0, N_("Launch Secure Loader"));
  cmd_slaunch_module =
	grub_register_command ("slaunch_module", grub_cmd_slaunch_module,
				0, N_("Secure Loader module command"));
  my_mod = mod;
}

GRUB_MOD_FINI(slaunch)
{
  grub_slaunch_free ();
  grub_unregister_command (cmd_slaunch_module);
  grub_unregister_command (cmd_slaunch);
}
