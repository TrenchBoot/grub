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
#include <grub/slaunch.h>
#include <grub/acpi.h>

#define GRUB_ACPI_DRTM_SIGNATURE "DRTM"

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

static inline grub_uint32_t *get_bootloader_data_addr (struct grub_slaunch_module *mod)
{
  grub_uint16_t *ptr = (grub_uint16_t *)mod->addr;
  return (grub_uint32_t *)(mod->addr + ptr[1]);
}

grub_err_t
grub_slaunch_boot_skinit (struct grub_slaunch_params *slparams)
{
  if (grub_slaunch_get_modules()) {
    grub_uint32_t *boot_data = get_bootloader_data_addr(grub_slaunch_get_modules());
    grub_uint32_t *apic = (grub_uint32_t *)0xfee00300ULL;
    struct drtm_t *drtm = get_drtm_acpi_table();

    grub_dprintf ("slaunch", "real_mode_target: 0x%x\r\n",
                  slparams->real_mode_target);
    grub_dprintf ("slaunch", "prot_mode_target: 0x%x\r\n",
                  slparams->prot_mode_target);
    grub_dprintf ("slaunch", "params: %p\r\n", slparams->params);

    boot_data[GRUB_SL_ZEROPAGE_OFFSET/4] = (grub_uint32_t)slparams->real_mode_target;
    if (drtm) {
      boot_data[GRUB_SL_EVENTLOG_ADDR_OFFSET/4] = drtm->Log_Area_Start;
      boot_data[GRUB_SL_EVENTLOG_SIZE_OFFSET/4] = drtm->Log_Area_Length;
    }

    grub_dprintf ("slaunch", "broadcasting INIT\r\n");
    *apic = 0x000c0500;               // INIT, all excluding self

    grub_dprintf ("slaunch", "grub_tis_init\r\n");
    grub_tis_init();
    grub_dprintf ("slaunch", "grub_tis_request_locality\r\n");
    grub_tis_request_locality(0xff);  // relinquish all localities

    grub_dprintf("linux", "Invoke SKINIT\r\n");
    return grub_relocator_skinit_boot (slparams->relocator, grub_slaunch_get_modules()->target, 0);
  } else {
    grub_dprintf("linux", "Secure Loader module not loaded, run slaunch_module\r\n");
  }
  return GRUB_ERR_NONE;
}

grub_err_t
grub_slaunch_mb2_boot (struct grub_relocator *rel, struct grub_relocator32_state state)
{
  grub_uint32_t *boot_data = get_bootloader_data_addr(grub_slaunch_get_modules());
  grub_uint32_t *apic = (grub_uint32_t *)0xfee00300ULL;
  struct drtm_t *drtm = get_drtm_acpi_table();

  // TODO: save kernel size for measuring in LZ for non-ELF files?
  boot_data[GRUB_SL_ZEROPAGE_OFFSET/4] = state.ebx;
  boot_data[GRUB_SL_ZEROPAGE_OFFSET/4 - 1] = 2;	// Pass boot protocol used
  if (drtm) {
    boot_data[GRUB_SL_EVENTLOG_ADDR_OFFSET/4] = drtm->Log_Area_Start;
    boot_data[GRUB_SL_EVENTLOG_SIZE_OFFSET/4] = drtm->Log_Area_Length;
  }

  grub_dprintf ("slaunch", "broadcasting INIT\r\n");
  *apic = 0x000c0500;               // INIT, all excluding self

  grub_dprintf ("slaunch", "grub_tis_init\r\n");
  grub_tis_init();
  grub_dprintf ("slaunch", "grub_tis_request_locality\r\n");
  grub_tis_request_locality(0xff);  // relinquish all localities

  grub_dprintf("slaunch", "Invoke SKINIT\r\n");
  return grub_relocator_skinit_boot (rel, grub_slaunch_get_modules()->target, 0);
}
