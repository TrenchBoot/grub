/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  Free Software Foundation, Inc.
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
 *
 *  TPM TIS and CRB driver.
 *
 *  Note: It is suggested to not use this driver together with UEFI TPM driver.
 */

#include <grub/command.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/i386/memory.h>
#include <grub/i386/mmio.h>
#include <grub/i386/tpm.h>
#include <grub/mm.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

/*
 * Code based on TCG PC Client Platform TPM Profile Specification for TPM 2.0,
 * Version 1.05 Revision 14 released September 4, 2020.
 */

#define TPM_MMIO_BASE		0xfed40000

/* 6.3.2 Register Space Addresses */
/* TIS registers. */
#define TPM_ACCESS		0x0000
#define TPM_INTF_CAPABILITY	0x0014
#define INTF_CAP_INTERFACE_VERSION_SHIFT	28
#define INTF_CAP_INTERFACE_VERSION_MASK		7
#define TPM_INTERFACE_ID	0x0030
#define INTERFACE_ID_INTERFACE_TYPE_SHIFT	0
#define INTERFACE_ID_INTERFACE_TYPE_MASK	0xF

/* CRB registers. */
#define TPM_LOC_CTRL		0x0008


#define TIS_RELINQUISH_LCL	0x20
#define CRB_RELINQUISH_LCL	0x0002

/* 6.4.2 Interface Identifier Register */
#define TPM_CRB_INTF_ACTIVE	0x1

/* 6.5.2.7 Interface Capability */
#define TPM_12_TIS_INTF_12	0x0
#define TPM_12_TIS_INTF_13	0x2
#define TPM_20_TIS_INTF_13	0x3

typedef enum
  {
    TPM_INTF_NONE = 0,
    TPM_INTF_TIS,
    TPM_INTF_CRB
  }
tpm_intf_t;

static grub_tpm_ver_t tpm_ver = GRUB_TPM_NONE;
static tpm_intf_t tpm_intf = TPM_INTF_NONE;

grub_tpm_ver_t
grub_get_tpm_ver (void)
{
  return tpm_ver;
}

/* Localities 0-4 are supported only. */
void
grub_tpm_relinquish_locality (grub_uint8_t lcl)
{
  grub_addr_t addr = TPM_MMIO_BASE + lcl * GRUB_PAGE_SIZE;

  if (tpm_intf == TPM_INTF_TIS)
    grub_write8 (TIS_RELINQUISH_LCL, addr + TPM_ACCESS);
  else if (tpm_intf == TPM_INTF_CRB)
    grub_write32 (CRB_RELINQUISH_LCL, addr + TPM_LOC_CTRL);
}

static grub_err_t
grub_cmd_tpm_type (grub_command_t cmd __attribute__ ((unused)),
		   int argc __attribute__ ((unused)),
		   char *argv[] __attribute__ ((unused)))
{
  const char *tpm_ver_s = "NONE";
  const char *tpm_intf_s = "NONE";

  if (tpm_ver == GRUB_TPM_12)
    tpm_ver_s = "1.2";
  else if (tpm_ver == GRUB_TPM_20)
    tpm_ver_s = "2.0";

  if (tpm_intf == TPM_INTF_TIS)
    tpm_intf_s = "TIS";
  else if (tpm_intf == TPM_INTF_CRB)
    tpm_intf_s = "CRB";

  grub_printf ("TPM family: %s\nTPM interface: %s\n", tpm_ver_s, tpm_intf_s);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_tpm_type;

GRUB_MOD_INIT (tpm)
{
  grub_uint32_t intf_id;
  grub_uint32_t intf_cap;

  cmd_tpm_type = grub_register_command ("tpm_type", grub_cmd_tpm_type,
					NULL, N_("Show TPM version and interface type."));

  tpm_ver = GRUB_TPM_20;

  intf_id = grub_read32 (TPM_MMIO_BASE + TPM_INTERFACE_ID);
  intf_id >>= INTERFACE_ID_INTERFACE_TYPE_SHIFT;
  intf_id &= INTERFACE_ID_INTERFACE_TYPE_MASK;

  tpm_intf = (intf_id == TPM_CRB_INTF_ACTIVE) ? TPM_INTF_CRB : TPM_INTF_TIS;

  /* CRB exists only in TPM 2.0 */
  if (tpm_intf == TPM_INTF_CRB)
    return;

  intf_cap = grub_read32 (TPM_MMIO_BASE + TPM_INTF_CAPABILITY);
  intf_cap >>= INTF_CAP_INTERFACE_VERSION_SHIFT;
  intf_cap &= INTF_CAP_INTERFACE_VERSION_MASK;

  if (intf_cap == TPM_12_TIS_INTF_12 || intf_cap == TPM_12_TIS_INTF_13)
    tpm_ver = GRUB_TPM_12;
}

GRUB_MOD_FINI (tpm)
{
  grub_unregister_command (cmd_tpm_type);
}
