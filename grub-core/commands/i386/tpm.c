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

#define TPM_MMIO_BASE		0xfed40000

/* TIS registers. */
#define TPM_ACCESS		0x0000
#define TPM_INTF_CAPABILITY	0x0014
#define TPM_INTERFACE_ID	0x0030

/* CRB registers. */
#define TPM_LOC_CTRL		0x0008

#define TPM_12_TIS_INTF_12	0x0
#define TPM_12_TIS_INTF_13	0x2
#define TPM_20_TIS_INTF_13	0x3

#define TPM_CRB_INTF_ACTIVE	0x1

#define TIS_RELINQUISH_LCL	0x20
#define CRB_RELINQUISH_LCL	0x0002

/* TODO: Do we need GRUB_PACKED for unions below??? */

union tpm_interface_id
{
  grub_uint32_t raw;
  struct
  {
    grub_uint32_t interface_type:4;
    grub_uint32_t interface_version:4;
    grub_uint32_t cap_locality:1;
    grub_uint32_t reserved_0:4;
    grub_uint32_t cap_tis:1;
    grub_uint32_t cap_crb:1;
    grub_uint32_t cap_ifres:2;
    grub_uint32_t interface_selector:2;
    grub_uint32_t intf_sel_lock:1;
    grub_uint32_t reserved_1:4;
    grub_uint32_t reserved_2:8;
  };
} GRUB_PACKED;
typedef union tpm_interface_id tpm_interface_id_t;

union tpm_intf_capability
{
  grub_uint32_t raw;
  struct
  {
    grub_uint32_t data_avail_int_support:1;
    grub_uint32_t sts_valid_int_support:1;
    grub_uint32_t locality_change_int_support:1;
    grub_uint32_t interrupt_level_high:1;
    grub_uint32_t interrupt_level_low:1;
    grub_uint32_t interrupt_edge_rising:1;
    grub_uint32_t interrupt_edge_falling:1;
    grub_uint32_t command_ready_int_support:1;
    grub_uint32_t burst_count_static:1;
    grub_uint32_t data_transfer_size_support:2;
    grub_uint32_t reserved_0:17;
    grub_uint32_t interface_version:3;
    grub_uint32_t reserved_1:1;
  };
} GRUB_PACKED;
typedef union tpm_intf_capability tpm_intf_capability_t;

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
grub_tpm_relinquish_lcl (grub_uint8_t lcl)
{
  grub_addr_t addr = TPM_MMIO_BASE + lcl * GRUB_PAGE_SIZE;

  if (tpm_intf == TPM_INTF_TIS)
    grub_writeb (TIS_RELINQUISH_LCL, (void *) (addr + TPM_ACCESS));
  else if (tpm_intf == TPM_INTF_CRB)
    grub_writel (CRB_RELINQUISH_LCL, (void *) (addr + TPM_LOC_CTRL));
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

  grub_printf ("TPM VER: %s\nTPM INTF: %s\n", tpm_ver_s, tpm_intf_s);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_tpm_type;

GRUB_MOD_INIT (tpm)
{
  tpm_interface_id_t intf_id;
  tpm_intf_capability_t intf_cap;

  cmd_tpm_type = grub_register_command ("tpm_type", grub_cmd_tpm_type,
					NULL, N_("Show TPM version and interface type."));

  intf_cap.raw = grub_readl ((void *)(grub_addr_t) (TPM_MMIO_BASE + TPM_INTF_CAPABILITY));

  if (intf_cap.interface_version == TPM_12_TIS_INTF_12 ||
      intf_cap.interface_version == TPM_12_TIS_INTF_13)
    {
      tpm_ver = GRUB_TPM_12;
      tpm_intf = TPM_INTF_TIS;
      return;
    }

  if (intf_cap.interface_version != TPM_20_TIS_INTF_13)
    return;

  tpm_ver = GRUB_TPM_20;

  intf_id.raw = grub_readl ((void *)(grub_addr_t) (TPM_MMIO_BASE + TPM_INTERFACE_ID));

  tpm_intf = (intf_id.interface_type == TPM_CRB_INTF_ACTIVE) ? TPM_INTF_CRB : TPM_INTF_TIS;
}

GRUB_MOD_FINI (tpm)
{
  grub_unregister_command (cmd_tpm_type);
}
