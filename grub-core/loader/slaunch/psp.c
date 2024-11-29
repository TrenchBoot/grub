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

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <grub/time.h>
#include <grub/pci.h>
#include <grub/efi/efi.h>
#include <grub/efi/api.h>
#include <grub/i386/linux.h>
#include <grub/i386/pci.h>
#include <grub/i386/psp.h>

struct psp_drtm_interface
{
  volatile grub_uint32_t *c2pmsg_72;
  volatile grub_uint32_t *c2pmsg_93;
  volatile grub_uint32_t *c2pmsg_94;
  volatile grub_uint32_t *c2pmsg_95;
};

typedef enum
{
  PSP_NONE = 0,
  PSP_V1,
  PSP_V2,
  PSP_V3
} psp_version_t;

struct pci_psp_device
{
  grub_uint16_t vendor_id;
  grub_uint16_t dev_id;
  psp_version_t version;
};

static const struct pci_psp_device psp_devs_list[] = {
  {0x1022, 0x1537, PSP_NONE},
  {0x1022, 0x1456, PSP_V1},
  {0x1022, 0x1468, PSP_NONE},
  {0x1022, 0x1486, PSP_V2},
  {0x1022, 0x15DF, PSP_V3},
  {0x1022, 0x1649, PSP_V2},
  {0x1022, 0x14CA, PSP_V3},
  {0x1022, 0x15C7, PSP_NONE}
};

static struct psp_drtm_interface psp_drtm;

struct drtm_capability
{
  int drtm_enabled;
  int tsme_enabled;
  int anti_rollback_status_bit;
  grub_uint32_t version;
  grub_uint32_t tmr_alignment;
  grub_uint32_t tmr_count;
};

static struct drtm_capability drtm_capability;

static const char *drtm_status_strings[] = {
	"DRTM_NO_ERROR",
	"DRTM_NOT_SUPPORTED",
	"DRTM_LAUNCH_ERROR",
	"DRTM_TMR_SETUP_FAILED_ERROR",
	"DRTM_TMR_DESTROY_FAILED_ERROR",
	"UNDEFINED",
	"UNDEFINED",
	"DRTM_GET_TCG_LOGS_FAILED_ERROR",
	"DRTM_OUT_OF_RESOURCES_ERROR",
	"DRTM_GENERIC_ERROR",
	"DRTM_INVALID_SERVICE_ID_ERROR",
	"DRTM_MEMORY_UNALIGNED_ERROR",
	"DRTM_MINIMUM_SIZE_ERROR",
	"DRTM_GET_TMR_DESCRIPTOR_FAILED",
	"DRTM_EXTEND_OSSL_DIGEST_FAILED",
	"DRTM_SETUP_NOT_ALLOWED",
	"DRTM_GET_IVRS_TABLE_FAILED"
};

static grub_err_t init_drtm_interface (grub_uint64_t base_addr, psp_version_t psp_version);
static void init_drtm_device (grub_pci_device_t dev);
static int drtm_wait_for_psp_ready (grub_uint32_t *status);

static const char *drtm_status_string (grub_uint32_t status)
{
  if (status > DRTM_GET_IVRS_TABLE_FAILED)
    return "UNDEFINED";

  return drtm_status_strings[status];
}

static void
smn_register_read (grub_uint32_t address, grub_uint32_t *value)
{
  grub_pci_device_t dev = {0, 0, 0};
  grub_pci_address_t addr;
  grub_uint32_t val;

  val = address;
  addr = grub_pci_make_address (dev, 0xb8);
  grub_pci_write (addr, val);
  addr = grub_pci_make_address (dev, 0xbc);
  val = grub_pci_read (addr);
  *value = val;
}

#define IOHC0NBCFG_SMNBASE 0x13b00000
#define PSP_BASE_ADDR_LO_SMN_ADDRESS (IOHC0NBCFG_SMNBASE + 0x102e0)

static grub_uint64_t
get_psp_bar_addr (void)
{
  grub_uint32_t pspbaselo;

  pspbaselo = 0;
  smn_register_read (PSP_BASE_ADDR_LO_SMN_ADDRESS, &pspbaselo);

  /* Mask out the lower bits */
  pspbaselo &= 0xfff00000;
  return (grub_uint64_t) pspbaselo;
}

static bool
is_drtm_device (grub_uint16_t vendor_id, grub_uint16_t dev_id)
{
  grub_uint32_t max_psp_devs = sizeof (psp_devs_list) / sizeof (psp_devs_list[0]);
  const struct pci_psp_device *psp = NULL;
  grub_uint32_t i;

  for (i = 0; i < max_psp_devs; i++)
    {
      if ((psp_devs_list[i].vendor_id == vendor_id) &&
	  (psp_devs_list[i].dev_id == dev_id))
	{
	  psp = &psp_devs_list[i];
	  break;
	}
    }

  if (psp && psp->version == PSP_NONE)
    {
      grub_dprintf ("slaunch", "DRTM: AMD SP device (PCI info: 0x%04x, 0x%04x) does not have PSP\n",
		    psp->vendor_id, psp->dev_id);
      return false;
    }

  return true;
}

grub_err_t
grub_psp_discover (void)
{
  grub_pci_device_t dev;
  grub_pci_address_t addr;
  grub_uint16_t vendor_id, dev_id;
  grub_uint64_t bar2_addr = 0;

  for (dev.bus = 0; dev.bus < GRUB_PCI_NUM_BUS; dev.bus++)
    {
      for (dev.device = 0; dev.device < GRUB_PCI_NUM_DEVICES; dev.device++)
	{
	  for (dev.function = 0; dev.function < GRUB_PCI_NUM_FUNCTIONS; dev.function++)
	    {
	      addr = grub_pci_make_address (dev, 0);
	      vendor_id = grub_pci_read_word (addr);
	      addr = grub_pci_make_address (dev, 2);
	      dev_id = grub_pci_read_word (addr);
	      if (is_drtm_device (vendor_id, dev_id))
		goto psp_found;
	    }
	}
    }

  return grub_error (GRUB_ERR_BAD_DEVICE, N_("DRTM: failed to find PSP\n"));

psp_found:
  init_drtm_device (dev);

  bar2_addr = get_psp_bar_addr();
  if (!bar2_addr)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("DRTM: failed to find PSP\n"));

  return init_drtm_interface (bar2_addr, PSP_V2);
}

static void
init_drtm_device (grub_pci_device_t dev)
{
  grub_uint16_t pci_cmd;
  grub_uint8_t pin, lat;
  grub_pci_address_t pci_cmd_addr, pin_addr, lat_addr;

  /* Enable memory space access for PSP */
  pci_cmd_addr = grub_pci_make_address (dev, GRUB_PCI_REG_COMMAND);
  pci_cmd = grub_pci_read_word (pci_cmd_addr) | 0x2;
  grub_pci_write_word (pci_cmd_addr, pci_cmd);

  /* Enable PCI interrupts */
  pin_addr = grub_pci_make_address (dev, GRUB_PCI_REG_IRQ_PIN);
  pin = grub_pci_read_byte (pin_addr);
  if (pin)
    {
      pci_cmd = grub_pci_read_word (pci_cmd_addr);
      if (pci_cmd & 0x400)
	{
	  pci_cmd &= ~0x400;
	  grub_pci_write_word (pci_cmd_addr, pci_cmd);
	}
    }

  /* Set PSP at bus master */
  pci_cmd = grub_pci_read_word (pci_cmd_addr) | 0x4;
  grub_pci_write_word (pci_cmd_addr, pci_cmd);

  /* Set PCI latency timer */
  lat_addr = grub_pci_make_address (dev, GRUB_PCI_REG_LAT_TIMER);
  lat = grub_pci_read_byte (lat_addr);
  if (lat < 16)
    {
      lat = 64;
      grub_pci_write_byte (lat_addr, lat);
    }
}

static grub_err_t
init_drtm_interface (grub_uint64_t base_addr, psp_version_t psp_version)
{
#ifdef __i386__
  grub_uint32_t base = (grub_uint32_t) base_addr;
#else
  grub_uint64_t base = base_addr;
#endif

  switch (psp_version)
    {
    case PSP_V2:
      psp_drtm.c2pmsg_72 = (volatile grub_uint32_t *)(base + 0x10a20);
      psp_drtm.c2pmsg_93 = (volatile grub_uint32_t *)(base + 0x10a74);
      psp_drtm.c2pmsg_94 = (volatile grub_uint32_t *)(base + 0x10a78);
      psp_drtm.c2pmsg_95 = (volatile grub_uint32_t *)(base + 0x10a7c);
      break;
    default:
      return grub_error (GRUB_ERR_BAD_DEVICE, N_("DRTM: Unrecognized PSP version %d\n"), psp_version);
    }

  return GRUB_ERR_NONE;
}

static int
drtm_wait_for_psp_ready (grub_uint32_t *status)
{
  int retry = 5;
  grub_uint32_t reg_val = 0;

  while (--retry)
    {
      reg_val = *psp_drtm.c2pmsg_72;

      if (reg_val & DRTM_MBOX_READY_MASK)
	break;

      /* TODO: select wait time appropriately */
      grub_millisleep (100);
    }

  if (!retry)
    return 0;

  if (status)
    *status = reg_val & 0xffff;

  return 1;
}

/*
 * For some reason this workaround is necessary to
 * kickstart the DRTM. Without this step, DRTM does
 * not return the capability.
 *
 * TODO: Check with AMD about why this is necessary.
 */
void
grub_drtm_kick_psp (void)
{
  *psp_drtm.c2pmsg_72 = 0;

  (void)drtm_wait_for_psp_ready (NULL);
}

grub_err_t
grub_drtm_get_capability (void)
{
  grub_uint32_t reg_val = 0;
  grub_uint32_t status = 0;

  if (!drtm_wait_for_psp_ready (NULL))
    return grub_error (GRUB_ERR_TIMEOUT, N_("DRTM: %s: PSP not ready to accept commands\n"), __func__);

  reg_val = (DRTM_CMD_GET_CAPABILITY << DRTM_MBOX_CMD_SHIFT);

  *psp_drtm.c2pmsg_72 = reg_val;

  if (!drtm_wait_for_psp_ready (&status))
    return grub_error (GRUB_ERR_TIMEOUT, N_("DRTM: %s: failed to get a response from PSP\n"), __func__);

  if (status != DRTM_NO_ERROR)
    return grub_error (GRUB_ERR_BAD_DEVICE, N_("DRTM: %s: failed to get PSP capability - %s\n"),
		       __func__, drtm_status_string (status));

  reg_val = *psp_drtm.c2pmsg_93;
  drtm_capability.drtm_enabled = (reg_val & 0x1) != 0;
  drtm_capability.tsme_enabled = (reg_val & 0x2) != 0;
  drtm_capability.anti_rollback_status_bit = (reg_val & 0x4) != 0;

  drtm_capability.version = *psp_drtm.c2pmsg_94;

  reg_val = *psp_drtm.c2pmsg_95;
  drtm_capability.tmr_alignment = reg_val & 0x00FFFFFF;
  drtm_capability.tmr_count = (reg_val & 0xFF000000) >> 24;

  return GRUB_ERR_NONE;
}

/**
 * Setup Trusted Memory Region (TMR). The PSP supports only
 * 1 TMR - as such all of the sysmem region is covered in
 * a single TMR.
 *
 * Walk the E820 MB2 memory map table to figure out the end
 * of the memory addresses. Setup the TMR to cover address
 * ranges from 0x0 to the end calculated during the walk.
 */
int
grub_drtm_setup_tmrs (grub_uint64_t tmr_end)
{
  grub_uint64_t tmr_count = 0;
  grub_uint64_t rem = 0;
  grub_uint32_t status = 0;

  tmr_count = grub_divmod64 (tmr_end, drtm_capability.tmr_alignment, &rem);
  if (rem != 0)
    tmr_count++;

  if (tmr_count > GRUB_UINT_MAX)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("DRTM: %s: memory region bigger than TMR\n"), __func__);
      return -1;
    }

  /*
   * Setup TMR for address range 0x0 to tmr_end. Size is in
   * multiples of tmr_alignment.
   */
  *psp_drtm.c2pmsg_93 = (grub_uint32_t)tmr_count;
  *psp_drtm.c2pmsg_94 = 0;
  *psp_drtm.c2pmsg_95 = 0;

  *psp_drtm.c2pmsg_72 = (DRTM_TMR_INDEX_0 << 24) |
			(DRTM_CMD_TMR_SETUP << DRTM_MBOX_CMD_SHIFT);

  if (!drtm_wait_for_psp_ready (&status))
    {
      grub_error (GRUB_ERR_TIMEOUT, N_("DRTM: %s: failed to get a response from PSP\n"), __func__);
      return -1;
    }

  if (status != DRTM_NO_ERROR)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("DRTM: %s: failed to setup TMRs - %s\n"),
		  __func__, drtm_status_string (status));
      return -1;
    }

  return 0;
}
