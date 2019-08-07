/*
 * acmod.c: support functions for use of Intel(r) TXT Authenticated
 *          Code (AC) Modules
 *
 * Copyright (c) 2003-2011, Intel Corporation
 * All rights reserved.
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
#include <grub/i386/txt.h>

/*
 * This checks to see if two numbers multiplied together are larger
 *   than the type that they are.  Returns TRUE if OVERFLOWING.
 *   If the first parameter "x" is greater than zero and
 *   if that is true, that the largest possible value 0xFFFFFFFF / "x"
 *   is less than the second parameter "y".  If "y" is zero then
 *   it will also fail because no unsigned number is less than zero.
 */
static inline int
multiply_overflow_u32 (grub_uint32_t x, grub_uint32_t y)
{
  /* Use x instead of (x > 0)? */
  return (x > 0) ? ((((grub_uint32_t)(~0))/x) < y) : 0;
}

/*
 *  These three "plus overflow" functions take a "x" value
 *    and add the "y" value to it and if the two values are
 *    greater than the size of the variable type, they will
 *    overflow the type and end up with a smaller value and
 *    return TRUE - that they did overflow.  i.e.
 */
static inline int plus_overflow_u32 (grub_uint32_t x, grub_uint32_t y)
{
  return ((((grub_uint32_t)(~0)) - x) < y);
}

static struct grub_txt_acm_info_table*
get_acmod_info_table (struct grub_txt_acm_header* hdr)
{
  grub_uint32_t user_area_off;

  /* Overflow? */
  if ( plus_overflow_u32 (hdr->header_len, hdr->scratch_size) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM header length plus scratch size overflows"));
      return NULL;
    }

  if ( multiply_overflow_u32 ((hdr->header_len + hdr->scratch_size), 4) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM header length and scratch size in bytes overflows"));
      return NULL;
    }

  /*
   * This fn assumes that the ACM has already passed at least the initial
   * is_acmod() checks.
   */

  user_area_off = (hdr->header_len + hdr->scratch_size) * 4;

  /* Overflow? */
  if ( plus_overflow_u32 (user_area_off, sizeof(struct grub_txt_acm_info_table)) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("user_area_off plus acm_info_table_t size overflows"));
      return NULL;
    }

  /* Check that table is within module. */
  if ( user_area_off + sizeof(struct grub_txt_acm_info_table) > hdr->size * 4 )
    {
      /* TODO: Is (grub_uint32_t) correct??? */
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM info table size too large: %x > %x"),
		  user_area_off + (grub_uint32_t)sizeof(struct grub_txt_acm_info_table), hdr->size * 4);
      return NULL;
    }

  /* Overflow? */
  if ( plus_overflow_u32 ((grub_uint32_t)(unsigned long)hdr, user_area_off) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("hdr plus user_area_off overflows"));
      return NULL;
    }

    return (struct grub_txt_acm_info_table *)((unsigned long)hdr + user_area_off);
}

static struct grub_txt_acm_chipset_id_list*
get_acmod_chipset_list (struct grub_txt_acm_header *hdr)
{
  struct grub_txt_acm_info_table *info_table;
  grub_uint32_t size, id_list_off;
  struct grub_txt_acm_chipset_id_list *chipset_id_list;

  /* This fn assumes that the ACM has already passed the is_acmod() checks */

  info_table = get_acmod_info_table (hdr);
  if ( !info_table )
    return NULL;
  id_list_off = info_table->chipset_id_list;

  size = hdr->size * 4;

  /* Overflow? */
  if ( plus_overflow_u32 (id_list_off, sizeof(struct grub_txt_acm_chipset_id)) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("id_list_off plus acm_chipset_id_t size overflows"));
      return NULL;
    }

  /* Check that chipset id table is w/in ACM */
  if ( id_list_off + sizeof(struct grub_txt_acm_chipset_id) > size )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("chipset id list is too big: %x"), id_list_off);
      return NULL;
    }

  /* Overflow? */
  if ( plus_overflow_u32 ((grub_uint32_t)(unsigned long)hdr, id_list_off) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("hdr plus id_list_off overflows"));
      return NULL;
    }

  chipset_id_list = (struct grub_txt_acm_chipset_id_list*)
                    ((unsigned long)hdr + id_list_off);

  /* Overflows? */
  if ( multiply_overflow_u32 (chipset_id_list->count,
                              sizeof(struct grub_txt_acm_chipset_id)) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("size of acm_chipset_id_list overflows"));
      return NULL;
    }

  if ( plus_overflow_u32 (id_list_off + sizeof(struct grub_txt_acm_chipset_id),
        chipset_id_list->count * sizeof(struct grub_txt_acm_chipset_id)) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("size of all entries overflows"));
      return NULL;
    }

  /* Check that all entries are w/in ACM */
  if ( id_list_off + sizeof(struct grub_txt_acm_chipset_id) +
       chipset_id_list->count * sizeof(struct grub_txt_acm_chipset_id) > size )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM chipset id entries are too big: %x"),
		  chipset_id_list->count);
      return NULL;
    }

  return chipset_id_list;
}

static struct grub_txt_acm_processor_id_list*
get_acmod_processor_list (struct grub_txt_acm_header* hdr)
{
  struct grub_txt_acm_info_table *info_table;
  grub_uint32_t size, id_list_off;
  struct grub_txt_acm_processor_id_list *proc_id_list;

  /* This fn assumes that the ACM has already passed the is_acmod() checks */

  info_table = get_acmod_info_table(hdr);
  if ( info_table == NULL )
    return NULL;
  id_list_off = info_table->processor_id_list;

  size = hdr->size * 4;

  /* Overflow? */
  if ( plus_overflow_u32 (id_list_off, sizeof(struct grub_txt_acm_processor_id)) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("id_list_off plus acm_processor_id_t size overflows"));
      return NULL;
    }

  /* Check that processor id table is w/in ACM */
  if ( id_list_off + sizeof(struct grub_txt_acm_processor_id) > size )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM processor id list is too big: %x"), id_list_off);
      return NULL;
    }

  /* Overflow? */
  if ( plus_overflow_u32 ((unsigned long)hdr, id_list_off) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("hdr plus id_list_off overflows"));
      return NULL;
    }

  proc_id_list = (struct grub_txt_acm_processor_id_list *)
                             ((unsigned long)hdr + id_list_off);

  /* Overflows? */
  if ( multiply_overflow_u32 (proc_id_list->count,
             sizeof(struct grub_txt_acm_processor_id)) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("size of acm_processor_id_list overflows"));
      return NULL;
    }

  if ( plus_overflow_u32 (id_list_off + sizeof(struct grub_txt_acm_processor_id),
        proc_id_list->count * sizeof(struct grub_txt_acm_processor_id)) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("size of all entries overflows"));
      return NULL;
    }

  /* Check that all entries are w/in ACM */
  if ( id_list_off + sizeof(struct grub_txt_acm_processor_id) +
         proc_id_list->count * sizeof(struct grub_txt_acm_processor_id) > size )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM processor id entries are too big: %x"),
		  proc_id_list->count);
      return NULL;
    }

  return proc_id_list;
}

static int
is_acmod (const void *acmod_base, grub_uint32_t acmod_size,
         grub_uint8_t *type_out)
{
  struct grub_txt_acm_header *acm_hdr = (struct grub_txt_acm_header *)acmod_base;
  struct grub_txt_acm_info_table *info_table;

  /* First check size */
  if ( acmod_size < sizeof (struct grub_txt_acm_header) )
    return 0;

  /* Then check overflow */
  if ( multiply_overflow_u32 (acm_hdr->size, 4) )
    return 0;

  /* Then check size equivalency */
  if ( acmod_size != acm_hdr->size * 4 )
    return 0;

  /* Then check type and vendor */
  if ( (acm_hdr->module_type != GRUB_TXT_ACM_MODULE_TYPE) ||
       (acm_hdr->module_vendor != GRUB_TXT_ACM_MODULE_VENDOR_INTEL) )
    return 0;

  info_table = get_acmod_info_table (acm_hdr);
  if ( !info_table )
    return 0;

  /* Check if ACM UUID is present */
  if ( grub_memcmp (&(info_table->uuid), GRUB_TXT_ACM_UUID, 16) )
    return 0;

  if ( type_out )
    *type_out = info_table->chipset_acm_type;

  return 1;
}

static struct grub_txt_acm_header*
get_bios_sinit (void *sinit_region_base)
{
  grub_uint8_t *txt_heap = grub_txt_get_heap ();
  struct grub_txt_bios_data *bios_data = grub_txt_bios_data_start (txt_heap);
  struct grub_txt_acm_header *bios_sinit;

  if ( !sinit_region_base )
     return NULL;

  if ( bios_data->bios_sinit_size == 0 )
    return NULL;

  /* BIOS has loaded an SINIT module, so verify that it is valid */
  grub_dprintf ("slaunch", "BIOS has already loaded an SINIT module\n");

  bios_sinit = (struct grub_txt_acm_header *)sinit_region_base;

  /* Is it a valid SINIT module? */
  if ( !grub_txt_is_sinit_acmod (sinit_region_base, bios_data->bios_sinit_size) ||
       !grub_txt_acmod_match_platform (bios_sinit) )
    return NULL;

  return bios_sinit;
}

grub_uint32_t
grub_txt_supported_os_sinit_data_ver (struct grub_txt_acm_header* hdr)
{
  static struct grub_txt_acm_info_table *info_table;

  /* Assumes that it passed is_sinit_acmod() */
  info_table = get_acmod_info_table (hdr);

  if ( info_table == NULL )
    return 0;

  return info_table->os_sinit_data_ver;
}

grub_uint32_t
grub_txt_get_sinit_capabilities (struct grub_txt_acm_header* hdr)
{
  static struct grub_txt_acm_info_table *info_table;

  /* Assumes that it passed is_sinit_acmod() */
  info_table = get_acmod_info_table (hdr);

  if ( info_table == NULL || info_table->version < 3 )
    return 0;

  return info_table->capabilities;
}

int
grub_txt_is_sinit_acmod (const void *acmod_base, grub_uint32_t acmod_size)
{
  grub_uint8_t type;

  if ( !is_acmod (acmod_base, acmod_size, &type) )
    return 0;

  if ( type != GRUB_TXT_ACM_CHIPSET_TYPE_SINIT )
    return 0;

  return 1;
}

/* Format of VER.FSBIF and VER.QPIIF registers. */
typedef union {
  grub_uint64_t _raw;
  struct {
     grub_uint64_t reserved   : 31;
     grub_uint64_t prod_fused : 1;
  };
} grub_txt_ver_fsbif_qpiif_t;

int
grub_txt_acmod_match_platform (struct grub_txt_acm_header *hdr)
{
  union grub_txt_didvid didvid;
  grub_uint32_t fms, ign, i;
  grub_uint64_t platform_id;
  grub_txt_ver_fsbif_qpiif_t ver;
  struct grub_txt_acm_chipset_id_list *chipset_id_list;
  struct grub_txt_acm_chipset_id *chipset_id;
  struct grub_txt_acm_processor_id_list *proc_id_list;
  struct grub_txt_acm_processor_id *proc_id;
  struct grub_txt_acm_info_table *info_table;

  /* This fn assumes that the ACM has already passed the is_acmod() checks */

  /* Get chipset fusing, device, and vendor id info */
  didvid.value = grub_txt_reg_pub_readq (GRUB_TXT_DIDVID);

  ver._raw = grub_txt_reg_pub_readq (GRUB_TXT_VER_FSBIF);
  if ( (ver._raw & 0xffffffff) == 0xffffffff ||
       (ver._raw & 0xffffffff) == 0x00 ) /* Need to use VER.QPIIF */
    ver._raw = grub_txt_reg_pub_readq (GRUB_TXT_VER_QPIIF);

  grub_dprintf ("slaunch", "chipset production fused: %x, "
		"chipset vendor: 0x%x, device: 0x%x, revision: 0x%x\n",
		ver.prod_fused, didvid.vid, didvid.did, didvid.rid);

  grub_cpuid (1, fms, ign, ign, ign);
  platform_id = grub_rdmsr (GRUB_MSR_X86_PLATFORM_ID);

  grub_dprintf ("slaunch", "processor family/model/stepping: 0x%x, "
		"platform id: 0x%" PRIxGRUB_UINT64_T "\n", fms, platform_id);

  /*
   * Check if chipset fusing is same. Note the DEBUG.FUSE bit in the version
   * is 0 when debug fused so the logic below checking a mismatch is valid.
   */
  if ( (ver._raw & GRUB_TXT_VERSION_DEBUG_FUSED) &&
       (hdr->flags & GRUB_TXT_ACM_FLAG_DEBUG_SIGNED) )
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("production/debug mismatch between chipset and ACM"));
      return 0;
    }

  /* Check if chipset vendor/device/revision IDs match */
  chipset_id_list = get_acmod_chipset_list (hdr);
  if ( !chipset_id_list )
    return 0;

  grub_dprintf ("slaunch", "%d SINIT ACM chipset id entries:\n", chipset_id_list->count);

  chipset_id = (struct grub_txt_acm_chipset_id *) ((grub_addr_t)chipset_id_list + sizeof (chipset_id_list->count));
  for (i = 0; i < chipset_id_list->count; i++, chipset_id++)
    {
      grub_dprintf ("slaunch", "  vendor: 0x%x, device: 0x%x, flags: 0x%x, "
		    "revision: 0x%x, extended: 0x%x\n", chipset_id->vendor_id,
		    chipset_id->device_id, chipset_id->flags,
		    chipset_id->revision_id, chipset_id->extended_id);

      if ( (didvid.vid == chipset_id->vendor_id ) &&
           (didvid.did == chipset_id->device_id ) &&
           ( ( ( (chipset_id->flags & GRUB_TXT_ACM_REVISION_ID_MASK) == 0) &&
                 (didvid.rid == chipset_id->revision_id) ) ||
               ( ( (chipset_id->flags & GRUB_TXT_ACM_REVISION_ID_MASK) == 1) &&
                 ( (didvid.rid & chipset_id->revision_id) != 0 ) ) ) )
            break;
    }

  if ( i >= chipset_id_list->count )
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("chipset id mismatch"));
      return 0;
    }

  /* Check if processor family/model/stepping and platform IDs match */
  info_table = get_acmod_info_table (hdr);
  if ( !info_table )
    return 0;

  /*
   * Logic inverted from oringal to avoid the if block. Not sure what drives
   * the logic of not checking processor infrmation for version 4 or less.
   */
  if ( info_table->version < 4 )
    return 1;

  proc_id_list = get_acmod_processor_list(hdr);
  if ( !proc_id_list )
    return 1;

  grub_dprintf ("slaunch", "%d SINIT ACM processor id entries:\n", proc_id_list->count);

  proc_id = (struct grub_txt_acm_processor_id *) ((grub_addr_t)proc_id_list + sizeof (proc_id_list->count));
  for (i = 0; i < proc_id_list->count; i++, proc_id++)
    {
      grub_dprintf ("slaunch", "  fms: 0x%x, fms_mask: 0x%x, platform_id: 0x%" PRIxGRUB_UINT64_T
		    ", platform_mask: 0x%" PRIxGRUB_UINT64_T "\n", proc_id->fms, proc_id->fms_mask,
		    proc_id->platform_id, proc_id->platform_mask);

      if ( (proc_id->fms == (fms & proc_id->fms_mask)) &&
           (proc_id->platform_id == (platform_id & proc_id->platform_mask)) )
        break;
    }

  if ( i >= proc_id_list->count )
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("chipset id mismatch"));
      return 0;
    }

  return 1;
}

struct grub_txt_acm_header *
grub_txt_sinit_select (struct grub_txt_acm_header *sinit)
{
  struct grub_txt_acm_header *bios_sinit;
  void *sinit_region_base;
  grub_uint32_t sinit_region_size;

  sinit_region_base = (void *)(grub_addr_t) grub_txt_reg_pub_readq (GRUB_TXT_SINIT_BASE);
  sinit_region_size = (grub_uint32_t) grub_txt_reg_pub_readq (GRUB_TXT_SINIT_SIZE);

  grub_dprintf ("slaunch", "TXT.SINIT.BASE: %p\nTXT.SINIT.SIZE: 0x%"
		PRIxGRUB_UINT32_T "\n", sinit_region_base, sinit_region_size);

  if (sinit_region_base == NULL)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("no SINIT ACM final resting place"));
      return NULL;
    }

  if (sinit != NULL)
    grub_dprintf ("slaunch", "SINIT ACM date: %" PRIxGRUB_UINT32_T "\n", sinit->date);

  bios_sinit = get_bios_sinit (sinit_region_base);

  /* Does BIOS provide SINIT ACM? */
  if (bios_sinit != NULL)
    {
      grub_dprintf ("slaunch", "BIOS SINIT ACM date: %" PRIxGRUB_UINT32_T "\n",
		    bios_sinit->date);

      if (sinit == NULL)
        {
	  grub_dprintf ("slaunch", "no SINIT ACM provided. Using BIOS SINIT ACM\n");
          return bios_sinit;
        }

      if (bios_sinit->date >= sinit->date)
        {
          grub_dprintf ("slaunch", "BIOS provides newer or same SINIT ACM, so, using BIOS one\n");
          return bios_sinit;
        }

      grub_dprintf ("slaunch", "BIOS provides older SINIT ACM, so, ignoring BIOS one\n");
    }

  /* Fail if there is no SINIT ACM. */
  if (sinit == NULL)
    return NULL;

  /* Our SINIT ACM is newer than BIOS one or BIOS does not have one. */

  if (multiply_overflow_u32 (sinit->size, 4))
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("SINIT ACM size in bytes overflows"));
      return NULL;
    }

  if ((sinit->size * 4) > sinit_region_size)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY,
		  N_("SINIT ACM does not fit into final resting place: 0x%"
		  PRIxGRUB_UINT32_T "\n"), sinit->size * 4);
      return NULL;
    }

  grub_memcpy (sinit_region_base, sinit, sinit->size * 4);

  return sinit_region_base;
}
