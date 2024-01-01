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
#include <grub/safemath.h>
#include <grub/dl.h>
#include <grub/cpu/relocator.h>
#include <grub/i386/cpuid.h>
#include <grub/i386/msr.h>
#include <grub/i386/txt.h>

/*
 * Macro that returns value of it->field if it's inside info table, 0 otherwise.
 * Fields at or below 'length' ('uuid', 'chipset_acm_type', 'version') don't
 * benefit from this macro, because it requires that 'length' (and by extension
 * fields below that) is valid.
 */
#define info_table_get(it, field)						\
  (__builtin_offsetof(struct grub_txt_acm_info_table, field) + sizeof(it->field)\
   <= it->length ? it->field : 0)

/*
 * Returns hdr + offset if [offset, offset + count * size) is within the bounds
 * of the ACM, NULL otherwise.
 */
static void*
n_fit_in_acm (struct grub_txt_acm_header *hdr, grub_uint32_t offset,
	      grub_uint32_t size, grub_uint32_t count)
{
  grub_uint32_t total_size, elem_end;
  /* ACM size overflow was checked in is_acmod() */
  grub_uint32_t acm_len = hdr->size * 4;

  /*
   * `offset` will often come from `info_table_get`, and this is the most
   * convenient place to check for the macro returning zero. This is fine, since
   * there is no legitimate reason to access the zero offset in this manner.
   */
  if ( offset == 0 )
    return NULL;

  if ( grub_mul (size, count, &total_size) )
    return NULL;

  if ( grub_add (offset, total_size, &elem_end) )
    return NULL;

  if ( elem_end > acm_len )
    return NULL;

  /* Not checking if (hdr + elem_end) overflows. We know that (hdr + acm_len)
   * doesn't, and that elem_end <= acm_len. For the same reason we don't have to
   * check if (hdr + offset) overflows. */

  return (void *)((unsigned long)hdr + offset);
}

static void*
fits_in_acm (struct grub_txt_acm_header *hdr, grub_uint32_t offset,
	     grub_uint32_t size)
{
  return n_fit_in_acm(hdr, offset, size, 1);
}

/*
 * Returns pointer to ACM information table. If the table is located outside of
 * ACM or its reported size is too small to cover at least 'length' field,
 * NULL is returned instead.
 */
static struct grub_txt_acm_info_table*
get_acmod_info_table (struct grub_txt_acm_header* hdr)
{
  grub_uint32_t user_area_off, info_table_size;
  struct grub_txt_acm_info_table *ptr = NULL;
  /* Minimum size required to read full size of table */
  info_table_size = __builtin_offsetof (struct grub_txt_acm_info_table, length)
		    + sizeof(ptr->length);

  /* Overflow? */
  if ( grub_add (hdr->header_len, hdr->scratch_size, &user_area_off) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM header length plus scratch size overflows"));
      return NULL;
    }

  if ( grub_mul (user_area_off, 4, &user_area_off) )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM header length and scratch size in bytes overflows"));
      return NULL;
    }

  ptr = fits_in_acm(hdr, user_area_off, info_table_size);

  if ( ptr != NULL )
    {
      if ( info_table_get (ptr, length) < info_table_size )
	return NULL;

      info_table_size = info_table_get (ptr, length);
      ptr = fits_in_acm(hdr, user_area_off, info_table_size);
    }

  return ptr;
}

/*
 * Function returns pointer to chipset ID list, after checking that
 * grub_txt_acm_chipset_id_list and all grub_txt_acm_chipset_id structures are
 * within ACM. Otherwise, NULL is returned.
 */
static struct grub_txt_acm_chipset_id_list*
get_acmod_chipset_list (struct grub_txt_acm_header *hdr)
{
  struct grub_txt_acm_info_table *info_table;
  grub_uint32_t id_entries_off;
  struct grub_txt_acm_chipset_id_list *chipset_id_list;

  /* This fn assumes that the ACM has already passed the is_acmod() checks */

  info_table = get_acmod_info_table (hdr);
  if ( info_table == NULL )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM info table out of bounds"));
      return NULL;
    }

  chipset_id_list = fits_in_acm(hdr, info_table_get (info_table, chipset_id_list),
				sizeof(struct grub_txt_acm_chipset_id_list));
  if ( chipset_id_list == NULL )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM chipset ID list out of bounds"));
      return NULL;
    }

  /* Overflows were checked by fits_in_acm() */
  id_entries_off = info_table->chipset_id_list + sizeof(*chipset_id_list);

  if ( n_fit_in_acm( hdr, id_entries_off, sizeof(struct grub_txt_acm_chipset_id),
		      chipset_id_list->count ) == NULL )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM chipset ID entries out of bounds"));
      return NULL;
    }

  return chipset_id_list;
}

/*
 * Function returns pointer to processor ID list, after checking that
 * grub_txt_acm_processor_id_list and all grub_txt_acm_processor_id structures
 * are within ACM. Otherwise, NULL is returned.
 */
static struct grub_txt_acm_processor_id_list*
get_acmod_processor_list (struct grub_txt_acm_header* hdr)
{
  struct grub_txt_acm_info_table *info_table;
  grub_uint32_t id_entries_off;
  struct grub_txt_acm_processor_id_list *proc_id_list;

  /* This fn assumes that the ACM has already passed the is_acmod() checks */

  info_table = get_acmod_info_table(hdr);
  if ( info_table == NULL )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM info table out of bounds"));
      return NULL;
    }

  proc_id_list = fits_in_acm(hdr, info_table_get (info_table, processor_id_list),
			     sizeof(*proc_id_list));
  if ( proc_id_list == NULL )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM processor ID list out of bounds"));
      return NULL;
    }

  /* Overflows were checked by fits_in_acm() */
  id_entries_off = info_table->processor_id_list + sizeof(*proc_id_list);

  if ( n_fit_in_acm ( hdr, id_entries_off, sizeof(*proc_id_list),
		     proc_id_list->count ) == NULL )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("ACM processor ID entries out of bounds"));
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
  grub_uint32_t size_from_hdr;

  /* First check size */
  if ( acmod_size < sizeof (*acm_hdr) )
    return 0;

  /* Then check overflow */
  if ( grub_mul (acm_hdr->size, 4, &size_from_hdr) )
    return 0;

  /* Then check size equivalency */
  if ( acmod_size != size_from_hdr )
    return 0;

  /* Then check type, sub-type and vendor */
  if ( (acm_hdr->module_type != GRUB_TXT_ACM_MODULE_TYPE) ||
       (acm_hdr->module_sub_type != GRUB_TXT_ACM_MODULE_SUB_TYPE_TXT_ACM) ||
       (acm_hdr->module_vendor != GRUB_TXT_ACM_MODULE_VENDOR_INTEL) )
    return 0;

  info_table = get_acmod_info_table (acm_hdr);
  if ( info_table == NULL )
    return 0;

  /* Check if ACM UUID is present */
  if ( grub_memcmp (&(info_table->uuid), GRUB_TXT_ACM_UUID, 16) )
    return 0;

  /*
   * TXT specification doesn't give clear mapping of info table size to version,
   * so just warn if the size is different than expected but try to use it
   * anyway. info_table_get() macro does enough testing to not read outside
   * of info table.
   */
  if ( info_table->length < sizeof(*info_table) )
    grub_dprintf ("slaunch", "Info table size (%x) smaller than expected (%"
		  PRIxGRUB_SIZE ")\n",
		  info_table->length, sizeof(*info_table));

  if ( type_out )
    *type_out = info_table_get (info_table, chipset_acm_type);

  return 1;
}

static struct grub_txt_acm_header*
get_bios_sinit (void *sinit_region_base)
{
  grub_uint8_t *txt_heap = grub_txt_get_heap ();
  struct grub_txt_bios_data *bios_data = grub_txt_bios_data_start (txt_heap);
  struct grub_txt_acm_header *bios_sinit;
  grub_uint32_t tmp;

  if ( sinit_region_base == NULL )
    return NULL;

  if ( bios_data->bios_sinit_size == 0 )
    return NULL;

  /* Check if ACM crosses 4G */
  if ( grub_add ( (unsigned long)sinit_region_base, bios_data->bios_sinit_size,
                  &tmp) )
    return NULL;

  /* BIOS has loaded an SINIT module, so verify that it is valid */
  grub_dprintf ("slaunch", "BIOS has already loaded an SINIT module\n");

  bios_sinit = (struct grub_txt_acm_header *)sinit_region_base;

  /* Is it a valid SINIT module? */
  if ( !grub_txt_is_sinit_acmod (sinit_region_base, bios_data->bios_sinit_size) ||
       !grub_txt_acmod_match_platform (bios_sinit) )
    {
      grub_dprintf("slaunch", "BIOS SINIT module did not pass reasonableness checks");
      return NULL;
    }

  return bios_sinit;
}

grub_uint32_t
grub_txt_supported_os_sinit_data_ver (struct grub_txt_acm_header* hdr)
{
  static struct grub_txt_acm_info_table *info_table;

  /* Assumes that it passed grub_txt_is_sinit_acmod() */
  info_table = get_acmod_info_table (hdr);

  if ( info_table == NULL )
    return 0;

  return info_table_get (info_table, os_sinit_data_ver);
}

grub_uint32_t
grub_txt_get_sinit_capabilities (struct grub_txt_acm_header* hdr)
{
  static struct grub_txt_acm_info_table *info_table;

  /* Assumes that it passed grub_txt_is_sinit_acmod() */
  info_table = get_acmod_info_table (hdr);

  if ( info_table == NULL || info_table->version < 3 )
    return 0;

  return info_table_get (info_table, capabilities);
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

static int
didvid_matches(union grub_txt_didvid didvid,
	       struct grub_txt_acm_chipset_id *chipset_id)
{
  if ( didvid.vid != chipset_id->vendor_id )
    return 0;

  if ( didvid.did != chipset_id->device_id )
    return 0;

  /* If RevisionIdMask is 0, the RevisionId field must exactly match the
   * TXT.DIDVID.RID field. */
  if ( (chipset_id->flags & GRUB_TXT_ACM_REVISION_ID_MASK) == 0 &&
       ( didvid.rid == chipset_id->revision_id ) )
    return 1;

  /* If RevisionIdMask is 1, the RevisionId field is a bitwise mask that can be
   * used to test for any bits set in the TXT.DIDVID.RID field. If any bits are
   * set, the RevisionId is a match. */
  if ( (chipset_id->flags & GRUB_TXT_ACM_REVISION_ID_MASK) != 0 &&
       ( didvid.rid & chipset_id->revision_id ) != 0 )
    return 1;

  return 0;
}

int
grub_txt_acmod_match_platform (struct grub_txt_acm_header *hdr)
{
  union grub_txt_didvid didvid;
  grub_uint32_t fms, ign, i, ver;
  grub_uint64_t platform_id;
  struct grub_txt_acm_chipset_id_list *chipset_id_list;
  struct grub_txt_acm_chipset_id *chipset_id;
  struct grub_txt_acm_processor_id_list *proc_id_list;
  struct grub_txt_acm_processor_id *proc_id;
  struct grub_txt_acm_info_table *info_table;

  /* This fn assumes that the ACM has already passed the is_acmod() checks */
  info_table = get_acmod_info_table (hdr);
  if ( info_table == NULL )
    return 0;

  /* Get chipset fusing, device, and vendor id info */
  didvid.value = grub_txt_reg_pub_read64 (GRUB_TXT_DIDVID);

  ver = grub_txt_reg_pub_read32 (GRUB_TXT_VER_QPIIF);
  if ( ver == 0xffffffff || ver == 0x00 ) /* Old CPU, need to use VER.FSBIF */
    ver = grub_txt_reg_pub_read32 (GRUB_TXT_VER_FSBIF);

  grub_dprintf ("slaunch", "chipset production fused: %s, "
		"chipset vendor: 0x%x, device: 0x%x, revision: 0x%x\n",
		(ver & GRUB_TXT_VERSION_PROD_FUSED) ? "yes" : "no" , didvid.vid,
		didvid.did, didvid.rid);

  grub_cpuid (1, fms, ign, ign, ign);
  platform_id = grub_rdmsr (GRUB_MSR_X86_PLATFORM_ID);

  grub_dprintf ("slaunch", "processor family/model/stepping: 0x%x, "
		"platform id: 0x%" PRIxGRUB_UINT64_T "\n", fms, platform_id);

  /*
   * Check if chipset fusing is same. Note the DEBUG.FUSE bit in the version
   * is 0 when debug fused so the logic below checking a mismatch is valid.
   */
  if ( !!(ver & GRUB_TXT_VERSION_PROD_FUSED) ==
       !!(hdr->flags & GRUB_TXT_ACM_FLAG_DEBUG_SIGNED) )
    {
      grub_error (GRUB_ERR_BAD_DEVICE, N_("production/debug mismatch between chipset and ACM"));
      return 0;
    }

  /* Check if chipset vendor/device/revision IDs match */
  chipset_id_list = get_acmod_chipset_list (hdr);
  if ( chipset_id_list == NULL )
    return 0;

  grub_dprintf ("slaunch", "%d SINIT ACM chipset id entries:\n", chipset_id_list->count);

  chipset_id = (struct grub_txt_acm_chipset_id *) ((grub_addr_t)chipset_id_list + sizeof (chipset_id_list->count));
  for (i = 0; i < chipset_id_list->count; i++, chipset_id++)
    {
      grub_dprintf ("slaunch", "  vendor: 0x%x, device: 0x%x, flags: 0x%x, "
		    "revision: 0x%x, extended: 0x%x\n", chipset_id->vendor_id,
		    chipset_id->device_id, chipset_id->flags,
		    chipset_id->revision_id, chipset_id->extended_id);

      if ( didvid_matches ( didvid, chipset_id) )
	break;
    }

  if ( i >= chipset_id_list->count )
    {
      /*
       * Version 9 introduces flexible ACM information table format, not yet
       * supported by this code.
       *
       * TXT spec says that 9 will be the final version and further changes will
       * be reflected elsewhere, but check for higher values too in case they
       * change their mind.
       */
      if ( info_table->version >= 9 )
	grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		    N_("chipset id mismatch, flexible ACM info list may contain"
		       " matching entry but it isn't yet supported by code"));
      else
	grub_error (GRUB_ERR_BAD_DEVICE, N_("chipset id mismatch"));

      return 0;
    }

  /*
   * Unfortunately the spec isn't too clear on what the changes to the info
   * table were, across the different versions, but an old version of the entire
   * spec document shows that the processor table field didn't exist when the
   * latest version of the info table was 3.
   */
  if ( info_table->version < 4 )
    return 1;

  /* Check if processor family/model/stepping and platform IDs match */
  proc_id_list = get_acmod_processor_list(hdr);
  if ( proc_id_list == NULL )
    return 0;

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
      grub_error (GRUB_ERR_BAD_DEVICE, N_("processor id mismatch"));
      return 0;
    }

  return 1;
}

/*
 * Choose between the BIOS-provided and user-provided SINIT ACMs, and copy the
 * chosen module to the SINIT memory.
 */
struct grub_txt_acm_header *
grub_txt_sinit_select (struct grub_txt_acm_header *sinit)
{
  struct grub_txt_acm_header *bios_sinit;
  void *sinit_region_base;
  grub_uint32_t sinit_size, sinit_region_size;

  sinit_region_base = (void *)(grub_addr_t) grub_txt_reg_pub_read32 (GRUB_TXT_SINIT_BASE);
  sinit_region_size = (grub_uint32_t) grub_txt_reg_pub_read32 (GRUB_TXT_SINIT_SIZE);

  grub_dprintf ("slaunch", "TXT.SINIT.BASE: %p\nTXT.SINIT.SIZE: 0x%"
		PRIxGRUB_UINT32_T "\n", sinit_region_base, sinit_region_size);

  if (sinit_region_base == NULL)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("no SINIT ACM final resting place"));
      return NULL;
    }

  if ( ((grub_addr_t) sinit_region_base & ((1 << GRUB_PAGE_SHIFT) - 1)) != 0 )
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("SINIT ACM base not properly aligned"));
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

  if (grub_mul (sinit->size, 4, &sinit_size))
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("SINIT ACM size in bytes overflows"));
      return NULL;
    }

  if (sinit_size > sinit_region_size)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY,
		  N_("SINIT ACM does not fit into final resting place: 0x%"
		  PRIxGRUB_UINT32_T "\n"), sinit_size);
      return NULL;
    }

  grub_memcpy (sinit_region_base, sinit, sinit_size);

  return sinit_region_base;
}
