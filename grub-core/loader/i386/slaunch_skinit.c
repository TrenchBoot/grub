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
#include <grub/crypto.h>

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

#define LZ_TAG_CLASS_MASK       0xF0

/* Tags with no particular class */
#define LZ_TAG_NO_CLASS         0x00
#define LZ_TAG_END              0x00
#define LZ_TAG_SETUP_INDIRECT   0x01
#define LZ_TAG_TAGS_SIZE        0x0F  /* Always first */

/* Tags specifying kernel type */
#define LZ_TAG_BOOT_CLASS       0x10
#define LZ_TAG_BOOT_LINUX       0x10
#define LZ_TAG_BOOT_MB2         0x11

/* Tags specific to TPM event log */
#define LZ_TAG_EVENT_LOG_CLASS  0x20
#define LZ_TAG_EVENT_LOG        0x20
#define LZ_TAG_LZ_HASH          0x21

struct lz_tag_hdr {
  grub_uint8_t type;
  grub_uint8_t len;
} __attribute__ (( packed ));

struct lz_tag_tags_size {
  struct lz_tag_hdr hdr;
  grub_uint16_t size;
} __attribute__ (( packed ));

struct lz_tag_boot_linux {
  struct lz_tag_hdr hdr;
  grub_uint32_t zero_page;
} __attribute__ (( packed ));

struct lz_tag_boot_mb2 {
  struct lz_tag_hdr hdr;
  grub_uint32_t mbi;
	grub_uint32_t kernel_entry;
  grub_uint32_t kernel_size;
} __attribute__ (( packed ));

struct lz_tag_evtlog {
  struct lz_tag_hdr hdr;
  grub_uint32_t address;
  grub_uint32_t size;
} __attribute__ (( packed ));

struct lz_tag_hash {
  struct lz_tag_hdr hdr;
  grub_uint16_t algo_id;
  grub_uint8_t digest[];
} __attribute__ (( packed ));

/* extensible setup indirect data node */
struct setup_indirect {
  grub_uint32_t type;
  grub_uint32_t reserved;  /* Reserved, must be set to zero. */
  grub_uint64_t len;
  grub_uint64_t addr;
} __attribute__ (( packed ));

/* extensible setup data list node */
struct setup_data {
  grub_uint64_t next;
  grub_uint32_t type;
  grub_uint32_t len;
  struct setup_indirect indirect;
} __attribute__ (( packed ));

struct lz_tag_setup_indirect {
  struct lz_tag_hdr hdr;
  struct setup_data data;
} __attribute__ (( packed ));

static inline struct lz_tag_tags_size *get_bootloader_data_addr (
    struct grub_slaunch_module *mod)
{
  grub_uint16_t *ptr = (grub_uint16_t *)mod->addr;
  return (struct lz_tag_tags_size *)(mod->addr + ptr[1]);
}

static inline void *next_tag(struct lz_tag_tags_size *tags)
{
  return (void *)(((grub_uint8_t *)tags) + tags->size);
}

grub_err_t
grub_slaunch_boot_skinit (struct grub_slaunch_params *slparams,
                          grub_uint64_t *old_setup_data)
{
  if (grub_slaunch_get_modules()) {
    grub_uint64_t phys_base = grub_slaunch_get_modules()->target;
    struct lz_tag_tags_size *tags = get_bootloader_data_addr(grub_slaunch_get_modules());
    grub_uint32_t *apic = (grub_uint32_t *)0xfee00300ULL;
    struct drtm_t *drtm = get_drtm_acpi_table();

    grub_printf ("real_mode_target: 0x%x\r\n",
                  slparams->real_mode_target);
    grub_printf ("prot_mode_target: 0x%x\r\n",
                  slparams->prot_mode_target);
    grub_printf ("params: %p\r\n", slparams->params);

    /* Tags header */
    tags->hdr.type = LZ_TAG_TAGS_SIZE;
    tags->hdr.len = sizeof(struct lz_tag_tags_size);
    tags->size = sizeof(struct lz_tag_tags_size);

    /* Hashes of LZ */
    {
      grub_uint8_t buff[64];  /* SHA1 ctx is smaller */
      struct lz_tag_hash *h = next_tag(tags);
      h->hdr.type = LZ_TAG_LZ_HASH;
      h->hdr.len = sizeof(struct lz_tag_hash) + GRUB_MD_SHA256->mdlen;
      h->algo_id = 0x000B;
      GRUB_MD_SHA256->init(buff);
      GRUB_MD_SHA256->write(buff, grub_slaunch_get_modules()->addr,
            (grub_addr_t)tags - (grub_addr_t)grub_slaunch_get_modules()->addr);
      GRUB_MD_SHA256->final(buff);
      grub_memcpy(h->digest, GRUB_MD_SHA256->read(buff), GRUB_MD_SHA256->mdlen);
      tags->size += h->hdr.len;

      h = next_tag(tags);
      h->hdr.type = LZ_TAG_LZ_HASH;
      h->hdr.len = sizeof(struct lz_tag_hash) + GRUB_MD_SHA1->mdlen;
      h->algo_id = 0x0004;
      GRUB_MD_SHA1->init(buff);
      GRUB_MD_SHA1->write(buff, grub_slaunch_get_modules()->addr,
            (grub_addr_t)tags - (grub_addr_t)grub_slaunch_get_modules()->addr);
      GRUB_MD_SHA1->final(buff);
      grub_memcpy(h->digest, GRUB_MD_SHA1->read(buff), GRUB_MD_SHA1->mdlen);
      tags->size += h->hdr.len;
    }

    /* Boot protocol data */
    struct lz_tag_boot_linux *b = next_tag(tags);
    b->hdr.type = LZ_TAG_BOOT_LINUX;
    b->hdr.len = sizeof(struct lz_tag_boot_linux);
    b->zero_page = (grub_uint32_t)slparams->real_mode_target;
    tags->size += b->hdr.len;

    if (drtm) {
      struct lz_tag_evtlog *e = next_tag(tags);
      e->hdr.type = LZ_TAG_EVENT_LOG;
      e->hdr.len = sizeof(struct lz_tag_evtlog);
      e->address = drtm->Log_Area_Start;
      e->size = drtm->Log_Area_Length;
      tags->size += e->hdr.len;
    }

    if (1) {
      grub_printf("%s:%d\n", __func__, __LINE__);
      struct lz_tag_setup_indirect *i = next_tag(tags);
      i->hdr.type = LZ_TAG_SETUP_INDIRECT;
      i->hdr.len = sizeof(struct lz_tag_setup_indirect);
      grub_printf("%s:%d\n", __func__, __LINE__);
      i->data.next = *old_setup_data;
      grub_printf("%s:%d\n", __func__, __LINE__);
      i->data.type = (1 << 31);
      i->data.len = sizeof(struct setup_indirect);
      i->data.indirect.type = (1 << 31) | 7;
      i->data.indirect.addr = phys_base;
      i->data.indirect.len = 0x10000;
      grub_printf("%s:%d\n", __func__, __LINE__);
      tags->size += i->hdr.len;
      grub_printf("%s:%d\n", __func__, __LINE__);
      *old_setup_data = (grub_uint64_t) phys_base + ((grub_addr_t)&i->data - (grub_addr_t)grub_slaunch_get_modules()->addr);
      grub_printf("%s:%d\n", __func__, __LINE__);
    }


    /* Mark end of tags */
    struct lz_tag_hdr *end = next_tag(tags);
    end->type = LZ_TAG_END;
    end->len = sizeof(struct lz_tag_hdr);
    tags->size += end->len;

    grub_printf ("broadcasting INIT\r\n");
    *apic = 0x000c0500;               // INIT, all excluding self

    grub_printf ("grub_tis_init\r\n");
    grub_tis_init();
    grub_printf ("grub_tis_request_locality\r\n");
    grub_tis_request_locality(0xff);  // relinquish all localities

    grub_printf("Invoke SKINIT\r\n");
    return grub_relocator_skinit_boot (slparams->relocator, grub_slaunch_get_modules()->target, 0);
  } else {
    grub_printf("Secure Loader module not loaded, run slaunch_module\r\n");
  }
  return GRUB_ERR_NONE;
}

grub_err_t
grub_slaunch_mb2_boot (struct grub_relocator *rel, struct grub_relocator32_state state)
{
  struct lz_tag_tags_size *tags = get_bootloader_data_addr(grub_slaunch_get_modules());
  grub_uint32_t *apic = (grub_uint32_t *)0xfee00300ULL;
  struct drtm_t *drtm = get_drtm_acpi_table();

  /* Tags header */
  tags->hdr.type = LZ_TAG_TAGS_SIZE;
  tags->hdr.len = sizeof(struct lz_tag_tags_size);
  tags->size = sizeof(struct lz_tag_tags_size);

  /* Hashes of LZ */
  {
    grub_uint8_t buff[64];  /* SHA1 ctx is smaller */
    struct lz_tag_hash *h = next_tag(tags);
    h->hdr.type = LZ_TAG_LZ_HASH;
    h->hdr.len = sizeof(struct lz_tag_hash) + GRUB_MD_SHA256->mdlen;
    h->algo_id = 0x000B;
    GRUB_MD_SHA256->init(buff);
    GRUB_MD_SHA256->write(buff, grub_slaunch_get_modules()->addr,
          (grub_addr_t)tags - (grub_addr_t)grub_slaunch_get_modules()->addr);
    GRUB_MD_SHA256->final(buff);
    grub_memcpy(h->digest, GRUB_MD_SHA256->read(buff), GRUB_MD_SHA256->mdlen);
    tags->size += h->hdr.len;

    h = next_tag(tags);
    h->hdr.type = LZ_TAG_LZ_HASH;
    h->hdr.len = sizeof(struct lz_tag_hash) + GRUB_MD_SHA1->mdlen;
    h->algo_id = 0x0004;
    GRUB_MD_SHA1->init(buff);
    GRUB_MD_SHA1->write(buff, grub_slaunch_get_modules()->addr,
          (grub_addr_t)tags - (grub_addr_t)grub_slaunch_get_modules()->addr);
    GRUB_MD_SHA1->final(buff);
    grub_memcpy(h->digest, GRUB_MD_SHA1->read(buff), GRUB_MD_SHA1->mdlen);
    tags->size += h->hdr.len;
  }

  /* Boot protocol data */
  struct lz_tag_boot_mb2 *b = next_tag(tags);
  b->hdr.type = LZ_TAG_BOOT_MB2;
  b->hdr.len = sizeof(struct lz_tag_boot_mb2);
  b->mbi = state.ebx;
  b->kernel_entry = state.eip;
  // TODO: save kernel size for measuring in LZ for non-ELF files?
  b->kernel_size = 0;
  tags->size += b->hdr.len;

  if (drtm) {
    struct lz_tag_evtlog *e = next_tag(tags);
    e->hdr.type = LZ_TAG_EVENT_LOG;
    e->hdr.len = sizeof(struct lz_tag_evtlog);
    e->address = drtm->Log_Area_Start;
    e->size = drtm->Log_Area_Length;
    tags->size += e->hdr.len;
  }

  /* Mark end of tags */
  struct lz_tag_hdr *end = next_tag(tags);
  end->type = LZ_TAG_END;
  end->len = sizeof(struct lz_tag_hdr);
  tags->size += end->len;

  grub_dprintf ("slaunch", "broadcasting INIT\r\n");
  *apic = 0x000c0500;               // INIT, all excluding self

  grub_dprintf ("slaunch", "grub_tis_init\r\n");
  grub_tis_init();
  grub_dprintf ("slaunch", "grub_tis_request_locality\r\n");
  grub_tis_request_locality(0xff);  // relinquish all localities

  grub_dprintf("slaunch", "Invoke SKINIT\r\n");
  return grub_relocator_skinit_boot (rel, grub_slaunch_get_modules()->target, 0);
}
