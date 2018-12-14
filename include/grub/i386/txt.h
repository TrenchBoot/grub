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
 *
 *  Intel TXT definitions header file.
 */

#ifndef GRUB_TXT_H
#define GRUB_TXT_H 1

#include <grub/types.h>
#include <grub/cpu/mmio.h>

/* Intel TXT Software Developers Guide */

/* Appendix A TXT Execution Technology Authenticated Code Modules */
/* A.1 Authenticated Code Module Format */

#define GRUB_TXT_ACM_MODULE_TYPE		2

#define GRUB_TXT_ACM_MODULE_SUB_TYPE_TXT_ACM	0
#define GRUB_TXT_ACM_MODULE_SUB_TYPE_S_ACM	1

#define GRUB_TXT_ACM_HEADER_LEN_0_0		161
#define GRUB_TXT_ACM_HEADER_LEN_3_0		224

#define GRUB_TXT_ACM_HEADER_VERSION_0_0		0x0000
#define GRUB_TXT_ACM_HEADER_VERSION_3_0		0x0300

#define GRUB_TXT_ACM_FLAG_PREPRODUCTION		(1<<14)
#define GRUB_TXT_ACM_FLAG_DEBUG_SIGNED		(1<<15)

#define GRUB_TXT_ACM_MODULE_VENDOR_INTEL	0x00008086

struct grub_txt_acm_header
{
  grub_uint16_t module_type;
  grub_uint16_t module_sub_type;
  grub_uint32_t header_len;
  grub_uint32_t header_version;
  grub_uint16_t chipset_id;
  grub_uint16_t flags;
  grub_uint32_t module_vendor;
  grub_uint32_t date; /* e.g 20131231H == December 31, 2013 */
  grub_uint32_t size; /* multiples of 4 bytes */
  grub_uint16_t txt_svn;
  grub_uint16_t se_svn;
  grub_uint32_t code_control;
  grub_uint32_t error_entry_point;
  grub_uint32_t gdt_limit;
  grub_uint32_t gdt_base;
  grub_uint32_t seg_sel;
  grub_uint32_t entry_point;
  grub_uint8_t reserved2[64];
  grub_uint32_t key_size;
  grub_uint32_t scratch_size;
  /* RSA Pub Key and Signature */
} GRUB_PACKED;

/* Appendix B SMX Interaction with Platform */
/* B.1 Intel Trusted Execution Technology Configuration Registers */

#ifdef __x86_64__
#define GRUB_TXT_PUB_CONFIG_REGS	0xfed30000ULL
#define GRUB_TXT_PRIV_CONFIG_REGS	0xfed20000ULL
#else
#define GRUB_TXT_PUB_CONFIG_REGS	0xfed30000
#define GRUB_TXT_PRIV_CONFIG_REGS	0xfed20000
#endif

#define GRUB_TXT_STS			0x0000
#define GRUB_TXT_ESTS			0x0008
#define GRUB_TXT_ERRORCODE		0x0030
#define GRUB_TXT_CMD_RESET		0x0038
#define GRUB_TXT_CMD_CLOSE_PRIVATE	0x0048
#define GRUB_TXT_VER_FSBIF		0x0100
#define GRUB_TXT_DIDVID			0x0110
#define GRUB_TXT_VER_QPIIF		0x0200
#define GRUB_TXT_CMD_UNLOCK_MEM_CONFIG	0x0218
#define GRUB_TXT_SINIT_BASE		0x0270
#define GRUB_TXT_SINIT_SIZE		0x0278
#define GRUB_TXT_MLE_JOIN		0x0290
#define GRUB_TXT_HEAP_BASE		0x0300
#define GRUB_TXT_HEAP_SIZE		0x0308
#define GRUB_TXT_MSEG_BASE		0x0310
#define GRUB_TXT_MSEG_SIZE		0x0318
#define GRUB_TXT_DPR			0x0330
#define GRUB_TXT_CMD_OPEN_LOCALITY1	0x0380
#define GRUB_TXT_CMD_CLOSE_LOCALITY1	0x0388
#define GRUB_TXT_CMD_OPEN_LOCALITY2	0x0390
#define GRUB_TXT_CMD_CLOSE_LOCALITY2	0x0398
#define GRUB_TXT_PUBLIC_KEY		0x0400
#define GRUB_TXT_CMD_SECRETS		0x08e0
#define GRUB_TXT_CMD_NO_SECRETS		0x08e8
#define GRUB_TXT_E2STS			0x08f0

/* Appendix C Intel TXT Heap Memory */

/* Ext Data Structs */

struct grub_txt_heap_uuid
{
  grub_uint32_t data1;
  grub_uint16_t data2;
  grub_uint16_t data3;
  grub_uint16_t data4;
  grub_uint8_t data5[6];
} GRUB_PACKED;

struct grub_txt_heap_ext_data_element
{
  grub_uint32_t type;
  grub_uint32_t size;
  /* Data */
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_END			0

struct grub_txt_heap_end_element
{
  grub_uint32_t type;
  grub_uint32_t size;
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_BIOS_SPEC_VER	1

struct grub_txt_heap_bios_spec_ver_element
{
  grub_uint16_t spec_ver_major;
  grub_uint16_t spec_ver_minor;
  grub_uint16_t spec_ver_revision;
} HEAP_BIOS_SPEC_VER_ELEMENT;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_ACM			2

struct grub_txt_heap_acm_element
{
  grub_uint32_t num_acms;
  /* Array of num_acms grub_uint64_t addresses */
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_STM			3

struct grub_txt_heap_stm_element
{
  /* STM specific BIOS properties */
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_CUSTOM		4

struct grub_txt_heap_custom_element
{
  struct grub_txt_heap_uuid uuid;
  /* Vendor Data */
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR	5

struct grub_txt_heap_event_log_element
{
  grub_uint64_t event_log_phys_addr;
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_MADT			6

struct grub_txt_heap_madt_element
{
  /* Copy of ACPI MADT table */
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1	8

struct grub_txt_heap_event_log_pointer2_1_element
{
  grub_uint64_t phys_addr;
  grub_uint32_t allocated_event_container_size;
  grub_uint32_t first_record_offset;
  grub_uint32_t next_record_offset;
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_MCFG			8

struct grub_txt_heap_mcfg_element
{
  /* Copy of ACPI MCFG table */
} GRUB_PACKED;

/* TXT Heap Tables */

struct grub_txt_bios_data
{
  grub_uint32_t version; /* Currently 5 for TPM 1.2 and 6 for TPM 2.0 */
  grub_uint32_t bios_sinit_size;
  grub_uint64_t reserved1;
  grub_uint64_t reserved22;
  grub_uint32_t num_logical_procs;
  /* Versions >= 5 with updates in version 6 */
  grub_uint32_t sinit_flags;
  grub_uint32_t mle_flags;
  /* Versions >= 4 */
  /* Ext Data Elements */
} GRUB_PACKED;

#define GRUB_TXT_MAX_EVENT_LOG_SIZE			5*4*1024   /* 4k*5 */

struct grub_txt_os_mle_data
{
  grub_uint32_t zero_page_addr;
  grub_uint8_t  event_log_buffer[GRUB_TXT_MAX_EVENT_LOG_SIZE];
} GRUB_PACKED;

struct grub_txt_os_sinit_data
{
  grub_uint32_t version; /* Currently 6 for TPM 1.2 and 7 for TPM 2.0 */
  grub_uint32_t flags;
  grub_uint64_t mle_ptab;
  grub_uint64_t mle_size;
  grub_uint64_t mle_hdr_base;
  grub_uint64_t vtd_pmr_lo_base;
  grub_uint64_t vtd_pmr_lo_size;
  grub_uint64_t vtd_pmr_hi_base;
  grub_uint64_t vtd_pmr_hi_size;
  grub_uint64_t lcp_po_base;
  grub_uint64_t lcp_po_size;
  grub_uint32_t capabilities;
  /* Version = 5 */
  grub_uint64_t    efi_rsdt_ptr;
  /* Versions >= 6 */
  /* Ext Data Elements */
} GRUB_PACKED;

struct grub_txt_sinit_mle_data
{
  grub_uint32_t version;             /* Current values are 6 through 9 */
  /* Versions <= 8 */
  grub_uint8_t bios_acm_id[20];
  grub_uint32_t edx_senter_flags;
  grub_uint64_t mseg_valid;
  grub_uint8_t sinit_hash[20];
  grub_uint8_t mle_hash[20];
  grub_uint8_t stm_hash[20];
  grub_uint8_t lcp_policy_hash[20];
  grub_uint32_t lcp_policy_control;
  /* Versions >= 7 */
  grub_uint32_t rlp_wakeup_addr;
  grub_uint32_t reserved;
  grub_uint32_t num_of_sinit_mdrs;
  grub_uint32_t sinit_mdrs_table_offset;
  grub_uint32_t sinit_vtd_dmar_table_size;
  grub_uint32_t sinit_vtd_dmar_table_offset;
  /* Versions >= 8 */
  grub_uint32_t processor_scrtm_status;
  /* Versions >= 9 */
  /* Ext Data Elements */
} GRUB_PACKED;

struct grub_txt_sinit_memory_descriptor_records
{
  grub_uint64_t address;
  grub_uint64_t length;
  grub_uint8_t type;
  grub_uint8_t reserved[7];
} GRUB_PACKED;

/* Section 2 Measured Launch Environment */
/* 2.1 MLE Architecture Overview */
/* Table 1. MLE Header structure */

struct grub_txt_mle_header
{
  grub_uint8_t uuid[16];
  grub_uint32_t header_len;
  grub_uint32_t version;
  grub_uint32_t entry_point;
  grub_uint32_t first_valid_page;
  grub_uint32_t mle_start;
  grub_uint32_t mle_end;
  grub_uint32_t capabilities;
  grub_uint32_t cmdline_start;
  grub_uint32_t cmdline_end;
} GRUB_PACKED;

/* TXT register and heap access */

static inline grub_uint64_t
grub_txt_read_reg (grub_uint32_t reg, grub_uint8_t read_public)
{
  grub_uint8_t *addr = (grub_uint8_t*)(read_public ? GRUB_TXT_PUB_CONFIG_REGS :
                                       GRUB_TXT_PRIV_CONFIG_REGS);
  return grub_readq(addr + reg);
}

static inline void
grub_txt_write_reg (grub_uint32_t reg, grub_uint64_t val, grub_uint8_t read_public)
{
  grub_uint8_t *addr = (grub_uint8_t*)(read_public ? GRUB_TXT_PUB_CONFIG_REGS :
                                       GRUB_TXT_PRIV_CONFIG_REGS);
  grub_writeq(val, addr + reg);
}

static inline grub_uint8_t*
grub_txt_get_heap (void)
{
#ifdef __x86_64__
  return (grub_uint8_t*)grub_txt_read_reg (GRUB_TXT_HEAP_BASE, 1);
#else
  return (grub_uint8_t*)(grub_uint32_t)grub_txt_read_reg (GRUB_TXT_HEAP_BASE, 1);
#endif
}

static inline grub_uint64_t
grub_txt_bios_data_size (grub_uint8_t *heap)
{
  return *(grub_uint64_t *)heap;
}

static inline struct grub_txt_bios_data*
grub_txt_bios_data_start (grub_uint8_t *heap)
{
  return (struct grub_txt_bios_data*)(heap + sizeof (grub_uint64_t));
}

static inline grub_uint64_t
grub_txt_os_mle_data_size (grub_uint8_t *heap)
{
  return *(grub_uint64_t *)(heap + grub_txt_bios_data_size (heap));
}

static inline struct grub_txt_os_mle_data*
grub_txt_os_mle_data_start (grub_uint8_t *heap)
{
  return (struct grub_txt_os_mle_data*)(heap + grub_txt_bios_data_size (heap) +
                                        sizeof (grub_uint64_t));
}

static inline grub_uint64_t
grub_txt_os_sinit_data_size (grub_uint8_t *heap)
{
  return *(grub_uint64_t *)(heap + grub_txt_bios_data_size (heap) +
                            grub_txt_os_mle_data_size (heap));
}

static inline struct grub_txt_os_sinit_data *
grub_txt_os_sinit_data_start (grub_uint8_t *heap)
{
  return (struct grub_txt_os_sinit_data*)(heap +
                 grub_txt_bios_data_size (heap) +
                 grub_txt_os_mle_data_size (heap) + sizeof (grub_uint64_t));
}

static inline grub_uint64_t
grub_txt_sinit_mle_data_size (grub_uint8_t *heap)
{
  return *(grub_uint64_t *)(heap + grub_txt_bios_data_size (heap) +
                            grub_txt_os_mle_data_size (heap) +
                            grub_txt_os_sinit_data_size (heap));
}

static inline struct grub_txt_sinit_mle_data*
grub_txt_sinit_mle_data_start (grub_uint8_t *heap)
{
  return (struct grub_txt_sinit_mle_data*)(heap +
                 grub_txt_bios_data_size (heap) +
                 grub_txt_os_mle_data_size (heap) +
                 grub_txt_os_sinit_data_size (heap) +
                 sizeof (grub_uint64_t));
}

/* Intel 64 and IA-32 Architectures Software Developer’s Manual */
/* Volume 2 (2A, 2B, 2C & 2D): Instruction Set Reference, A-Z */

/* CHAPTER 6 SAFER MODE EXTENSIONS REFERENCE */

#define GRUB_SMX_LEAF_CAPABILITIES	0
#define GRUB_SMX_LEAF_UNDEFINED		1
#define GRUB_SMX_LEAF_ENTERACCS		2
#define GRUB_SMX_LEAF_EXITAC 		3
#define GRUB_SMX_LEAF_SENTER		4
#define GRUB_SMX_LEAF_SEXIT		5
#define GRUB_SMX_LEAF_PARAMETERS	6
#define GRUB_SMX_LEAF_SMCTRL		7
#define GRUB_SMX_LEAF_WAKEUP		8

#define GRUB_SMX_CAPABILITY_CHIPSET_PRESENT	(1<<0)
#define GRUB_SMX_CAPABILITY_UNDEFINED		(1<<1)
#define GRUB_SMX_CAPABILITY_ENTERACCS		(1<<2)
#define GRUB_SMX_CAPABILITY_EXITAC		(1<<3)
#define GRUB_SMX_CAPABILITY_SENTER		(1<<4)
#define GRUB_SMX_CAPABILITY_SEXIT		(1<<5)
#define GRUB_SMX_CAPABILITY_PARAMETERS		(1<<6)
#define GRUB_SMX_CAPABILITY_SMCTRL		(1<<7)
#define GRUB_SMX_CAPABILITY_WAKEUP		(1<<8)
#define GRUB_SMX_CAPABILITY_EXTENDED_LEAFS	(1<<31)

static inline grub_uint32_t
grub_txt_getsec_capabilities (grub_uint32_t index)
{
  grub_uint32_t caps;

  __asm__ __volatile__ (".byte 0x0f,0x37\n"
                        : "=a" (caps)
                        : "a" (GRUB_SMX_LEAF_CAPABILITIES), "b" (index));
  return caps;
}

static inline void
grub_txt_getsec_enteraccs (grub_uint32_t acm_phys_addr, grub_uint32_t acm_size)
{
  __asm__ __volatile__ (".byte 0x0f,0x37\n" :
                        : "a" (GRUB_SMX_LEAF_ENTERACCS),
                          "b" (acm_phys_addr), "c" (acm_size));
}

static inline void
grub_txt_getsec_exitac (grub_uint32_t near_jump)
{
  __asm__ __volatile__ (".byte 0x0f,0x37\n" :
                        : "a" (GRUB_SMX_LEAF_EXITAC), "b" (near_jump));
}

static inline void
grub_txt_getsec_senter (grub_uint32_t acm_phys_addr, grub_uint32_t acm_size)
{
  __asm__ __volatile__ (".byte 0x0f,0x37\n" :
                        : "a" (GRUB_SMX_LEAF_SENTER),
                          "b" (acm_phys_addr), "c" (acm_size));
}

static inline void
grub_txt_getsec_sexit (void)
{
  __asm__ __volatile__ (".byte 0x0f,0x37\n" : : "a" (GRUB_SMX_LEAF_SEXIT));
}

#define GRUB_SMX_PARAMETER_TYPE_MASK	0x1f

static inline void
grub_txt_getsec_parameters (grub_uint32_t index, grub_uint32_t *eax_out,
                            grub_uint32_t *ebx_out, grub_uint32_t *ecx_out)
{
  if (!eax_out || !ebx_out || !ecx_out)
    return;

  __asm__ __volatile__ (".byte 0x0f,0x37\n"
                        : "=a" (*eax_out), "=b" (*ebx_out), "=c" (*ecx_out)
                        : "a" (GRUB_SMX_LEAF_PARAMETERS), "b" (index));
}

static inline void
grub_txt_getsec_smctrl (void)
{
  __asm__ __volatile__ (".byte 0x0f,0x37\n" :
                        : "a" (GRUB_SMX_LEAF_SMCTRL), "b" (0));
}

static inline void
grub_txt_getsec_wakeup (void)
{
  __asm__ __volatile__ (".byte 0x0f,0x37\n" : : "a" (GRUB_SMX_LEAF_WAKEUP));
}

#endif
