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
 *
 *  Intel TXT definitions header file.
 */

#ifndef GRUB_TXT_H
#define GRUB_TXT_H 1

#include <grub/err.h>
#include <grub/types.h>
#include <grub/i386/memory.h>
#include <grub/i386/mmio.h>
#include <grub/i386/slaunch.h>

/* Intel TXT Software Developers Guide Revision 017.4 */

/* Chapter 2, Table 4. MLE/SINIT Capabilities Field Bit Definitions */
#define GRUB_TXT_PLATFORM_TYPE_LEGACY		0
#define GRUB_TXT_PLATFORM_TYPE_CLIENT		1
#define GRUB_TXT_PLATFORM_TYPE_SERVER		2
#define GRUB_TXT_PLATFORM_TYPE_RESERVED		3

#define GRUB_TXT_CAPS_GETSEC_WAKE_SUPPORT		(1<<0)
#define GRUB_TXT_CAPS_MONITOR_SUPPORT			(1<<1)
#define GRUB_TXT_CAPS_ECX_PT_SUPPORT			(1<<2)
#define GRUB_TXT_CAPS_STM_SUPPORT			(1<<3)
#define GRUB_TXT_CAPS_TPM_12_NO_LEGACY_PCR_USAGE	(1<<4)
#define GRUB_TXT_CAPS_TPM_12_AUTH_PCR_USAGE		(1<<5)  /* Must be 1 for TPM 2.0 */
#define GRUB_TXT_CAPS_PLATFORM_TYPE			(3<<6)
#define GRUB_TXT_CAPS_MAXPHYSADDR_SUPPORT		(1<<8)
#define GRUB_TXT_CAPS_TPM_20_EVTLOG_SUPPORT		(1<<9)
#define GRUB_TXT_CAPS_CBNT_SUPPORT			(1<<10)
#define GRUB_TXT_CAPS_STARTUP_ACM_SUPPORT		(7<<11) /* Reserved for MLE, must be 0 */
#define GRUB_TXT_CAPS_DMA_PROTECTION			(1<<14) /* 0 = Legacy, 1 = TPR */
/* Rest is reserved */

/* Appendix A TXT Execution Technology Authenticated Code Modules */
/* A.1 Authenticated Code Module Format */
#define GRUB_TXT_ACM_MODULE_TYPE		2

#define GRUB_TXT_ACM_MODULE_SUB_TYPE_TXT_ACM	0
#define GRUB_TXT_ACM_MODULE_SUB_TYPE_S_ACM	1

#define GRUB_TXT_ACM_FLAG_PREPRODUCTION		(1<<14)
#define GRUB_TXT_ACM_FLAG_DEBUG_SIGNED		(1<<15)

#define GRUB_TXT_ACM_MODULE_VENDOR_INTEL	0x00008086

#define GRUB_TXT_MLE_MAX_SIZE			0x40000000

#define GRUB_MLE_AP_WAKE_BLOCK_SIZE		(4 * GRUB_PAGE_SIZE)

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

/* A.1.2 ACM Information Table */
#define GRUB_TXT_ACM_UUID "\xaa\x3a\xc0\x7f\xa7\x46\xdb\x18\x2e\xac\x69\x8f\x8d\x41\x7f\x5a"

#define GRUB_TXT_ACM_CHIPSET_TYPE_BIOS		0
#define GRUB_TXT_ACM_CHIPSET_TYPE_SINIT		1
/* Revocation ACMs */
#define GRUB_TXT_ACM_CHIPSET_TYPE_BIOS_RACM	8
#define GRUB_TXT_ACM_CHIPSET_TYPE_SINIT_RACM	9

struct grub_txt_acm_info_table
{
  grub_uint8_t uuid[16];
  grub_uint8_t chipset_acm_type;
  grub_uint8_t version;
  grub_uint16_t length;
  grub_uint32_t chipset_id_list;
  grub_uint32_t os_sinit_data_ver;
  grub_uint32_t min_mle_header_ver;
  grub_uint32_t capabilities;
  grub_uint32_t acm_version_revision;
  grub_uint32_t processor_id_list;
  /* Version >= 5 */
  grub_uint32_t tpm_info_list;
} GRUB_PACKED;

struct grub_txt_acm_chipset_id_list
{
  grub_uint32_t count;
        /* Array of chipset ID structs */
} GRUB_PACKED;

#define GRUB_TXT_ACM_REVISION_ID_MASK	(1<<0)

struct grub_txt_acm_chipset_id
{
  grub_uint32_t flags;
  grub_uint16_t vendor_id;
  grub_uint16_t device_id;
  grub_uint16_t revision_id;
  grub_uint16_t reserved;
  grub_uint32_t extended_id;
} GRUB_PACKED;

struct grub_txt_acm_processor_id_list
{
  grub_uint32_t count;
        /* Array of processor ID structs */
} GRUB_PACKED;

struct grub_txt_acm_processor_id
{
  grub_uint32_t fms;
  grub_uint32_t fms_mask;
  grub_uint64_t platform_id;
  grub_uint64_t platform_mask;
} GRUB_PACKED;

struct grub_txt_acm_tpm_info
{
  grub_uint32_t capabilities;
  grub_uint16_t count;
  /* List of supported hash algorithm per TPM2 spec */
} GRUB_PACKED;

/* Appendix B SMX Interaction with Platform */
/* B.1 Intel Trusted Execution Technology Configuration Registers */

#ifdef __x86_64__
#define GRUB_TXT_CFG_REGS_PUB	0xfed30000ULL
#else
#define GRUB_TXT_CFG_REGS_PUB	0xfed30000
#endif

#define GRUB_TXT_STS			0x0000
#define GRUB_TXT_ESTS			0x0008
#define GRUB_TXT_ERRORCODE		0x0030
#define GRUB_TXT_CMD_RESET		0x0038
#define GRUB_TXT_CMD_CLOSE_PRIVATE	0x0048
/* VER_FSBIF is considered deprecated, but some CPUs still use it */
#define GRUB_TXT_VER_FSBIF		0x0100
#define GRUB_TXT_DIDVID			0x0110
#define GRUB_TXT_VER_QPIIF		0x0200
#define GRUB_TXT_CMD_UNLOCK_MEM_CONFIG	0x0218
#define GRUB_TXT_SINIT_BASE		0x0270
#define GRUB_TXT_SINIT_SIZE		0x0278
#define GRUB_TXT_MLE_JOIN		0x0290
#define GRUB_TXT_HEAP_BASE		0x0300
#define GRUB_TXT_HEAP_SIZE		0x0308
/* DPR is considered deprecated, but some CPUs still use it */
#define GRUB_TXT_DPR			0x0330
#define GRUB_TXT_CMD_OPEN_LOCALITY1	0x0380
#define GRUB_TXT_CMD_CLOSE_LOCALITY1	0x0388
#define GRUB_TXT_CMD_OPEN_LOCALITY2	0x0390
#define GRUB_TXT_CMD_CLOSE_LOCALITY2	0x0398
#define GRUB_TXT_PUBLIC_KEY		0x0400
#define GRUB_TXT_CMD_SECRETS		0x08e0
#define GRUB_TXT_CMD_NO_SECRETS		0x08e8
#define GRUB_TXT_E2STS			0x08f0

#define GRUB_TXT_STS_SENTER_DONE	(1 << 0)
#define GRUB_TXT_STS_SEXIT_DONE		(1 << 1)
#define GRUB_TXT_STS_MEM_CONFIG_LOCK	(1 << 6)
#define GRUB_TXT_STS_PRIVATE_OPEN	(1 << 7)
#define GRUB_TXT_STS_LOCALITY1_OPEN	(1 << 15)
#define GRUB_TXT_STS_LOCALITY2_OPEN	(1 << 16)

#define GRUB_TXT_ESTS_TXT_RESET		(1 << 0)

#define GRUB_TXT_VER_FSBIF_DEBUG_FUSE	(1 << 31)

#define GRUB_TXT_VER_QPIIF_DEBUG_FUSE	(1 << 31)

#define GRUB_TXT_E2STS_SECRETS		(1 << 1)

union grub_txt_didvid
{
  grub_uint64_t value;
  struct
  {
    grub_uint16_t vid;
    grub_uint16_t did;
    grub_uint16_t rid;
    grub_uint16_t id_ext;
  };
} GRUB_PACKED;

#define GRUB_TXT_VERSION_PROD_FUSED	(1<<31)

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

#define GRUB_TXT_HEAP_EXTDATA_TYPE_END			0

struct grub_txt_heap_end_element
{
  /* Empty, just the common header with type and size */
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_BIOS_SPEC_VER	1

struct grub_txt_heap_bios_spec_ver_element
{
  grub_uint16_t spec_ver_major;
  grub_uint16_t spec_ver_minor;
  grub_uint16_t spec_ver_revision;
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_ACM			2

struct grub_txt_heap_acm_element
{
  grub_uint32_t num_acms;
  /* Array of num_acms grub_uint64_t addresses */
  grub_uint64_t addr[];
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_STM			3

struct grub_txt_heap_stm_element
{
  /* STM specific BIOS properties */
  /* GNU extension used to counteract "error: flexible array member in a struct
   * with no named members". */
  grub_uint8_t data[0];
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_CUSTOM		4

struct grub_txt_heap_custom_element
{
  struct grub_txt_heap_uuid uuid;
  /* Vendor Data */
  grub_uint8_t data[];
} GRUB_PACKED;

/* Deprecated, but still used for TPM 1.2 */
#define GRUB_TXT_HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR	5

struct grub_txt_heap_tpm_event_log_element
{
  grub_uint64_t event_log_phys_addr;
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_MADT			6

struct grub_txt_heap_madt_element
{
  /* Copy of ACPI MADT table */
  /* GNU extension used to counteract "error: flexible array member in a struct
   * with no named members". */
  grub_uint8_t madt[0];
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1	8

struct grub_txt_heap_event_log_pointer2_1_element
{
  grub_uint64_t phys_addr;
  grub_uint32_t allocated_event_container_size;
  grub_uint32_t first_record_offset;
  grub_uint32_t next_record_offset;
} GRUB_PACKED;

#define GRUB_TXT_HEAP_EXTDATA_TYPE_MCFG			9

struct grub_txt_heap_mcfg_element
{
  /* Copy of ACPI MCFG table */
  /* GNU extension used to counteract "error: flexible array member in a struct
   * with no named members". */
  grub_uint8_t data[0];
} GRUB_PACKED;

#define GRUB_TXT_HEAP_ELEMENT_HEADER_SIZE	(2 * sizeof(grub_uint32_t))

struct grub_txt_heap_ext_data_element
{
  grub_uint32_t type;
  grub_uint32_t size; /* Must be at least 8 bytes, includes size of this struct */
  union {
    struct grub_txt_heap_end_element end;
    struct grub_txt_heap_bios_spec_ver_element bios_spec_ver;
    struct grub_txt_heap_acm_element acm;
    struct grub_txt_heap_stm_element stm;
    struct grub_txt_heap_custom_element custom;
    struct grub_txt_heap_tpm_event_log_element tpm_event_log;
    struct grub_txt_heap_madt_element madt;
    struct grub_txt_heap_event_log_pointer2_1_element event_log_pointer2_1;
    struct grub_txt_heap_mcfg_element mcfg;
  };
} GRUB_PACKED;

/* TXT Heap Tables */

struct grub_txt_bios_data
{
  grub_uint32_t version; /* Currently 5 for TPM 1.2 and 6 for TPM 2.0 */
  grub_uint32_t bios_sinit_size;
  grub_uint64_t reserved1;
  grub_uint64_t reserved2;
  grub_uint32_t num_logical_procs;
  /* Versions >= 3 */
  grub_uint32_t sinit_flags;
  /* Versions >= 5 with updates in version 6 */
  grub_uint32_t mle_flags;
  /* Versions >= 4 */
  /* Ext Data Elements */
} GRUB_PACKED;

/* GRUB SLAUNCH specific definitions OS-MLE data */
#define GRUB_SL_OS_MLE_STRUCT_VERSION	1

struct grub_slaunch_mtrr_pair
{
  grub_uint64_t mtrr_physbase;
  grub_uint64_t mtrr_physmask;
} GRUB_PACKED;

struct grub_slaunch_mtrr_state
{
  grub_uint64_t default_mem_type;
  grub_uint64_t mtrr_vcnt;
  struct grub_slaunch_mtrr_pair mtrr_pair[GRUB_SL_MAX_VARIABLE_MTRRS];
} GRUB_PACKED;

struct grub_txt_os_mle_data
{
  grub_uint32_t version;
  grub_uint32_t boot_params_addr;
  grub_uint64_t saved_misc_enable_msr;
  struct grub_slaunch_mtrr_state saved_bsp_mtrrs;
  grub_uint32_t ap_wake_block;
  grub_uint32_t ap_wake_block_size;
  grub_uint64_t evtlog_addr;
  grub_uint32_t evtlog_size;
  grub_uint8_t mle_scratch[64];
} GRUB_PACKED;

/* Table 29. OS to SINIT Data Table */
#define GRUB_TXT_PCR_EXT_MAX_AGILITY_POLICY	0
#define GRUB_TXT_PCR_EXT_MAX_PERF_POLICY	1

struct grub_txt_os_sinit_data
{
  grub_uint32_t version; /* Currently 6 for TPM 1.2 and 7 for TPM 2.0 */
  grub_uint32_t flags;   /* Version 7+ only, otherwise reserved */
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
  /* Versions >= 5 */
  /* Warning: version 5 has pointer to RSDT here, not RSDP */
  grub_uint64_t    efi_rsdp_ptr;
  /* Versions >= 6 */
  /* Ext Data Elements */
  grub_uint8_t ext_data_elts[];
} GRUB_PACKED;

struct grub_txt_sinit_mle_data
{
  grub_uint32_t version;             /* Current values are 6 through 9 */
  /* Reserved for versions >= 9, must be 0 */
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
  grub_uint32_t processor_scrtm_status;  /* Reserved for version 9 */
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
/* Table 3. MLE Header structure */

#define GRUB_TXT_MLE_UUID "\x5a\xac\x82\x90\x6f\x47\xa7\x74\x0f\x5c\x55\xa2\xcb\x51\xb6\x42"

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

struct grub_txt_heap_event_log_ptr_elt
{
  grub_uint64_t event_log_phys_addr;
} GRUB_PACKED;

struct grub_txt_heap_event_log_ptr_elt2_1
{
  grub_uint64_t phys_addr;
  grub_uint32_t allcoated_event_container_size;
  grub_uint32_t first_record_offset;
  grub_uint32_t next_record_offset;
} GRUB_PACKED;

/* TXT register and heap access */

static inline grub_uint8_t
grub_txt_reg_pub_read8 (grub_uint16_t reg)
{
  return grub_read8 (GRUB_TXT_CFG_REGS_PUB + reg);
}

static inline grub_uint32_t
grub_txt_reg_pub_read32 (grub_uint16_t reg)
{
  return grub_read32 (GRUB_TXT_CFG_REGS_PUB + reg);
}

static inline grub_uint64_t
grub_txt_reg_pub_read64 (grub_uint16_t reg)
{
  return grub_read64 (GRUB_TXT_CFG_REGS_PUB + reg);
}

static inline grub_uint8_t *
grub_txt_get_heap (void)
{
  return (grub_uint8_t *)(grub_addr_t) grub_txt_reg_pub_read32 (GRUB_TXT_HEAP_BASE);
}

static inline grub_uint32_t
grub_txt_get_heap_size (void)
{
  return grub_txt_reg_pub_read32 (GRUB_TXT_HEAP_SIZE);
}

/*
 * Each block of data on heap begins with 64-bit size field, followed by proper
 * data. Specified size includes size field, so the minimal value of that field
 * is 8. TXT SDG mentions that all sizes must be multiples of 8 bytes, but even
 * BiosData produced by code signed by Intel doesn't follow that requirement.
 * This means that we can't just cast pointer to arbitrary location on TXT heap
 * with (grub_uint64_t *), because unaligned pointer is UB.
 */
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
  return (struct grub_txt_os_mle_data*)(heap +
                                        grub_txt_bios_data_size (heap) +
                                        sizeof (grub_uint64_t));
}

static inline grub_uint64_t
grub_txt_os_sinit_data_size (grub_uint8_t *heap)
{
  return *(grub_uint64_t *)(heap +
                            grub_txt_bios_data_size (heap) +
                            grub_txt_os_mle_data_size (heap));
}

static inline struct grub_txt_os_sinit_data *
grub_txt_os_sinit_data_start (grub_uint8_t *heap)
{
  return (struct grub_txt_os_sinit_data*)(heap +
                                          grub_txt_bios_data_size (heap) +
                                          grub_txt_os_mle_data_size (heap) +
                                          sizeof (grub_uint64_t));
}

static inline grub_uint64_t
grub_txt_sinit_mle_data_size (grub_uint8_t *heap)
{
  return *(grub_uint64_t *)(heap +
                            grub_txt_bios_data_size (heap) +
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
/* Order Number: 325383-082US December 2023 */

/* CHAPTER 7 SAFER MODE EXTENSIONS REFERENCE */

/* Table 7-2. GETSEC Leaf Functions */
#define GRUB_SMX_LEAF_CAPABILITIES	0
#define GRUB_SMX_LEAF_UNDEFINED		1
#define GRUB_SMX_LEAF_ENTERACCS		2
#define GRUB_SMX_LEAF_EXITAC 		3
#define GRUB_SMX_LEAF_SENTER		4
#define GRUB_SMX_LEAF_SEXIT		5
#define GRUB_SMX_LEAF_PARAMETERS	6
#define GRUB_SMX_LEAF_SMCTRL		7
#define GRUB_SMX_LEAF_WAKEUP		8

/* Table 7-3. GETSEC Capability Result Encoding */
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

  asm volatile ("getsec"
                        : "=a" (caps)
                        : "a" (GRUB_SMX_LEAF_CAPABILITIES), "b" (index));
  return caps;
}

static inline void
grub_txt_getsec_parameters (grub_uint32_t index, grub_uint32_t *eax_out,
                            grub_uint32_t *ebx_out, grub_uint32_t *ecx_out)
{
  if (!eax_out || !ebx_out || !ecx_out)
    return;

  asm volatile ("getsec"
                        : "=a" (*eax_out), "=b" (*ebx_out), "=c" (*ecx_out)
                        : "a" (GRUB_SMX_LEAF_PARAMETERS), "b" (index));
}

#define GRUB_SMX_PARAMETER_TYPE_MASK		0x1f
#define GRUB_SMX_PARAMETER_NULL			0
#define GRUB_SMX_PARAMETER_ACM_VERSIONS		1
#define GRUB_SMX_PARAMETER_MAX_ACM_SIZE		2
#define GRUB_SMX_PARAMETER_ACM_MEMORY_TYPES	3
#define GRUB_SMX_PARAMETER_SENTER_CONTROLS	4
#define GRUB_SMX_PARAMETER_TXT_EXTENSIONS	5

#define GRUB_SMX_PARAMETER_MAX_VERSIONS	0x20

#define GRUB_SMX_GET_MAX_ACM_SIZE(v)	((v) & ~(__typeof__(v))GRUB_SMX_PARAMETER_TYPE_MASK)

#define GRUB_SMX_ACM_MEMORY_TYPE_UC	0x00000100
#define GRUB_SMX_ACM_MEMORY_TYPE_WC	0x00000200
#define GRUB_SMX_ACM_MEMORY_TYPE_WT	0x00001000
#define GRUB_SMX_ACM_MEMORY_TYPE_WP	0x00002000
#define GRUB_SMX_ACM_MEMORY_TYPE_WB	0x00004000

#define GRUB_SMX_GET_ACM_MEMORY_TYPES(v) ((v) & ~(__typeof__(v))GRUB_SMX_PARAMETER_TYPE_MASK)

#define GRUB_SMX_GET_SENTER_CONTROLS(v)	((v & 0x7f00) >> 8)

#define GRUB_SMX_PROCESSOR_BASE_SCRTM	0x00000020
#define GRUB_SMX_MACHINE_CHECK_HANDLING	0x00000040
#define GRUB_SMX_GET_TXT_EXT_FEATURES(v) (v & (__typeof__(v))(GRUB_SMX_PROCESSOR_BASE_SCRTM|GRUB_SMX_MACHINE_CHECK_HANDLING))

#define GRUB_SMX_DEFAULT_VERSION	0x0
#define GRUB_SMX_DEFAULT_VERSION_MASK	0xffffffff
#define GRUB_SMX_DEFAULT_MAX_ACM_SIZE	0x8000 /* 32K */
#define GRUB_SMX_DEFAULT_ACM_MEMORY_TYPE GRUB_SMX_ACM_MEMORY_TYPE_UC
#define GRUB_SMX_DEFAULT_SENTER_CONTROLS 0x0

/*
 * Measured Launch Environment Developer’s Guide,
 * Table 29. OS to SINIT Data Table
 */
#define GRUB_TXT_PMR_ALIGN_SHIFT	21
#define GRUB_TXT_PMR_ALIGN		(1 << GRUB_TXT_PMR_ALIGN_SHIFT)

struct grub_smx_supported_versions
{
  grub_uint32_t mask;
  grub_uint32_t version;
} GRUB_PACKED;

struct grub_smx_parameters
{
  struct grub_smx_supported_versions versions[GRUB_SMX_PARAMETER_MAX_VERSIONS];
  grub_uint32_t version_count;
  grub_uint32_t max_acm_size;
  grub_uint32_t acm_memory_types;
  grub_uint32_t senter_controls;
  grub_uint32_t txt_feature_ext_flags;
} GRUB_PACKED;

extern grub_uint32_t grub_txt_supported_os_sinit_data_ver (struct grub_txt_acm_header* hdr);

extern grub_uint32_t grub_txt_get_sinit_capabilities (struct grub_txt_acm_header* hdr);

extern int grub_txt_is_sinit_acmod (const void *acmod_base, grub_uint32_t acmod_size);

extern int grub_txt_acmod_match_platform (struct grub_txt_acm_header *hdr);

extern struct grub_txt_acm_header* grub_txt_sinit_select (struct grub_txt_acm_header *sinit);

extern grub_err_t grub_txt_verify_platform (void);
extern grub_err_t grub_txt_prepare_cpu (void);

extern grub_uint32_t grub_txt_get_mle_ptab_size (grub_uint32_t mle_size);
extern void grub_txt_setup_mle_ptab (struct grub_slaunch_params *slparams);

extern grub_err_t grub_txt_init (void);
extern void grub_txt_shutdown (void);
extern void grub_txt_state_show (void);
extern grub_err_t grub_txt_boot_prepare (struct grub_slaunch_params *slparams);

#endif
