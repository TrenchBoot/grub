/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (c) 2018 Daniel P. Smith, Apertus Solutions, LLC
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
 *  The definitions in this header are extracted from the Trusted Computing
 *  Group's "TPM Main Specification", Parts 1-3.
 */

#ifndef GRUB_TIS_H
#define GRUB_TIS_H 1

#include <grub/types.h>

/* Section 2.2.3 */
#define TPM_AUTH_DATA_USAGE grub_uint8_t
#define TPM_PAYLOAD_TYPE grub_uint8_t
#define TPM_VERSION_BYTE grub_uint8_t
#define TPM_TAG grub_uint16_t
#define TPM_PROTOCOL_ID grub_uint16_t
#define TPM_STARTUP_TYPE grub_uint16_t
#define TPM_ENC_SCHEME grub_uint16_t
#define TPM_SIG_SCHEME grub_uint16_t
#define TPM_MIGRATE_SCHEME grub_uint16_t
#define TPM_PHYSICAL_PRESENCE grub_uint16_t
#define TPM_ENTITY_TYPE grub_uint16_t
#define TPM_KEY_USAGE grub_uint16_t
#define TPM_EK_TYPE grub_uint16_t
#define TPM_STRUCTURE_TAG grub_uint16_t
#define TPM_PLATFORM_SPECIFIC grub_uint16_t
#define TPM_COMMAND_CODE grub_uint32_t
#define TPM_CAPABILITY_AREA grub_uint32_t
#define TPM_KEY_FLAGS grub_uint32_t
#define TPM_ALGORITHM_ID grub_uint32_t
#define TPM_MODIFIER_INDICATOR grub_uint32_t
#define TPM_ACTUAL_COUNT grub_uint32_t
#define TPM_TRANSPORT_ATTRIBUTES grub_uint32_t
#define TPM_AUTHHANDLE grub_uint32_t
#define TPM_DIRINDEX grub_uint32_t
#define TPM_KEY_HANDLE grub_uint32_t
#define TPM_PCRINDEX grub_uint32_t
#define TPM_RESULT grub_uint32_t
#define TPM_RESOURCE_TYPE grub_uint32_t
#define TPM_KEY_CONTROL grub_uint32_t
#define TPM_NV_INDEX grub_uint32_t The
#define TPM_FAMILY_ID grub_uint32_t
#define TPM_FAMILY_VERIFICATION grub_uint32_t
#define TPM_STARTUP_EFFECTS grub_uint32_t
#define TPM_SYM_MODE grub_uint32_t
#define TPM_FAMILY_FLAGS grub_uint32_t
#define TPM_DELEGATE_INDEX grub_uint32_t
#define TPM_CMK_DELEGATE grub_uint32_t
#define TPM_COUNT_ID grub_uint32_t
#define TPM_REDIT_COMMAND grub_uint32_t
#define TPM_TRANSHANDLE grub_uint32_t
#define TPM_HANDLE grub_uint32_t
#define TPM_FAMILY_OPERATION grub_uint32_t

/* Section 6 */
#define TPM_TAG_RQU_COMMAND		0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND	0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND	0x00C3
#define TPM_TAG_RSP_COMMAND		0x00C4
#define TPM_TAG_RSP_AUTH1_COMMAND	0x00C5
#define TPM_TAG_RSP_AUTH2_COMMAND	0x00C6

/* Section 16 */
#define TPM_SUCCESS			0x0

/* Section 17 */
#define TPM_ORD_EXTEND			0x00000014

#define SHA1_DIGEST_SIZE		20

/* Section 5.4 */
struct grub_tpm_sha1_digest
{
  grub_uint8_t digest[SHA1_DIGEST_SIZE];
};

struct grub_tpm_digest
{
  TPM_PCRINDEX pcr;
  union
  {
    struct grub_tpm_sha1_digest sha1;
  } digest;
};

#define TPM_DIGEST		struct grub_tpm_digest
#define TPM_CHOSENID_HASH	TPM_DIGEST
#define TPM_COMPOSITE_HASH	TPM_DIGEST
#define TPM_DIRVALUE		TPM_DIGEST
#define TPM_HMAC		TPM_DIGEST
#define TPM_PCRVALUE		TPM_DIGEST
#define TPM_AUDITDIGEST		TPM_DIGEST
#define TPM_DAA_TPM_SEED	TPM_DIGEST
#define TPM_DAA_CONTEXT_SEED	TPM_DIGEST

struct grub_tpm_extend_cmd
{
  TPM_COMMAND_CODE ordinal;
  TPM_PCRINDEX pcr_num;
  TPM_DIGEST digest;
};

struct grub_tpm_extend_resp
{
  TPM_COMMAND_CODE ordinal;
  TPM_PCRVALUE digest;
};

struct grub_tpm_cmd_buf
{
  TPM_TAG tag;
  grub_uint32_t size;
  TPM_RESULT result;
  union
  {
    struct grub_tpm_extend_cmd extend;
  } cmd;
};

struct grub_tpm_resp_buf
{
  TPM_TAG tag;
  grub_uint32_t size;
  TPM_RESULT result;
  union
  {
    struct grub_tpm_extend_resp extend;
  } resp;
};

/* TPM Interface Specification functions */
grub_uint8_t EXPORT_FUNC(grub_tis_request_locality) (grub_uint8_t l);
grub_uint8_t EXPORT_FUNC(grub_tis_init) (void);
grub_size_t EXPORT_FUNC(grub_tis_send) (struct grub_tpm_cmd_buf *buf);
grub_size_t EXPORT_FUNC(grub_tis_recv) (struct grub_tpm_resp_buf *buf);

/* TPM Commands */
grub_uint8_t EXPORT_FUNC(grub_tpm_pcr_extend) (struct grub_tpm_digest *d);

#endif
