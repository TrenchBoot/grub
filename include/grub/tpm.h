/* tpm.h - tpm interface
 *
 * Copyright (C) 2011 Infineon Technologies
 * Copyright (C) 2017 Intel Corporation
 *
 * Authors:
 * Peter Huewe <huewe.external@infineon.com>
 * Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 * Version: 2.1.1
 *
 * Description:
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 *
 * It is based on the Linux kernel driver tpm.c from Leendert van
 * Dorn, Dave Safford, Reiner Sailer, and Kyleen Hall.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#ifndef _TPM_H_
#define _TPM_H_

#include <grub/types.h>

/* Size of external transmit buffer (used in tpm_transmit)*/
#define TPM_BUFSIZE 4096
#define TPM_ERROR_SIZE 10
#define TPM_HEADER_SIZE 10
#define TPM_DIGEST_SIZE 20

/* Index of fields in TPM command buffer */
#define TPM_CMD_SIZE_BYTE 2
#define TPM_CMD_ORDINAL_BYTE 6

/* Index of Count field in TPM response buffer */
#define TPM_RSP_SIZE_BYTE 2
#define TPM_RSP_RC_BYTE 6

#define TPM_TAG_RQU_COMMAND 193
#define TPM_ORD_PCR_EXTEND 20
#define EXTEND_PCR_RESULT_SIZE 34
#define EXTEND_PCR_RESULT_BODY_SIZE 20

struct tpm_input_header {
	grub_uint16_t tag;
	grub_uint32_t length;
	grub_uint32_t ordinal;
} GRUB_PACKED;

struct tpm_output_header {
	grub_uint16_t tag;
	grub_uint32_t length;
	grub_uint32_t return_code;
} GRUB_PACKED;

typedef union {
	struct tpm_input_header in;
	struct tpm_output_header out;
} tpm_cmd_header;

struct tpm_pcrread_out {
	grub_uint8_t pcr_result[TPM_DIGEST_SIZE];
} GRUB_PACKED;

struct tpm_pcrread_in {
	grub_uint32_t	pcr_idx;
} GRUB_PACKED;

/* 128 bytes is an arbitrary cap. This could be as large as TPM_BUFSIZE - 18
 * bytes, but 128 is still a relatively large number of random bytes and
 * anything much bigger causes users of struct tpm_cmd_t to start getting
 * compiler warnings about stack frame size. */
#define TPM_MAX_RNG_DATA	128

struct tpm_getrandom_out {
	grub_uint32_t rng_data_len;
	grub_uint8_t rng_data[TPM_MAX_RNG_DATA];
} GRUB_PACKED;

struct tpm_getrandom_in {
	grub_uint32_t num_bytes;
} GRUB_PACKED;

typedef union {
	struct	tpm_pcrread_in	pcrread_in;
	struct	tpm_pcrread_out	pcrread_out;
	struct	tpm_getrandom_in getrandom_in;
	struct	tpm_getrandom_out getrandom_out;
} tpm_cmd_params;

struct tpm_cmd_t {
	tpm_cmd_header header;
	tpm_cmd_params params;
} GRUB_PACKED;



int EXPORT_FUNC(grub_tpm_release_locality)(int l);
int EXPORT_FUNC(grub_tpm_request_locality)(int l);
int EXPORT_FUNC(grub_tpm_open)(void);
int EXPORT_FUNC(grub_tpm_pcr_extend)(grub_uint32_t pcr_idx, grub_uint8_t *digest);

#endif
