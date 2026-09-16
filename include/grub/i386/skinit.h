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

#ifndef __SKINIT_H__
#define __SKINIT_H__

#define GRUB_SKL_VERSION 0

/* This is the setup_data type reserved for Secure Launch defined in bootparams */
#define GRUB_SETUP_SECURE_LAUNCH 10

/* The AMD defined structure layout for the SLB. The last two fields are SL specific */
struct grub_sl_header
{
  grub_uint16_t skl_entry_point;
  grub_uint16_t length;
  grub_uint8_t reserved[62];
  grub_uint16_t skl_info_offset;
  grub_uint16_t bootloader_data_offset;
} GRUB_PACKED;

struct grub_skl_info
{
  grub_uint8_t  uuid[16]; /* 78 f1 26 8e 04 92 11 e9  83 2a c8 5b 76 c4 cc 02 */
  grub_uint32_t version;
  grub_uint16_t msb_key_algo;
  grub_uint8_t  msb_key_hash[64]; /* Support up to SHA512 */
} GRUB_PACKED;

extern int grub_skl_set_module (const void *skl_base, grub_uint32_t size);
extern grub_err_t grub_skl_setup_module (struct grub_slaunch_params *slparams);
extern grub_err_t grub_skl_prepare_bootloader_data (struct grub_slaunch_params *slparams);
extern void grub_skl_link_amd_info (struct grub_slaunch_params *slparams);

extern grub_err_t grub_skinit_is_supported (void);
extern grub_uint64_t grub_skinit_efi_mmap_end (grub_addr_t map, grub_size_t map_size,
                                               grub_size_t desc_size);
extern grub_err_t grub_skinit_psp_memory_protect (struct grub_slaunch_params *slparams);
extern grub_err_t grub_skinit_prepare_cpu (void);
extern void grub_skinit_send_init_ipi_shorthand (void);

#endif /* __SKINIT_H__ */
