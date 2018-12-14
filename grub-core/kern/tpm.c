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
 *  The code in this file is based on the article "Writing a TPM Device Driver"
 *  published on http://ptgmedia.pearsoncmg.com.
 */

#include <grub/cpu/io.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/tis.h>

grub_uint8_t
grub_tpm_pcr_extend (struct grub_tpm_digest *d)
{
  grub_size_t bytes;
  struct grub_tpm_cmd_buf send;
  struct grub_tpm_resp_buf resp;

  send.tag = TPM_TAG_RQU_COMMAND;
  send.size = sizeof(struct grub_tpm_extend_cmd) + 6;
  send.cmd.extend.ordinal = TPM_ORD_EXTEND;
  send.cmd.extend.pcr_num = d->pcr;
  grub_memcpy(&(send.cmd.extend.digest), &(d->digest), sizeof(TPM_DIGEST));

  if (send.size != grub_tis_send(&send))
    return 0;

  bytes = sizeof(struct grub_tpm_extend_resp) + 10;
  if (bytes != grub_tis_recv(&resp))
    return 0;

  if (resp.result != TPM_SUCCESS)
    return 0;

  return 1;
}
