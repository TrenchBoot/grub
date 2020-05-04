/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020  Free Software Foundation, Inc.
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

#ifndef GRUB_I386_TPM_H
#define GRUB_I386_TPM_H 1

#include <grub/types.h>

typedef enum
  {
    GRUB_TPM_NONE = 0,
    GRUB_TPM_12,
    GRUB_TPM_20
  }
grub_tpm_ver_t;

extern grub_tpm_ver_t grub_get_tpm_ver (void);
extern void grub_tpm_relinquish_locality (grub_uint8_t lcl);

#endif /* GRUB_I386_TPM_H */
