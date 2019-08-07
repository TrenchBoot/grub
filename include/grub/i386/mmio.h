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
 *  along with GRUB.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GRUB_I386_MMIO_H
#define GRUB_I386_MMIO_H 1

#include <grub/types.h>

static inline grub_uint8_t
grub_readb (const grub_addr_t addr)
{
  grub_uint8_t val;

  val = (*(volatile grub_uint8_t *) (addr));

  return val;
}

static inline grub_uint32_t
grub_readl (const grub_addr_t addr)
{
  grub_uint32_t val;

  val = (*(volatile grub_uint32_t *) (addr));

  return val;
}

static inline grub_uint64_t
grub_readq (const grub_addr_t addr)
{
  grub_uint64_t val;

  val = (*(volatile grub_uint64_t *) (addr));

  return val;
}

static inline void
grub_writeb (grub_uint8_t val, grub_addr_t addr)
{
  (*(volatile grub_uint8_t *) (addr)) = val;
}

static inline void
grub_writel (grub_uint32_t val, grub_addr_t addr)
{
  (*(volatile grub_uint32_t *) (addr)) = val;
}

static inline void
grub_writeq (grub_uint64_t val, grub_addr_t addr)
{
  (*(volatile grub_uint64_t *) (addr)) = val;
}

#endif /* GRUB_I386_MMIO_H */
