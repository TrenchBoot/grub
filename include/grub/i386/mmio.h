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
 *  along with GRUB.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GRUB_MMIO_H
#define GRUB_MMIO_H 1

#include <grub/types.h>

#define grub_mb()	__asm__ __volatile__ ("mfence" : : : "memory")
#define grub_rmb()	__asm__ __volatile__ ("lfence" : : : "memory")
#define grub_wmb()	__asm__ __volatile__ ("sfence" : : : "memory")
#define grub_barrier()	__asm__ __volatile__ ("" : : : "memory")

static __inline grub_uint8_t
grub_readb (void *addr)
{
  grub_uint8_t _v;

  grub_barrier();
  _v = (*(volatile grub_uint8_t*)(addr));
  grub_rmb();
  return _v;
}

static __inline grub_uint16_t
grub_readw (void *addr)
{
  grub_uint16_t _v;

  grub_barrier();
  _v = (*(volatile grub_uint16_t*)(addr));
  grub_rmb();
  return _v;
}

static __inline grub_uint32_t
grub_readl (void *addr)
{
  grub_uint32_t _v;

  grub_barrier();
  _v = (*(volatile grub_uint32_t*)(addr));
  grub_rmb();
  return _v;
}

static __inline grub_uint64_t
grub_readq (void *addr)
{
  grub_uint64_t _v;

  grub_barrier();
  _v = (*(volatile grub_uint64_t*)(addr));
  grub_rmb();
  return _v;
}

static __inline void
grub_writeb (grub_uint8_t value, void *addr)
{
  grub_wmb();
  (*(volatile grub_uint8_t *)(addr)) = value;
  grub_barrier();
}

static __inline void
grub_writew (grub_uint16_t value, void *addr)
{
  grub_wmb();
  (*(volatile grub_uint16_t *)(addr)) = value;
  grub_barrier();
}

static __inline void
grub_writel (grub_uint32_t value, void *addr)
{
  grub_wmb();
  (*(volatile grub_uint32_t *)(addr)) = value;
  grub_barrier();
}

static __inline void
grub_writeq (grub_uint64_t value, void *addr)
{
  grub_wmb();
  (*(volatile grub_uint64_t *)(addr)) = value;
  grub_barrier();
}

#endif
