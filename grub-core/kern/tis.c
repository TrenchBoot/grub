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

#include <grub/i386/io.h>
#include <grub/i386/mmio.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/tis.h>

#ifdef __x86_64__
#define MMIO_BASE			0xFED40000ULL
#else
#define MMIO_BASE			0xFED40000
#endif

#define MAX_LOCALITY			4

/* macros to access registers at locality ’’l’’ */
#define ACCESS(l)			(0x0000 | ((l) << 12))
#define STS(l)				(0x0018 | ((l) << 12))
#define DATA_FIFO(l)			(0x0024 | ((l) << 12))
#define DID_VID(l)			(0x0F00 | ((l) << 12))
/* access bits */
#define ACCESS_ACTIVE_LOCALITY		0x20 /* (R)*/
#define ACCESS_RELINQUISH_LOCALITY	0x20 /* (W) */
#define ACCESS_REQUEST_USE		0x02 /* (W) */
/* status bits */
#define STS_VALID			0x80 /* (R) */
#define STS_COMMAND_READY		0x40 /* (R) */
#define STS_DATA_AVAIL			0x10 /* (R) */
#define STS_DATA_EXPECT			0x08 /* (R) */
#define STS_GO				0x20 /* (W) */

#define NO_LOCALITY			0xFF

static grub_uint8_t locality = NO_LOCALITY;

static grub_uint8_t
grub_read8 (grub_uint32_t field)
{
  void *mmio_addr = (void*)(MMIO_BASE | field);

  return grub_readb(mmio_addr);
}

static void
grub_write8 (unsigned char val, grub_uint32_t field)
{
  void *mmio_addr = (void*)(MMIO_BASE | field);

  grub_writeb(val, mmio_addr);
}

static grub_uint32_t
grub_read32 (grub_uint32_t field)
{
  void *mmio_addr = (void*)(MMIO_BASE | field);

  return grub_readl(mmio_addr);
}

__attribute__((unused)) /* TODO not used yet */
static void
grub_write32 (unsigned int val, grub_uint32_t field)
{
  void *mmio_addr = (void*)(MMIO_BASE | field);

  grub_writel(val, mmio_addr);
}

static inline void
grub_io_delay (void)
{
  __asm__ __volatile__ ("outb %al, $0x80");
}

static grub_uint32_t
grub_burst_wait (void)
{
  grub_uint32_t count = 0;

  while (count == 0)
  {
    count = grub_read8 (STS(locality) + 1);
    count += grub_read8 (STS(locality) + 2) << 8;

    if (count == 0)
      grub_io_delay (); /* wait for FIFO to drain */
  }

  return count;
}

grub_uint8_t
grub_tis_request_locality (grub_uint8_t l)
{
  if (locality <= MAX_LOCALITY)
    grub_write8 (ACCESS_RELINQUISH_LOCALITY, ACCESS(locality));

  if (l == NO_LOCALITY)
    locality = l;

  if (l <= MAX_LOCALITY)
    {
      grub_write8 (ACCESS_REQUEST_USE, ACCESS(l));

      /* wait for locality to be granted */
      if (grub_read8 (ACCESS(l) & ACCESS_ACTIVE_LOCALITY))
        locality = l;
      else
        locality = NO_LOCALITY;
    }

  return locality;
}

grub_uint8_t
grub_tis_init (void)
{
  grub_uint32_t vendor;
  grub_uint8_t i;

  for (i=0; i<=MAX_LOCALITY; i++)
    grub_write8 (ACCESS_RELINQUISH_LOCALITY, ACCESS(i));

  if (grub_tis_request_locality (0) == NO_LOCALITY)
    return 0;

  vendor = grub_read32 (DID_VID(0));
  if ((vendor & 0xFFFF) == 0xFFFF)
    return 0;

  return 1;
}

grub_size_t
grub_tis_send (struct grub_tpm_cmd_buf *buf)
{
  grub_uint8_t status, *buf_ptr;
  grub_uint32_t burstcnt = 0;
  grub_uint32_t count = 0;

  if (locality > MAX_LOCALITY)
    return 0;

  grub_write8 (STS_COMMAND_READY, STS(locality));

  buf_ptr = (grub_uint8_t *) buf;

  /* send all but the last byte */
  while (count < (buf->size - 1))
    {
      burstcnt = grub_burst_wait();
      for (; burstcnt > 0 && count < buf->size - 1; burstcnt--)
        {
          grub_write8 (buf_ptr[count], DATA_FIFO(locality));
          count++;
        }

      /* check for overflow */
      for (status = 0; (status & STS_VALID) == 0; )
        status = grub_read8(STS(locality));

      if ((status & STS_DATA_EXPECT) == 0)
        return 0;
    }

  /* write last byte */
  grub_write8 (buf_ptr[count], DATA_FIFO(locality));

  /* make sure it stuck */
  for (status = 0; (status & STS_VALID) == 0; )
    status = grub_read8(STS(locality));

  if ((status & STS_DATA_EXPECT) != 0)
    return 0;

  /* go and do it */
  grub_write8 (STS_GO, STS(locality));

  return (grub_size_t)count;
}

static grub_size_t
grub_recv_data (unsigned char *buf, grub_size_t len)
{
  grub_size_t size = 0;
  grub_uint8_t status, *bufptr;
  grub_uint32_t burstcnt = 0;

  bufptr = (grub_uint8_t *)buf;

  status = grub_read8 (STS(locality));
  while ((status & (STS_DATA_AVAIL | STS_VALID))
         == (STS_DATA_AVAIL | STS_VALID)
         && size < len)
    {
      burstcnt = grub_burst_wait ();
      for (; burstcnt > 0 && size < len; burstcnt--)
        {
          *bufptr = grub_read8 (DATA_FIFO(locality));
          bufptr++;
          size++;
        }

      status = grub_read8 (STS(locality));
    }

  return size;
}

grub_size_t
grub_tis_recv (struct grub_tpm_resp_buf *buf)
{
  grub_uint32_t expected;
  grub_uint8_t status, *buf_ptr;
  grub_size_t size = 0;

  buf_ptr = (grub_uint8_t *)buf;

  /* ensure that there is data available */
  status = grub_read8 (STS(locality));
  if ((status & (STS_DATA_AVAIL | STS_VALID))
      != (STS_DATA_AVAIL | STS_VALID))
    goto err;

  /* read first 6 bytes, including tag and paramsize */
  if ((size = grub_recv_data (buf_ptr, 6)) < 6)
    goto err;

  buf_ptr += 6;

  expected = grub_be_to_cpu32 (buf->size);
  if (expected > sizeof(struct grub_tpm_resp_buf))
    goto err;

  /* read all data, except last byte */
  if ((size += grub_recv_data (buf_ptr, expected - 7))
      < expected - 1)
    goto err;

  buf_ptr += expected - 7;

  /* check for receive underflow */
  status = grub_read8 (STS(locality));
  if ((status & (STS_DATA_AVAIL | STS_VALID))
      != (STS_DATA_AVAIL | STS_VALID))
    goto err;

  /* read last byte */
  if ((size += grub_recv_data (buf_ptr, 1)) != expected)
    goto err;

  /* make sure we read everything */
  status = grub_read8 (STS(locality));
  if ((status & (STS_DATA_AVAIL | STS_VALID))
      == (STS_DATA_AVAIL | STS_VALID))
    goto err;

  grub_write8 (STS_COMMAND_READY, STS(locality));

  return size;
err:
  return 0;
}
