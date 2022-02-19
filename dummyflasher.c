/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009,2010 Carl-Daniel Hailfinger
 * Copyright (C) 2016 Hatim Kanchwala <hatim at hatimak.me>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "flash.h"
#include "chipdrivers.h"
#include "programmer.h"
#include "flashchips.h"
#include "spi.h"

/* Comments reflect what's implemented for a specific chip (may be incomplete) */
enum emu_chip {
	EMULATE_NONE,			/* SR1 */
	EMULATE_ST_M25P10_RES,		/* SR1 */
	EMULATE_SST_SST25VF040_REMS,	/* SR1 */
	EMULATE_SST_SST25VF032B,	/* SR1, SFDP */
	EMULATE_MACRONIX_MX25L6436,	/* SR1, SCUR, OTP (mode) */
	EMULATE_WINBOND_W25Q128FV,	/* SR1-2, OTP (sec. regs) */
	EMULATE_VARIABLE_SIZE,		/* SR1 */
	EMULATE_EON_EN25QH128,		/* SR1, OTP (mode) */
};

struct emu_data {
	enum emu_chip emu_chip;
	int emu_features; /* combination of FEATURE_* constants */
	char *emu_persistent_image;
	unsigned int emu_chip_size;
	int erase_to_zero;
	int emu_modified;	/* is the image modified since reading it? */
	uint8_t emu_status[2];
	uint8_t emu_status_len;	/* number of emulated status registers */
	uint8_t emu_scur;	/* security register */
	/* If "freq" parameter is passed in from command line, commands will delay
	 * for this period before returning. */
	unsigned long int delay_us;
	unsigned int emu_max_byteprogram_size;
	unsigned int emu_max_aai_size;
	unsigned int emu_jedec_se_size;
	unsigned int emu_jedec_be_52_size;
	unsigned int emu_jedec_be_d8_size;
	unsigned int emu_jedec_ce_60_size;
	unsigned int emu_jedec_ce_c7_size;
	unsigned char spi_blacklist[256];
	unsigned char spi_ignorelist[256];
	unsigned int spi_blacklist_size;
	unsigned int spi_ignorelist_size;

	bool hwwp;	/* state of hardware write protection */
	/* wp_start == wp_end when write-protection is disabled */
	uint32_t wp_start;
	uint32_t wp_end;

	unsigned int spi_write_256_chunksize;
	uint8_t *flashchip_contents;

	/* For chips with OTP mode. */
	bool otp_mode;		/* in OTP mode */
	bool otp_locked;	/* OTP region is locked (there is only one) */

	/* For all chips with OTP. */
	uint8_t otp_region_count;
	uint16_t otp_region_size;	/* this assumes regions of equal size */
	char *otp_image_path[FLASHROM_OTP_MAX_REGIONS];	/* path to a persistent image on disk */
	uint8_t *otp_region[FLASHROM_OTP_MAX_REGIONS];	/* data of the region */
};

/* A legit complete SFDP table based on the MX25L6436E (rev. 1.8) datasheet. */
static const uint8_t sfdp_table[] = {
	0x53, 0x46, 0x44, 0x50, // @0x00: SFDP signature
	0x00, 0x01, 0x01, 0xFF, // @0x04: revision 1.0, 2 headers
	0x00, 0x00, 0x01, 0x09, // @0x08: JEDEC SFDP header rev. 1.0, 9 DW long
	0x1C, 0x00, 0x00, 0xFF, // @0x0C: PTP0 = 0x1C (instead of 0x30)
	0xC2, 0x00, 0x01, 0x04, // @0x10: Macronix header rev. 1.0, 4 DW long
	0x48, 0x00, 0x00, 0xFF, // @0x14: PTP1 = 0x48 (instead of 0x60)
	0xFF, 0xFF, 0xFF, 0xFF, // @0x18: hole.
	0xE5, 0x20, 0xC9, 0xFF, // @0x1C: SFDP parameter table start
	0xFF, 0xFF, 0xFF, 0x03, // @0x20
	0x00, 0xFF, 0x08, 0x6B, // @0x24
	0x08, 0x3B, 0x00, 0xFF, // @0x28
	0xEE, 0xFF, 0xFF, 0xFF, // @0x2C
	0xFF, 0xFF, 0x00, 0x00, // @0x30
	0xFF, 0xFF, 0x00, 0xFF, // @0x34
	0x0C, 0x20, 0x0F, 0x52, // @0x38
	0x10, 0xD8, 0x00, 0xFF, // @0x3C: SFDP parameter table end
	0xFF, 0xFF, 0xFF, 0xFF, // @0x40: hole.
	0xFF, 0xFF, 0xFF, 0xFF, // @0x44: hole.
	0x00, 0x36, 0x00, 0x27, // @0x48: Macronix parameter table start
	0xF4, 0x4F, 0xFF, 0xFF, // @0x4C
	0xD9, 0xC8, 0xFF, 0xFF, // @0x50
	0xFF, 0xFF, 0xFF, 0xFF, // @0x54: Macronix parameter table end
};

static void *dummy_map(const char *descr, uintptr_t phys_addr, size_t len)
{
	msg_pspew("%s: Mapping %s, 0x%zx bytes at 0x%0*" PRIxPTR "\n",
		  __func__, descr, len, PRIxPTR_WIDTH, phys_addr);
	return (void *)phys_addr;
}

static void dummy_unmap(void *virt_addr, size_t len)
{
	msg_pspew("%s: Unmapping 0x%zx bytes at %p\n", __func__, len, virt_addr);
}

static int dummy_spi_write_256(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	struct emu_data *emu_data = flash->mst->spi.data;
	return spi_write_chunked(flash, buf, start, len,
				 emu_data->spi_write_256_chunksize);
}

static void dummy_chip_writeb(const struct flashctx *flash, uint8_t val, chipaddr addr)
{
	msg_pspew("%s: addr=0x%" PRIxPTR ", val=0x%02x\n", __func__, addr, val);
}

static void dummy_chip_writew(const struct flashctx *flash, uint16_t val, chipaddr addr)
{
	msg_pspew("%s: addr=0x%" PRIxPTR ", val=0x%04x\n", __func__, addr, val);
}

static void dummy_chip_writel(const struct flashctx *flash, uint32_t val, chipaddr addr)
{
	msg_pspew("%s: addr=0x%" PRIxPTR ", val=0x%08x\n", __func__, addr, val);
}

static void dummy_chip_writen(const struct flashctx *flash, const uint8_t *buf, chipaddr addr, size_t len)
{
	size_t i;
	msg_pspew("%s: addr=0x%" PRIxPTR ", len=0x%zx, writing data (hex):", __func__, addr, len);
	for (i = 0; i < len; i++) {
		if ((i % 16) == 0)
			msg_pspew("\n");
		msg_pspew("%02x ", buf[i]);
	}
}

static uint8_t dummy_chip_readb(const struct flashctx *flash, const chipaddr addr)
{
	msg_pspew("%s:  addr=0x%" PRIxPTR ", returning 0xff\n", __func__, addr);
	return 0xff;
}

static uint16_t dummy_chip_readw(const struct flashctx *flash, const chipaddr addr)
{
	msg_pspew("%s:  addr=0x%" PRIxPTR ", returning 0xffff\n", __func__, addr);
	return 0xffff;
}

static uint32_t dummy_chip_readl(const struct flashctx *flash, const chipaddr addr)
{
	msg_pspew("%s:  addr=0x%" PRIxPTR ", returning 0xffffffff\n", __func__, addr);
	return 0xffffffff;
}

static void dummy_chip_readn(const struct flashctx *flash, uint8_t *buf, const chipaddr addr, size_t len)
{
	msg_pspew("%s:  addr=0x%" PRIxPTR ", len=0x%zx, returning array of 0xff\n", __func__, addr, len);
	memset(buf, 0xff, len);
	return;
}

static uint8_t get_status_ro_bit_mask(const struct emu_data *data, enum flash_reg status_reg)
{
	assert(status_reg == STATUS1 || status_reg == STATUS2);

	uint8_t ro_bits = (status_reg == STATUS1 ? SPI_SR_WEL | SPI_SR_WIP : 0);

	if (data->emu_chip == EMULATE_WINBOND_W25Q128FV) {
		const bool srp0 = (data->emu_status[0] >> 7);
		const bool srp1 = (data->emu_status[1] & 1);

		const bool wp_active = (srp1 || (srp0 && data->hwwp));

		if (wp_active) {
			ro_bits = 0xff;
		} else if (status_reg == STATUS2) {
			/* SUS (bit_7) and (R) (bit_2). */
			ro_bits = 0x84;
			/* Once any of the lock bits (LB[1..3]) are set, they
			 * can't be unset. */
			ro_bits |= data->emu_status[1] & (1 << 3);
			ro_bits |= data->emu_status[1] & (1 << 4);
			ro_bits |= data->emu_status[1] & (1 << 5);
		}
	}

	return ro_bits;
}

static void update_write_protection(struct emu_data *data)
{
	if (data->emu_chip != EMULATE_WINBOND_W25Q128FV)
		return;

	const struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 2,
		.srp = {data->emu_status[0] >> 7, data->emu_status[1] & 1},

		.bp_bit_count = 3,
		.bp =
		{
			(data->emu_status[0] >> 2) & 1,
			(data->emu_status[0] >> 3) & 1,
			(data->emu_status[0] >> 4) & 1
		},

		.tb_bit_present = true,
		.tb = (data->emu_status[0] >> 5) & 1,

		.sec_bit_present = true,
		.sec = (data->emu_status[0] >> 6) & 1,

		.cmp_bit_present = true,
		.cmp = (data->emu_status[1] >> 6) & 1,
	};

	struct flashrom_wp_range range;
	decode_range_w25(&cfg, data->emu_chip_size, &range);

	data->wp_start = range.start;
	data->wp_end = range.start + range.len;
}

/* Checks whether range intersects a write-protected area of the flash if one is
 * defined. */
static bool is_write_protected(const struct emu_data *data, uint32_t start, uint32_t len)
{
	if (len == 0)
		return false;

	const uint32_t last = start + len - 1;
	return (start < data->wp_end && last >= data->wp_start);
}

/* Returns non-zero on error. */
static int write_flash_data(struct emu_data *data, uint32_t start, uint32_t len, const uint8_t *buf)
{
	if (is_write_protected(data, start, len)) {
		msg_perr("At least part of the write range is write protected!\n");
		return 1;
	}

	memcpy(data->flashchip_contents + start, buf, len);
	data->emu_modified = 1;
	return 0;
}

/* Returns non-zero on error. */
static int erase_flash_data(struct emu_data *data, uint32_t start, uint32_t len)
{
	if (is_write_protected(data, start, len)) {
		msg_perr("At least part of the erase range is write protected!\n");
		return 1;
	}

	/* FIXME: take data->erase_to_zero into account. */
	memset(data->flashchip_contents + start, 0xff, len);
	data->emu_modified = 1;
	return 0;
}

/* Checks if received offset is valid and that kind of requested operation is
 * allowed in current state. Returns zero if everything is fine. */
static int validate_otp_sector_op(struct emu_data *data, unsigned int offs, bool read_op)
{
	assert(data->emu_chip == EMULATE_EON_EN25QH128 ||
	       data->emu_chip == EMULATE_MACRONIX_MX25L6436);

	if (!read_op && data->otp_locked) {
		msg_perr("OTP is locked, cannot change contents of OTP sector anymore\n");
		return 1;
	}
	if ((offs & 0xfff) >= 0x200) {
		msg_perr("OTP address out of range: 0x%jx\n", (uintmax_t)offs);
		return 1;
	}
	/* MX25L6436 doesn't care about the values of high 12 bits. */
	if (data->emu_chip == EMULATE_EON_EN25QH128 && (offs >> 12) != 0xfff) {
		msg_perr("OTP address out of range: 0x%jx\n", (uintmax_t)offs);
		return 1;
	}

	return 0;
}

static int emulate_spi_chip_response(unsigned int writecnt,
				     unsigned int readcnt,
				     const unsigned char *writearr,
				     unsigned char *readarr,
				     struct emu_data *data)
{
	unsigned int offs, i, toread;
	uint8_t ro_bits;
	uint8_t region;
	static int unsigned aai_offs;
	const unsigned char sst25vf040_rems_response[2] = {0xbf, 0x44};
	const unsigned char sst25vf032b_rems_response[2] = {0xbf, 0x4a};
	const unsigned char mx25l6436_rems_response[2] = {0xc2, 0x16};
	const unsigned char w25q128fv_rems_response[2] = {0xef, 0x17};
	const unsigned char en25qh128_rems_response[2] = {0x1c, 0x17};

	if (writecnt == 0) {
		msg_perr("No command sent to the chip!\n");
		return 1;
	}
	/* spi_blacklist has precedence over spi_ignorelist. */
	for (i = 0; i < data->spi_blacklist_size; i++) {
		if (writearr[0] == data->spi_blacklist[i]) {
			msg_pdbg("Refusing blacklisted SPI command 0x%02x\n",
				 data->spi_blacklist[i]);
			return SPI_INVALID_OPCODE;
		}
	}
	for (i = 0; i < data->spi_ignorelist_size; i++) {
		if (writearr[0] == data->spi_ignorelist[i]) {
			msg_cdbg("Ignoring ignorelisted SPI command 0x%02x\n",
				 data->spi_ignorelist[i]);
			/* Return success because the command does not fail,
			 * it is simply ignored.
			 */
			return 0;
		}
	}

	if (data->emu_max_aai_size && (data->emu_status[0] & SPI_SR_AAI)) {
		if (writearr[0] != JEDEC_AAI_WORD_PROGRAM &&
		    writearr[0] != JEDEC_WRDI &&
		    writearr[0] != JEDEC_RDSR) {
			msg_perr("Forbidden opcode (0x%02x) attempted during "
				 "AAI sequence!\n", writearr[0]);
			return 0;
		}
	}

	switch (writearr[0]) {
	case JEDEC_RES:
		if (writecnt < JEDEC_RES_OUTSIZE)
			break;
		/* offs calculation is only needed for SST chips which treat RES like REMS. */
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];
		offs += writecnt - JEDEC_REMS_OUTSIZE;
		switch (data->emu_chip) {
		case EMULATE_ST_M25P10_RES:
			if (readcnt > 0)
				memset(readarr, 0x10, readcnt);
			break;
		case EMULATE_SST_SST25VF040_REMS:
			for (i = 0; i < readcnt; i++)
				readarr[i] = sst25vf040_rems_response[(offs + i) % 2];
			break;
		case EMULATE_SST_SST25VF032B:
			for (i = 0; i < readcnt; i++)
				readarr[i] = sst25vf032b_rems_response[(offs + i) % 2];
			break;
		case EMULATE_MACRONIX_MX25L6436:
			if (readcnt > 0)
				memset(readarr, 0x16, readcnt);
			break;
		case EMULATE_WINBOND_W25Q128FV:
			if (readcnt > 0)
				memset(readarr, 0x17, readcnt);
			break;
		case EMULATE_EON_EN25QH128:
			if (readcnt > 0)
				memset(readarr, 0x17, readcnt);
			break;
		default: /* ignore */
			break;
		}
		break;
	case JEDEC_REMS:
		/* REMS response has wraparound and uses an address parameter. */
		if (writecnt < JEDEC_REMS_OUTSIZE)
			break;
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];
		offs += writecnt - JEDEC_REMS_OUTSIZE;
		switch (data->emu_chip) {
		case EMULATE_SST_SST25VF040_REMS:
			for (i = 0; i < readcnt; i++)
				readarr[i] = sst25vf040_rems_response[(offs + i) % 2];
			break;
		case EMULATE_SST_SST25VF032B:
			for (i = 0; i < readcnt; i++)
				readarr[i] = sst25vf032b_rems_response[(offs + i) % 2];
			break;
		case EMULATE_MACRONIX_MX25L6436:
			for (i = 0; i < readcnt; i++)
				readarr[i] = mx25l6436_rems_response[(offs + i) % 2];
			break;
		case EMULATE_WINBOND_W25Q128FV:
			for (i = 0; i < readcnt; i++)
				readarr[i] = w25q128fv_rems_response[(offs + i) % 2];
			break;
		case EMULATE_EON_EN25QH128:
			for (i = 0; i < readcnt; i++)
				readarr[i] = en25qh128_rems_response[(offs + i) % 2];
			break;
		default: /* ignore */
			break;
		}
		break;
	case JEDEC_RDID:
		switch (data->emu_chip) {
		case EMULATE_SST_SST25VF032B:
			if (readcnt > 0)
				readarr[0] = 0xbf;
			if (readcnt > 1)
				readarr[1] = 0x25;
			if (readcnt > 2)
				readarr[2] = 0x4a;
			break;
		case EMULATE_MACRONIX_MX25L6436:
			if (readcnt > 0)
				readarr[0] = 0xc2;
			if (readcnt > 1)
				readarr[1] = 0x20;
			if (readcnt > 2)
				readarr[2] = 0x17;
			break;
		case EMULATE_WINBOND_W25Q128FV:
			if (readcnt > 0)
				readarr[0] = 0xef;
			if (readcnt > 1)
				readarr[1] = 0x40;
			if (readcnt > 2)
				readarr[2] = 0x18;
			break;
		case EMULATE_VARIABLE_SIZE:
			if (readcnt > 0)
				readarr[0] = (PROGMANUF_ID >> 8) & 0xff;
			if (readcnt > 1)
				readarr[1] = PROGMANUF_ID & 0xff;
			if (readcnt > 2)
				readarr[2] = (PROGDEV_ID >> 8) & 0xff;
			if (readcnt > 3)
				readarr[3] = PROGDEV_ID & 0xff;
			break;
		case EMULATE_EON_EN25QH128:
			if (readcnt > 0)
				readarr[0] = 0x1c;
			if (readcnt > 1)
				readarr[1] = 0x70;
			if (readcnt > 2)
				readarr[2] = 0x18;
			break;
		default: /* ignore */
			break;
		}
		break;
	case JEDEC_RDSR:
		if (data->emu_chip == EMULATE_EON_EN25QH128 && data->otp_mode) {
			memset(readarr, (data->emu_status[0] & 0x7F) | (data->otp_locked << 7), readcnt);
			break;
		}
		memset(readarr, data->emu_status[0], readcnt);
		break;
	case JEDEC_RDSR2:
		if (data->emu_status_len >= 2)
			memset(readarr, data->emu_status[1], readcnt);
		break;
	/* FIXME: this should be chip-specific. */
	case JEDEC_EWSR:
	case JEDEC_WREN:
		data->emu_status[0] |= SPI_SR_WEL;
		break;
	case JEDEC_WRSR:
		if (!(data->emu_status[0] & SPI_SR_WEL)) {
			msg_perr("WRSR attempted, but WEL is 0!\n");
			break;
		}

		if (data->emu_chip == EMULATE_EON_EN25QH128 && data->otp_mode) {
			data->otp_locked = true;
			msg_pdbg("OTP bit set...\n");
			break;
		}

		/* FIXME: add some reasonable simulation of the busy flag */
		ro_bits = get_status_ro_bit_mask(data, STATUS1);
		data->emu_status[0] &= ro_bits;
		data->emu_status[0] |= (writearr[1] & ~ro_bits);
		if (writecnt == 3 && (data->emu_features & FEATURE_WRSR_EXT)) {
			ro_bits = get_status_ro_bit_mask(data, STATUS2);
			data->emu_status[1] &= ro_bits;
			data->emu_status[1]|= (writearr[2] & ~ro_bits);
		}
		/* Note: W25Q128FV doesn't change value of SR2 if it's not
		 * provided, other chips might differ. */

		if (writecnt == 3)
			msg_pdbg2("WRSR wrote 0x%02x%02x.\n", data->emu_status[1], data->emu_status[0]);
		else
			msg_pdbg2("WRSR wrote 0x%02x.\n", data->emu_status[0]);

		update_write_protection(data);
		break;
	case JEDEC_WRSR2:
		if (data->emu_status_len < 2)
			break;
		if (!(data->emu_status[0] & SPI_SR_WEL)) {
			msg_perr("WRSR2 attempted, but WEL is 0!\n");
			break;
		}

		ro_bits = get_status_ro_bit_mask(data, STATUS2);
		data->emu_status[1] &= ro_bits;
		data->emu_status[1] |= (writearr[1] & ~ro_bits);

		update_write_protection(data);
		break;
	case JEDEC_READ:
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];
		if (data->otp_mode) {
			if (validate_otp_sector_op(data, offs, true))
				break;
			memcpy(readarr, data->otp_region[0] + (offs & 0xfff), readcnt);
			break;
		}
		/* Truncate to emu_chip_size. */
		offs %= data->emu_chip_size;
		if (readcnt > 0)
			memcpy(readarr, data->flashchip_contents + offs, readcnt);
		break;
	case JEDEC_READ_4BA:
		offs = writearr[1] << 24 | writearr[2] << 16 | writearr[3] << 8 | writearr[4];
		/* Truncate to emu_chip_size. */
		offs %= data->emu_chip_size;
		if (readcnt > 0)
			memcpy(readarr, data->flashchip_contents + offs, readcnt);
		break;
	case JEDEC_BYTE_PROGRAM:
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];
		if (data->otp_mode) {
			if (validate_otp_sector_op(data, offs, false))
				break;
			memcpy(data->otp_region[0] + (offs & 0xfff), writearr + 4, writecnt - 4);
			break;
		}
		/* Truncate to emu_chip_size. */
		offs %= data->emu_chip_size;
		if (writecnt < 5) {
			msg_perr("BYTE PROGRAM size too short!\n");
			return 1;
		}
		if (writecnt - 4 > data->emu_max_byteprogram_size) {
			msg_perr("Max BYTE PROGRAM size exceeded!\n");
			return 1;
		}
		if (write_flash_data(data, offs, writecnt - 4, writearr + 4)) {
			msg_perr("Failed to program flash!\n");
			return 1;
		}
		break;
	case JEDEC_BYTE_PROGRAM_4BA:
		offs = writearr[1] << 24 | writearr[2] << 16 | writearr[3] << 8 | writearr[4];
		/* Truncate to emu_chip_size. */
		offs %= data->emu_chip_size;
		if (writecnt < 6) {
			msg_perr("BYTE PROGRAM size too short!\n");
			return 1;
		}
		if (writecnt - 5 > data->emu_max_byteprogram_size) {
			msg_perr("Max BYTE PROGRAM size exceeded!\n");
			return 1;
		}
		if (write_flash_data(data, offs, writecnt - 5, writearr + 5)) {
			msg_perr("Failed to program flash!\n");
			return 1;
		}
		break;
	case JEDEC_AAI_WORD_PROGRAM:
		if (!data->emu_max_aai_size)
			break;
		if (!(data->emu_status[0] & SPI_SR_AAI)) {
			if (writecnt < JEDEC_AAI_WORD_PROGRAM_OUTSIZE) {
				msg_perr("Initial AAI WORD PROGRAM size too "
					 "short!\n");
				return 1;
			}
			if (writecnt > JEDEC_AAI_WORD_PROGRAM_OUTSIZE) {
				msg_perr("Initial AAI WORD PROGRAM size too "
					 "long!\n");
				return 1;
			}
			data->emu_status[0] |= SPI_SR_AAI;
			aai_offs = writearr[1] << 16 | writearr[2] << 8 |
				   writearr[3];
			/* Truncate to emu_chip_size. */
			aai_offs %= data->emu_chip_size;
			if (write_flash_data(data, aai_offs, 2, writearr + 4)) {
				msg_perr("Failed to program flash!\n");
				return 1;
			}
			aai_offs += 2;
		} else {
			if (writecnt < JEDEC_AAI_WORD_PROGRAM_CONT_OUTSIZE) {
				msg_perr("Continuation AAI WORD PROGRAM size "
					 "too short!\n");
				return 1;
			}
			if (writecnt > JEDEC_AAI_WORD_PROGRAM_CONT_OUTSIZE) {
				msg_perr("Continuation AAI WORD PROGRAM size "
					 "too long!\n");
				return 1;
			}
			if (write_flash_data(data, aai_offs, 2, writearr + 1)) {
				msg_perr("Failed to program flash!\n");
				return 1;
			}
			aai_offs += 2;
		}
		break;
	case JEDEC_WRDI:
		if (data->emu_max_aai_size)
			data->emu_status[0] &= ~SPI_SR_AAI;
		if (data->emu_chip == EMULATE_EON_EN25QH128) {
			data->otp_mode = false;
			msg_pdbg("Left OTP mode...\n");
		}
		break;
	case JEDEC_SE:
		if (!data->emu_jedec_se_size)
			break;
		if (writecnt != JEDEC_SE_OUTSIZE) {
			msg_perr("SECTOR ERASE 0x20 outsize invalid!\n");
			return 1;
		}
		if (readcnt != JEDEC_SE_INSIZE) {
			msg_perr("SECTOR ERASE 0x20 insize invalid!\n");
			return 1;
		}
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];
		if (data->otp_mode) {
			if (validate_otp_sector_op(data, offs, false))
				break;
			memset(data->otp_region[0], 0xff, data->otp_region_size);
			break;
		}
		if (offs & (data->emu_jedec_se_size - 1))
			msg_pdbg("Unaligned SECTOR ERASE 0x20: 0x%x\n", offs);
		offs &= ~(data->emu_jedec_se_size - 1);
		if (erase_flash_data(data, offs, data->emu_jedec_se_size)) {
			msg_perr("Failed to erase flash!\n");
			return 1;
		}
		break;
	case JEDEC_BE_52:
		if (!data->emu_jedec_be_52_size)
			break;
		if (writecnt != JEDEC_BE_52_OUTSIZE) {
			msg_perr("BLOCK ERASE 0x52 outsize invalid!\n");
			return 1;
		}
		if (readcnt != JEDEC_BE_52_INSIZE) {
			msg_perr("BLOCK ERASE 0x52 insize invalid!\n");
			return 1;
		}
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];
		if (offs & (data->emu_jedec_be_52_size - 1))
			msg_pdbg("Unaligned BLOCK ERASE 0x52: 0x%x\n", offs);
		offs &= ~(data->emu_jedec_be_52_size - 1);
		if (erase_flash_data(data, offs, data->emu_jedec_be_52_size)) {
			msg_perr("Failed to erase flash!\n");
			return 1;
		}
		break;
	case JEDEC_BE_D8:
		if (!data->emu_jedec_be_d8_size)
			break;
		if (writecnt != JEDEC_BE_D8_OUTSIZE) {
			msg_perr("BLOCK ERASE 0xd8 outsize invalid!\n");
			return 1;
		}
		if (readcnt != JEDEC_BE_D8_INSIZE) {
			msg_perr("BLOCK ERASE 0xd8 insize invalid!\n");
			return 1;
		}
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];
		if (offs & (data->emu_jedec_be_d8_size - 1))
			msg_pdbg("Unaligned BLOCK ERASE 0xd8: 0x%x\n", offs);
		offs &= ~(data->emu_jedec_be_d8_size - 1);
		if (erase_flash_data(data, offs, data->emu_jedec_be_d8_size)) {
			msg_perr("Failed to erase flash!\n");
			return 1;
		}
		break;
	case JEDEC_CE_60:
		if (!data->emu_jedec_ce_60_size)
			break;
		if (writecnt != JEDEC_CE_60_OUTSIZE) {
			msg_perr("CHIP ERASE 0x60 outsize invalid!\n");
			return 1;
		}
		if (readcnt != JEDEC_CE_60_INSIZE) {
			msg_perr("CHIP ERASE 0x60 insize invalid!\n");
			return 1;
		}
		/* JEDEC_CE_60_OUTSIZE is 1 (no address) -> no offset. */
		/* emu_jedec_ce_60_size is emu_chip_size. */
		if (erase_flash_data(data, 0, data->emu_jedec_ce_60_size)) {
			msg_perr("Failed to erase flash!\n");
			return 1;
		}
		break;
	case JEDEC_CE_C7:
		if (!data->emu_jedec_ce_c7_size)
			break;
		if (writecnt != JEDEC_CE_C7_OUTSIZE) {
			msg_perr("CHIP ERASE 0xc7 outsize invalid!\n");
			return 1;
		}
		if (readcnt != JEDEC_CE_C7_INSIZE) {
			msg_perr("CHIP ERASE 0xc7 insize invalid!\n");
			return 1;
		}
		/* JEDEC_CE_C7_OUTSIZE is 1 (no address) -> no offset. */
		/* emu_jedec_ce_c7_size is emu_chip_size. */
		if (erase_flash_data(data, 0, data->emu_jedec_ce_c7_size)) {
			msg_perr("Failed to erase flash!\n");
			return 1;
		}
		break;
	case JEDEC_SFDP:
		if (data->emu_chip != EMULATE_MACRONIX_MX25L6436)
			break;
		if (writecnt < 4)
			break;
		offs = writearr[1] << 16 | writearr[2] << 8 | writearr[3];

		/* SFDP expects one dummy byte after the address. */
		if (writecnt == 4) {
			/* The dummy byte was not written, make sure it is read instead.
			 * Shifting and shortening the read array does achieve this goal.
			 */
			readarr++;
			readcnt--;
		} else {
			/* The response is shifted if more than 5 bytes are written, because SFDP data is
			 * already shifted out by the chip while those superfluous bytes are written. */
			offs += writecnt - 5;
		}

		/* The SFDP spec implies that the start address of an SFDP read may be truncated to fit in the
		 * SFDP table address space, i.e. the start address may be wrapped around at SFDP table size.
		 * This is a reasonable implementation choice in hardware because it saves a few gates. */
		if (offs >= sizeof(sfdp_table)) {
			msg_pdbg("Wrapping the start address around the SFDP table boundary (using 0x%x "
				 "instead of 0x%x).\n", (unsigned int)(offs % sizeof(sfdp_table)), offs);
			offs %= sizeof(sfdp_table);
		}
		toread = min(sizeof(sfdp_table) - offs, readcnt);
		memcpy(readarr, sfdp_table + offs, toread);
		if (toread < readcnt)
			msg_pdbg("Crossing the SFDP table boundary in a single "
				 "continuous chunk produces undefined results "
				 "after that point.\n");
		break;
	case JEDEC_READ_SEC_REG:
		if (data->emu_chip != EMULATE_WINBOND_W25Q128FV)
			break;

		if (writecnt != JEDEC_READ_SEC_REG_OUTSIZE) {
			msg_perr("READ SECURITY REGISTER size not proper!\n");
			break;
		}
		/* writearr[1..3] holds the address, writearr[1] must be 0x00,
		 * (writearr[2..3] & 01ff) holds the byte address pointing to within
		 * the security register range, and (writearr[2] & 0xf0) must be either
		 * of 0x01, 0x02 or 0x03 corresponding to security register 1, 2 or 3 resp. */
		if (writearr[1] || (writearr[2] & 0x0e))
			break;
		offs = (writearr[2] & 0x01) << 8 | writearr[3];
		/* Truncate to security register size. */
		offs %= data->otp_region_size;
		if (readcnt > 0) {
			region = (writearr[2] & 0xf0) >> 4;
			if (region > 0 && region < FLASHROM_OTP_MAX_REGIONS)
				memcpy(readarr, data->otp_region[region - 1] + offs, readcnt);
		}
		break;
	case JEDEC_PROG_BYTE_SEC_REG:
		if (data->emu_chip != EMULATE_WINBOND_W25Q128FV)
			break;

		if (writecnt < JEDEC_PROG_BYTE_SEC_REG_OUTSIZE) {
			msg_perr("PROGRAM SECURITY REGISTER size too short!\n");
			break;
		}
		/* writearr[1..3] holds the address, writearr[1] must be 0x00,
		 * (writearr[2..3] & 01ff) holds the byte address pointing to within
		 * the security register range, and (writearr[2] & 0xf0) must be either
		 * of 0x01, 0x02 or 0x03 corresponding to security register 1, 2 or 3 resp. */
		if (writearr[1] || (writearr[2] & 0x0e))
			break;
		offs = (writearr[2] & 0x01) << 8 | writearr[3];
		/* Truncate to security register size. */
		offs %= data->otp_region_size;

		region = (writearr[2] >> 4);
		if (region > 0 && region < FLASHROM_OTP_MAX_REGIONS) {
			--region;
			uint8_t ls_bit_pos = 3 + region;
			/* If corresponding Lock Bits are set then the register is locked against
			 * any further write attempts. */
			if (!(data->emu_status[1] & (1 << ls_bit_pos)))
				memcpy(data->otp_region[region] + offs, writearr + 4, writecnt - 4);
		}
		break;
	case JEDEC_ERASE_SEC_REG:
		if (data->emu_chip != EMULATE_WINBOND_W25Q128FV)
			break;

		if (writecnt != JEDEC_ERASE_SEC_REG_OUTSIZE) {
			msg_perr("ERASE SECURITY REGISTER size not proper!\n");
			break;
		}
		/* writearr[1..3] holds the address, writearr[1] must be 0x00,
		 * (writearr[2..3] & 01ff) holds the byte address pointing to within
		 * the security register range, and (writearr[2] & 0xf0) must be either
		 * of 0x01, 0x02 or 0x03 corresponding to security register 1, 2 or 3 resp. */
		if (writearr[1] || (writearr[2] & 0x0e))
			break;

		region = (writearr[2] >> 4);
		if (region > 0 && region < FLASHROM_OTP_MAX_REGIONS) {
			--region;
			uint8_t ls_bit_pos = 3 + region;
			/* If corresponding Lock Bits are set then the register
			 * is locked against any further erase attempts. */
			if (!(data->emu_status[1] & (1 << ls_bit_pos)))
				memset(data->otp_region[region], 0xff, data->otp_region_size);
		}
		break;
	case JEDEC_ENTER_OTP: /* enter OTP for Eon chips */
		if (data->emu_chip != EMULATE_EON_EN25QH128)
			break;
		data->otp_mode = true;
		msg_pdbg("Entered OTP mode...\n");
		break;
	case JEDEC_ENSO: /* enter OTP for Macronix/Adesto chips */
		if (data->emu_chip != EMULATE_MACRONIX_MX25L6436)
			break;
		data->otp_mode = true;
		msg_pdbg("Entered OTP mode...\n");
		break;
	case JEDEC_EXSO: /* exit OTP for Macronix/Adesto chips */
		if (data->emu_chip != EMULATE_MACRONIX_MX25L6436)
			break;
		data->otp_mode = false;
		msg_pdbg("Left OTP mode...\n");
		break;
	case JEDEC_RDSCUR:
		if (data->emu_chip != EMULATE_MACRONIX_MX25L6436)
			break;
		memset(readarr, data->emu_scur, readcnt);
		break;
	case JEDEC_WRSCUR:
		if (data->emu_chip != EMULATE_MACRONIX_MX25L6436)
			break;
		/* Can't use this command in OTP mode. */
		if (data->otp_mode)
			break;
		data->emu_scur |= 0x02; /* LDSO bit */
		data->otp_locked = true;
		break;
	default:
		/* No special response. */
		break;
	}
	if (writearr[0] != JEDEC_WREN && writearr[0] != JEDEC_EWSR)
		data->emu_status[0] &= ~SPI_SR_WEL;
	return 0;
}

static int dummy_spi_send_command(const struct flashctx *flash, unsigned int writecnt,
				  unsigned int readcnt,
				  const unsigned char *writearr,
				  unsigned char *readarr)
{
	unsigned int i;
	struct emu_data *emu_data = flash->mst->spi.data;
	if (!emu_data) {
		msg_perr("No data in flash context!\n");
		return 1;
	}

	msg_pspew("%s:", __func__);

	msg_pspew(" writing %u bytes:", writecnt);
	for (i = 0; i < writecnt; i++)
		msg_pspew(" 0x%02x", writearr[i]);

	/* Response for unknown commands and missing chip is 0xff. */
	memset(readarr, 0xff, readcnt);
	switch (emu_data->emu_chip) {
	case EMULATE_ST_M25P10_RES:
	case EMULATE_SST_SST25VF040_REMS:
	case EMULATE_SST_SST25VF032B:
	case EMULATE_MACRONIX_MX25L6436:
	case EMULATE_WINBOND_W25Q128FV:
	case EMULATE_VARIABLE_SIZE:
	case EMULATE_EON_EN25QH128:
		if (emulate_spi_chip_response(writecnt, readcnt, writearr,
					      readarr, emu_data)) {
			msg_pdbg("Invalid command sent to flash chip!\n");
			return 1;
		}
		break;
	default:
		break;
	}
	msg_pspew(" reading %u bytes:", readcnt);
	for (i = 0; i < readcnt; i++)
		msg_pspew(" 0x%02x", readarr[i]);
	msg_pspew("\n");

	programmer_delay((writecnt + readcnt) * emu_data->delay_us);
	return 0;
}

static int dummy_shutdown(void *data)
{
	msg_pspew("%s\n", __func__);
	struct emu_data *emu_data = (struct emu_data *)data;
	if (emu_data->emu_chip == EMULATE_NONE) {
		free(data);
		return 0;
	}

	if (emu_data->emu_persistent_image && emu_data->emu_modified) {
		msg_pdbg("Writing %s\n", emu_data->emu_persistent_image);
		write_buf_to_file(emu_data->flashchip_contents,
				  emu_data->emu_chip_size,
				  emu_data->emu_persistent_image);
	}
	free(emu_data->emu_persistent_image);
	free(emu_data->flashchip_contents);

	for (uint8_t region = 0; region < emu_data->otp_region_count; ++region) {
		if (emu_data->otp_image_path[region]) {
			msg_pdbg("Writing %s\n", emu_data->otp_image_path[region]);
			write_buf_to_file(emu_data->otp_region[region],
					  emu_data->otp_region_size,
					  emu_data->otp_image_path[region]);
		}

		free(emu_data->otp_region[region]);
		free(emu_data->otp_image_path[region]);
	}

	free(data);
	return 0;
}

static const struct spi_master spi_master_dummyflasher = {
	.features	= SPI_MASTER_4BA,
	.max_data_read	= MAX_DATA_READ_UNLIMITED,
	.max_data_write	= MAX_DATA_UNSPECIFIED,
	.command	= dummy_spi_send_command,
	.multicommand	= default_spi_send_multicommand,
	.read		= default_spi_read,
	.write_256	= dummy_spi_write_256,
	.write_aai	= default_spi_write_aai,
};

static const struct par_master par_master_dummyflasher = {
		.chip_readb		= dummy_chip_readb,
		.chip_readw		= dummy_chip_readw,
		.chip_readl		= dummy_chip_readl,
		.chip_readn		= dummy_chip_readn,
		.chip_writeb		= dummy_chip_writeb,
		.chip_writew		= dummy_chip_writew,
		.chip_writel		= dummy_chip_writel,
		.chip_writen		= dummy_chip_writen,
};

static int init_data(struct emu_data *data, enum chipbustype *dummy_buses_supported)
{

	char *bustext = NULL;
	char *tmp = NULL;
	unsigned int i;
	char *endptr;
	char *status = NULL;
	char *scur = NULL;
	int size = -1;  /* size for VARIABLE_SIZE chip device */

	bustext = extract_programmer_param("bus");
	msg_pdbg("Requested buses are: %s\n", bustext ? bustext : "default");
	if (!bustext)
		bustext = strdup("parallel+lpc+fwh+spi");
	/* Convert the parameters to lowercase. */
	tolower_string(bustext);

	*dummy_buses_supported = BUS_NONE;
	if (strstr(bustext, "parallel")) {
		*dummy_buses_supported |= BUS_PARALLEL;
		msg_pdbg("Enabling support for %s flash.\n", "parallel");
	}
	if (strstr(bustext, "lpc")) {
		*dummy_buses_supported |= BUS_LPC;
		msg_pdbg("Enabling support for %s flash.\n", "LPC");
	}
	if (strstr(bustext, "fwh")) {
		*dummy_buses_supported |= BUS_FWH;
		msg_pdbg("Enabling support for %s flash.\n", "FWH");
	}
	if (strstr(bustext, "spi")) {
		*dummy_buses_supported |= BUS_SPI;
		msg_pdbg("Enabling support for %s flash.\n", "SPI");
	}
	if (*dummy_buses_supported == BUS_NONE)
		msg_pdbg("Support for all flash bus types disabled.\n");
	free(bustext);

	tmp = extract_programmer_param("spi_write_256_chunksize");
	if (tmp) {
		data->spi_write_256_chunksize = strtoul(tmp, &endptr, 0);
		if (*endptr != '\0' || data->spi_write_256_chunksize < 1) {
			msg_perr("invalid spi_write_256_chunksize\n");
			free(tmp);
			return 1;
		}
	}
	free(tmp);

	tmp = extract_programmer_param("spi_blacklist");
	if (tmp) {
		i = strlen(tmp);
		if (!strncmp(tmp, "0x", 2)) {
			i -= 2;
			memmove(tmp, tmp + 2, i + 1);
		}
		if ((i > 512) || (i % 2)) {
			msg_perr("Invalid SPI command blacklist length\n");
			free(tmp);
			return 1;
		}
		data->spi_blacklist_size = i / 2;
		for (i = 0; i < data->spi_blacklist_size * 2; i++) {
			if (!isxdigit((unsigned char)tmp[i])) {
				msg_perr("Invalid char \"%c\" in SPI command "
					 "blacklist\n", tmp[i]);
				free(tmp);
				return 1;
			}
		}
		for (i = 0; i < data->spi_blacklist_size; i++) {
			unsigned int tmp2;
			/* SCNx8 is apparently not supported by MSVC (and thus
			 * MinGW), so work around it with an extra variable
			 */
			sscanf(tmp + i * 2, "%2x", &tmp2);
			data->spi_blacklist[i] = (uint8_t)tmp2;
		}
		msg_pdbg("SPI blacklist is ");
		for (i = 0; i < data->spi_blacklist_size; i++)
			msg_pdbg("%02x ", data->spi_blacklist[i]);
		msg_pdbg(", size %u\n", data->spi_blacklist_size);
	}
	free(tmp);

	tmp = extract_programmer_param("spi_ignorelist");
	if (tmp) {
		i = strlen(tmp);
		if (!strncmp(tmp, "0x", 2)) {
			i -= 2;
			memmove(tmp, tmp + 2, i + 1);
		}
		if ((i > 512) || (i % 2)) {
			msg_perr("Invalid SPI command ignorelist length\n");
			free(tmp);
			return 1;
		}
		data->spi_ignorelist_size = i / 2;
		for (i = 0; i < data->spi_ignorelist_size * 2; i++) {
			if (!isxdigit((unsigned char)tmp[i])) {
				msg_perr("Invalid char \"%c\" in SPI command "
					 "ignorelist\n", tmp[i]);
				free(tmp);
				return 1;
			}
		}
		for (i = 0; i < data->spi_ignorelist_size; i++) {
			unsigned int tmp2;
			/* SCNx8 is apparently not supported by MSVC (and thus
			 * MinGW), so work around it with an extra variable
			 */
			sscanf(tmp + i * 2, "%2x", &tmp2);
			data->spi_ignorelist[i] = (uint8_t)tmp2;
		}
		msg_pdbg("SPI ignorelist is ");
		for (i = 0; i < data->spi_ignorelist_size; i++)
			msg_pdbg("%02x ", data->spi_ignorelist[i]);
		msg_pdbg(", size %u\n", data->spi_ignorelist_size);
	}
	free(tmp);

	/* frequency to emulate in Hz (default), KHz, or MHz */
	tmp = extract_programmer_param("freq");
	if (tmp) {
		unsigned long int freq;
		char *units = tmp;
		char *end = tmp + strlen(tmp);

		errno = 0;
		freq = strtoul(tmp, &units, 0);
		if (errno) {
			msg_perr("Invalid frequency \"%s\", %s\n",
					tmp, strerror(errno));
			free(tmp);
			return 1;
		}

		if ((units > tmp) && (units < end)) {
			int units_valid = 0;

			if (units < end - 3) {
				;
			} else if (units == end - 2) {
				if (!strcasecmp(units, "hz"))
					units_valid = 1;
			} else if (units == end - 3) {
				if (!strcasecmp(units, "khz")) {
					freq *= 1000;
					units_valid = 1;
				} else if (!strcasecmp(units, "mhz")) {
					freq *= 1000000;
					units_valid = 1;
				}
			}

			if (!units_valid) {
				msg_perr("Invalid units: %s\n", units);
				free(tmp);
				return 1;
			}
		}

		/* Assume we only work with bytes and transfer at 1 bit/Hz */
		data->delay_us = (1000000 * 8) / freq;
	}
	free(tmp);

	tmp = extract_programmer_param("size");
	if (tmp) {
		size = strtol(tmp, NULL, 10);
		if (size <= 0 || (size % 1024 != 0)) {
			msg_perr("%s: Chip size is not a multiple of 1024: %s\n",
					 __func__, tmp);
			free(tmp);
			return 1;
		}
		free(tmp);
	}

	tmp = extract_programmer_param("hwwp");
	if (tmp) {
		if (!strcmp(tmp, "yes")) {
			msg_pdbg("Emulated chip will have hardware WP enabled\n");
			data->hwwp = true;
		} else if (!strcmp(tmp, "no")) {
			msg_pdbg("Emulated chip will have hardware WP disabled\n");
		} else {
			msg_perr("hwwp can be \"yes\" or \"no\"\n");
			free(tmp);
			return 1;
		}
		free(tmp);
	}

	tmp = extract_programmer_param("emulate");
	if (!tmp) {
		msg_pdbg("Not emulating any flash chip.\n");
		/* Nothing else to do. */
		return 0;
	}

	if (!strcmp(tmp, "M25P10.RES")) {
		data->emu_chip = EMULATE_ST_M25P10_RES;
		data->emu_chip_size = 128 * 1024;
		data->emu_max_byteprogram_size = 128;
		data->emu_max_aai_size = 0;
		data->emu_status_len = 1;
		data->emu_jedec_se_size = 0;
		data->emu_jedec_be_52_size = 0;
		data->emu_jedec_be_d8_size = 32 * 1024;
		data->emu_jedec_ce_60_size = 0;
		data->emu_jedec_ce_c7_size = data->emu_chip_size;
		msg_pdbg("Emulating ST M25P10.RES SPI flash chip (RES, page "
			 "write)\n");
	}
	if (!strcmp(tmp, "SST25VF040.REMS")) {
		data->emu_chip = EMULATE_SST_SST25VF040_REMS;
		data->emu_chip_size = 512 * 1024;
		data->emu_max_byteprogram_size = 1;
		data->emu_max_aai_size = 0;
		data->emu_status_len = 1;
		data->emu_jedec_se_size = 4 * 1024;
		data->emu_jedec_be_52_size = 32 * 1024;
		data->emu_jedec_be_d8_size = 0;
		data->emu_jedec_ce_60_size = data->emu_chip_size;
		data->emu_jedec_ce_c7_size = 0;
		msg_pdbg("Emulating SST SST25VF040.REMS SPI flash chip (REMS, "
			 "byte write)\n");
	}
	if (!strcmp(tmp, "SST25VF032B")) {
		data->emu_chip = EMULATE_SST_SST25VF032B;
		data->emu_chip_size = 4 * 1024 * 1024;
		data->emu_max_byteprogram_size = 1;
		data->emu_max_aai_size = 2;
		data->emu_status_len = 1;
		data->emu_jedec_se_size = 4 * 1024;
		data->emu_jedec_be_52_size = 32 * 1024;
		data->emu_jedec_be_d8_size = 64 * 1024;
		data->emu_jedec_ce_60_size = data->emu_chip_size;
		data->emu_jedec_ce_c7_size = data->emu_chip_size;
		msg_pdbg("Emulating SST SST25VF032B SPI flash chip (RDID, AAI "
			 "write)\n");
	}
	if (!strcmp(tmp, "MX25L6436")) {
		data->emu_chip = EMULATE_MACRONIX_MX25L6436;
		data->emu_chip_size = 8 * 1024 * 1024;
		data->emu_max_byteprogram_size = 256;
		data->emu_max_aai_size = 0;
		data->emu_status_len = 1;
		data->emu_jedec_se_size = 4 * 1024;
		data->emu_jedec_be_52_size = 32 * 1024;
		data->emu_jedec_be_d8_size = 64 * 1024;
		data->emu_jedec_ce_60_size = data->emu_chip_size;
		data->emu_jedec_ce_c7_size = data->emu_chip_size;
		data->otp_region_count = 1;
		data->otp_region_size = 512;
		msg_pdbg("Emulating Macronix MX25L6436 SPI flash chip (RDID, "
			 "SFDP, OTP)\n");
	}
	if (!strcmp(tmp, "W25Q128FV")) {
		data->emu_chip = EMULATE_WINBOND_W25Q128FV;
		data->emu_features = FEATURE_WRSR_EXT;
		data->emu_chip_size = 16 * 1024 * 1024;
		data->emu_max_byteprogram_size = 256;
		data->emu_max_aai_size = 0;
		data->emu_status_len = 2;
		data->emu_jedec_se_size = 4 * 1024;
		data->emu_jedec_be_52_size = 32 * 1024;
		data->emu_jedec_be_d8_size = 64 * 1024;
		data->emu_jedec_ce_60_size = data->emu_chip_size;
		data->emu_jedec_ce_c7_size = data->emu_chip_size;
		data->otp_region_count = 3;
		data->otp_region_size = 256;
		msg_pdbg("Emulating Winbond W25Q128FV SPI flash chip (RDID, "
			 "OTP)\n");
	}
	if (!strcmp(tmp, "EN25QH128")) {
		data->emu_chip = EMULATE_EON_EN25QH128;
		data->emu_chip_size = 16 * 1024 * 1024;
		data->emu_max_byteprogram_size = 256;
		data->emu_max_aai_size = 0;
		data->emu_status_len = 1;
		data->emu_jedec_se_size = 4 * 1024;
		data->emu_jedec_be_52_size = 32 * 1024;
		data->emu_jedec_be_d8_size = 64 * 1024;
		data->emu_jedec_ce_60_size = data->emu_chip_size;
		data->emu_jedec_ce_c7_size = data->emu_chip_size;
		data->otp_region_count = 1;
		data->otp_region_size = 512;
		msg_pdbg("Emulating Eon EN25QH128 SPI flash chip (RDID, "
			 "OTP)\n");
	}

	/* The name of variable-size virtual chip. A 4 MiB flash example:
	 *   flashrom -p dummy:emulate=VARIABLE_SIZE,size=4194304
	 */
	if (!strcmp(tmp, "VARIABLE_SIZE")) {
		if (size == -1) {
			msg_perr("%s: the size parameter is not given.\n", __func__);
			free(tmp);
			return 1;
		}
		data->emu_chip = EMULATE_VARIABLE_SIZE;
		data->emu_chip_size = size;
		data->emu_max_byteprogram_size = 256;
		data->emu_max_aai_size = 0;
		data->emu_status_len = 1;
		data->emu_jedec_se_size = 4 * 1024;
		data->emu_jedec_be_52_size = 32 * 1024;
		data->emu_jedec_be_d8_size = 64 * 1024;
		data->emu_jedec_ce_60_size = data->emu_chip_size;
		data->emu_jedec_ce_c7_size = data->emu_chip_size;
		msg_pdbg("Emulating generic SPI flash chip (size=%d bytes)\n",
		         data->emu_chip_size);
	}

	if (data->emu_chip == EMULATE_NONE) {
		msg_perr("Invalid chip specified for emulation: %s\n", tmp);
		free(tmp);
		return 1;
	}
	free(tmp);

	/* Should emulated flash erase to zero (yes/no)? */
	tmp = extract_programmer_param("erase_to_zero");
	if (tmp) {
		if (!strcmp(tmp, "yes")) {
			msg_pdbg("Emulated chip will erase to 0x00\n");
			data->erase_to_zero = 1;
		} else if (!strcmp(tmp, "no")) {
			msg_pdbg("Emulated chip will erase to 0xff\n");
		} else {
			msg_perr("erase_to_zero can be \"yes\" or \"no\"\n");
			free(tmp);
			return 1;
		}
	}
	free(tmp);

	status = extract_programmer_param("spi_status");
	if (status) {
		uint32_t emu_status;

		errno = 0;
		emu_status = strtoul(status, &endptr, 0);
		if (errno != 0 || status == endptr) {
			free(status);
			msg_perr("Error: initial status register specified, "
				 "but the value could not be converted.\n");
			return 1;
		}
		free(status);

		data->emu_status[0] = emu_status;
		data->emu_status[1] = emu_status >> 8;

		if (data->emu_status_len == 2) {
			msg_pdbg("Initial status registers:\n"
				 "\tSR1 is set to 0x%02x\n"
				 "\tSR2 is set to 0x%02x\n",
				 data->emu_status[0], data->emu_status[1]);
		} else {
			msg_pdbg("Initial status register is set to 0x%02x.\n",
				 data->emu_status[0]);
		}
	}

	scur = extract_programmer_param("spi_scur");
	if (scur) {
		uint8_t value;

		errno = 0;
		value = strtoul(scur, &endptr, 0);
		if (errno != 0 || scur == endptr || *endptr != '\0') {
			free(scur);
			msg_perr("Error: initial security register specified, "
				 "but the value could not be converted.\n");
			return 1;
		}
		free(scur);

		data->emu_scur = value;
		if (data->emu_chip == EMULATE_MACRONIX_MX25L6436)
			data->otp_locked = ((value & 0x3) != 0);

		msg_pdbg("Initial security register is set to 0x%02x.\n",
			 data->emu_scur);
	}

	data->flashchip_contents = malloc(data->emu_chip_size);
	if (!data->flashchip_contents) {
		msg_perr("Out of memory!\n");
		return 1;
	}

	for (uint8_t region = 0; region < data->otp_region_count; ++region) {
		data->otp_region[region] = malloc(data->otp_region_size);
		if (!data->otp_region[region]) {
			msg_perr("Out of memory!\n");
			return 1;
		}
	}

	return 0;
}

static int dummy_init(void)
{
	struct stat image_stat;

	struct emu_data *data = calloc(1, sizeof(*data));
	if (!data) {
		msg_perr("Out of memory!\n");
		return 1;
	}
	data->emu_chip = EMULATE_NONE;
	data->delay_us = 0;
	data->spi_write_256_chunksize = 256;

	msg_pspew("%s\n", __func__);

	enum chipbustype dummy_buses_supported;
	if (init_data(data, &dummy_buses_supported)) {
		free(data);
		return 1;
	}

	if (data->emu_chip == EMULATE_NONE) {
		msg_pdbg("Not emulating any flash chip.\n");
		/* Nothing else to do. */
		goto dummy_init_out;
	}

	msg_pdbg("Filling fake flash chip with 0x%02x, size %i\n",
			data->erase_to_zero ? 0x00 : 0xff, data->emu_chip_size);
	memset(data->flashchip_contents, data->erase_to_zero ? 0x00 : 0xff, data->emu_chip_size);

	/* Will be freed by shutdown function if necessary. */
	data->emu_persistent_image = extract_programmer_param("image");
	/* We will silently (in default verbosity) ignore the file if it does not exist (yet) or the size does
	 * not match the emulated chip. */
	if (data->emu_persistent_image && !stat(data->emu_persistent_image, &image_stat)) {
		msg_pdbg("Found persistent image %s, %jd B ",
			 data->emu_persistent_image, (intmax_t)image_stat.st_size);
		if ((uintmax_t)image_stat.st_size == data->emu_chip_size) {
			msg_pdbg("matches.\n");
			msg_pdbg("Reading %s\n", data->emu_persistent_image);
			if (read_buf_from_file(data->flashchip_contents, data->emu_chip_size,
					   data->emu_persistent_image)) {
				msg_perr("Unable to read %s\n", data->emu_persistent_image);
				free(data->emu_persistent_image);
				free(data->flashchip_contents);
				free(data);
				return 1;
			}
		} else {
			msg_pdbg("doesn't match.\n");
		}
	}

	/* Silently (in default verbosity) ignore files that don't exist (yet)
	 * or whose size does not match the security register size on chip. */
	for (uint8_t region = 0; region < data->otp_region_count; ++region) {
		const uint16_t region_size = data->otp_region_size;

		char param_name[8];
		char *image_path;

		msg_pdbg("Filling fake security sector with 0xff, size %d bytes\n", region_size);
		memset(data->otp_region[region], data->erase_to_zero ? 0x00 : 0xff, region_size);

		snprintf(param_name, sizeof(param_name), "otp%d", region + 1);

		image_path = extract_programmer_param(param_name);
		if (!image_path)
			continue;

		data->otp_image_path[region] = image_path;

		if (stat(image_path, &image_stat)) {
			msg_pdbg("OTP region image doesn't exist: %s\n", image_path);
			continue;
		}

		msg_pdbg("Found persistent image %s, %jd B for security sector, ", image_path,
			 (intmax_t)image_stat.st_size);
		if (image_stat.st_size == region_size) {
			msg_pdbg("matches.\n");
			msg_pdbg("Reading %s\n", image_path);
			read_buf_from_file(data->otp_region[region], region_size, image_path);
		} else {
			msg_pdbg("doesn't match.\n");
		}
	}

dummy_init_out:
	if (register_shutdown(dummy_shutdown, data)) {
		free(data->emu_persistent_image);
		free(data->flashchip_contents);

		for (uint8_t region = 0; region < data->otp_region_count; ++region) {
			free(data->otp_region[region]);
			free(data->otp_image_path[region]);
		}

		free(data);
		return 1;
	}
	if (dummy_buses_supported & BUS_NONSPI)
		register_par_master(&par_master_dummyflasher,
				    dummy_buses_supported & BUS_NONSPI,
				    data);
	if (dummy_buses_supported & BUS_SPI)
		register_spi_master(&spi_master_dummyflasher, data);

	return 0;
}

int probe_variable_size(struct flashctx *flash)
{
	unsigned int i;
	const struct emu_data *emu_data = flash->mst->spi.data;

	/* Skip the probing if we don't emulate this chip. */
	if (!emu_data || emu_data->emu_chip != EMULATE_VARIABLE_SIZE)
		return 0;

	/*
	 * This will break if one day flashctx becomes read-only.
	 * Once that happens, we need to have special hacks in functions:
	 *
	 *     erase_and_write_flash() in flashrom.c
	 *     read_flash_to_file()
	 *     handle_romentries()
	 *     ...
	 *
	 * Search "total_size * 1024" in code.
	 */
	flash->chip->total_size = emu_data->emu_chip_size / 1024;
	msg_cdbg("%s: set flash->total_size to %dK bytes.\n", __func__,
	         flash->chip->total_size);

	if (emu_data->erase_to_zero)
		flash->chip->feature_bits |= FEATURE_ERASED_ZERO;

	/* Update the first count of each of the block_erasers. */
	for (i = 0; i < NUM_ERASEFUNCTIONS; i++) {
		struct block_eraser *eraser = &flash->chip->block_erasers[i];
		if (!eraser->block_erase)
			break;

		eraser->eraseblocks[0].count = 1;
		eraser->eraseblocks[0].size = emu_data->emu_chip_size;
		msg_cdbg("%s: eraser.size=%d, .count=%d\n",
		         __func__, eraser->eraseblocks[0].size,
		         eraser->eraseblocks[0].count);
	}

	return 1;
}

const struct programmer_entry programmer_dummy = {
	.name			= "dummy",
	.type			= OTHER,
				/* FIXME */
	.devs.note		= "Dummy device, does nothing and logs all accesses\n",
	.init			= dummy_init,
	.map_flash_region	= dummy_map,
	.unmap_flash_region	= dummy_unmap,
	.delay			= internal_delay,
};