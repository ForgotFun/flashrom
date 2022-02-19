/*
 * This file is part of the flashrom project.
 *
 * Copyright 2021 Google LLC
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

#include "flash.h"
#include "chipdrivers.h"

/* Protection range calculation that works with many common SPI flash chips.
 *
 * TODO: Rename this function when the extent of it's compatibility with
 * various chips is more fully known.
 */
void decode_range_w25(const struct flashrom_wp_chip_config *cfg, uint32_t chip_len, struct flashrom_wp_range *range)
{
	/* Interpret BP bits as an integer */
	uint32_t bp = 0;
	uint32_t bp_max = 0;
	for(size_t i = 0; i < cfg->bp_bit_count; i++) {
		bp |= cfg->bp[i] << i;
		bp_max |= 1 << i;
	}

	if (cfg->bp == 0) {
		/* Special case: all BP bits are 0 => no write protection */
		range->len = 0;
	} else if (bp == bp_max) {
		/* Special case: all BP bits are 1 => full write protection */
		range->len = chip_len;
	} else {
		/* Usual case: the BP bits encode a coefficient in the form
		 * `coeff = 2 ** (bp - 1)`.
		 *
		 * The range's length is given by multiplying the coefficient
		 * by a base unit, usually a 4K sector or a 64K block. */

		uint32_t coeff     = 1 << (bp - 1);
		uint32_t max_coeff = 1 << (bp_max - 2);

		uint32_t sector_len        = 4  * 1024;
		uint32_t default_block_len = 64 * 1024;

		if (cfg->sec_bit_present && cfg->sec == 1) {
			/* SEC=1, protect 4K sectors. Flash chips clamp the
			 * protection length at 32K, probably to avoid overlap
			 * with the SEC=0 case.
			 */
			range->len = min(sector_len * coeff, default_block_len / 2);
		} else {
			/* SEC=0 or is not present, protect blocks.
			 *
			 * With very large chips, the 'block' size can be
			 * larger than 64K. This occurs when a larger block
			 * size is needed so that half the chip can be
			 * protected by the maximum possible coefficient.
			 */
			uint32_t min_block_len = chip_len / 2 / max_coeff;
			uint32_t block_len = max(min_block_len, default_block_len);

			range->len = min(block_len * coeff, chip_len);
		}
	}

	/* Apply TB bit */
	bool protect_top = cfg->tb_bit_present ? (cfg->tb == 0) : 1;

	/* Apply CMP bit */
	if (cfg->cmp_bit_present && cfg->cmp == 1) {
		range->len = chip_len - range->len;
		protect_top = !protect_top;
	}

	/* Calculate start address, ensuring that empty ranges have start
	 * address of 0. */
	if (protect_top && range->len > 0)
		range->start = chip_len - range->len;
	else
		range->start = 0;
}
