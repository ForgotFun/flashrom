/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2010 Google Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flash.h"
#include "libflashrom.h"
#include "chipdrivers.h"


#define wp_chip_config flashrom_wp_chip_config
#define wp_range flashrom_wp_range
#define wp_mode flashrom_wp_mode


/**
 * @brief Determine if WP operations are supported with a flash context/chip.
 * @param[in] flash Initialized flash context.
 *
 * @return true  if WP operations are supported,
 *         false if WP operations are not suported.
 */
bool flashrom_wp_chip_supported(const struct flashctx *flash)
{
	return (flash->chip != NULL) && (flash->chip->decode_range != NULL);
}


/** Read and extract a single bit from a chip's status/config registers */
static int read_reg_bit(const struct flashctx *flash, struct reg_bit_info bit, uint8_t *value, bool *present)
{
	*value = 0;
	*present = bit.reg != INVALID_REG;

	if (*present) {
		int ret = spi_read_register(flash, bit.reg, value);
		if (ret)
			return ret;
		*value = (*value >> bit.bit_index) & 1;
	}

	return 0;
}

/**
 * @brief Read the WP configuration from a flash chip.
 *
 * @param[in]  flash An initialized flash context with a supported chip.
 * @param[out] cfg   WP configuration read from the chip.
 *
 * @return 0 on success
 */
int flashrom_wp_read_chip_config(const struct flashctx *flash, struct wp_chip_config *cfg)
{
	/* Use the chip's register bit layout to determine what registers to
	 * read and how to intrepret their contents. */
	const struct reg_bit_map *bits = &flash->chip->reg_bits;
	bool tmp;

	*cfg = (struct wp_chip_config) {0};

	int ret = 0;
	ret |= read_reg_bit(flash, bits->tb,  &cfg->tb,  &cfg->tb_bit_present);
	ret |= read_reg_bit(flash, bits->sec, &cfg->sec, &cfg->sec_bit_present);
	ret |= read_reg_bit(flash, bits->cmp, &cfg->cmp, &cfg->cmp_bit_present);

	for(size_t i = 0; bits->bp[i].reg != INVALID_REG; i++) {
		ret |= read_reg_bit(flash, bits->bp[i], &cfg->bp[i], &tmp);
		cfg->bp_bit_count = i + 1;
	}

	for(size_t i = 0; bits->srp[i].reg != INVALID_REG; i++) {
		ret |= read_reg_bit(flash, bits->srp[i], &cfg->srp[i], &tmp);
		cfg->srp_bit_count = i + 1;
	}

	return ret;
}

/** Helper function for flashrom_wp_write_chip_config that sets a single bit in
 *  an array of register values and an array of write masks. */
static void set_reg_bit(
		uint8_t *reg_values, uint8_t *write_masks,
		struct reg_bit_info bit, uint8_t value)
{
	if (bit.reg != INVALID_REG) {
		reg_values[bit.reg] |= value << bit.bit_index;
		write_masks[bit.reg] |= 1 << bit.bit_index;
	}
}

/**
 * @brief Write a WP configuration to a flash chip.
 *
 * @param[in] flash An initialized flash context with a supported chip.
 * @param[in] cfg   The WP configuration to write to the chip.
 *
 * @return 0 on success
 */
int flashrom_wp_write_chip_config(struct flashctx *flash, const struct wp_chip_config *cfg)
{
	const struct reg_bit_map *bits = &flash->chip->reg_bits;

	/* Convert wp_chip_config to register values / write masks */
	uint8_t reg_values[MAX_REGISTERS] = {0};
	uint8_t write_masks[MAX_REGISTERS] = {0};

	for (size_t i = 0; i < cfg->srp_bit_count; i++)
		set_reg_bit(reg_values, write_masks, bits->srp[i], cfg->srp[i]);

	for (size_t i = 0; i < cfg->bp_bit_count; i++)
		set_reg_bit(reg_values, write_masks, bits->bp[i], cfg->bp[i]);

	set_reg_bit(reg_values, write_masks, bits->tb,  cfg->tb);
	set_reg_bit(reg_values, write_masks, bits->sec, cfg->sec);
	set_reg_bit(reg_values, write_masks, bits->cmp, cfg->cmp);

	/* Write each register */
	for (enum flash_reg reg = INVALID_REG; reg < MAX_REGISTERS; reg++) {
		if (!write_masks[reg])
			continue;

		uint8_t value = 0;
		int ret = spi_read_register(flash, reg, &value);
		if (ret)
			return ret;

		value = (value & ~write_masks[reg]) | (reg_values[reg] & write_masks[reg]);

		ret = spi_write_register(flash, reg, value);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * @brief Compare two WP configurations.
 *
 * Can be used to determine if two WP configuraitons are equal and to decide
 * which of two configurations should be used if they both select the same
 * protection range.
 *
 * @param[in] cfga The first configuration to compare.
 * @param[in] cfgb The second configuration to compare.
 *
 * @return -1 if the configurations are not equal and cfga is preferred,
 *          0 if the configurations are equal,
 *          1 if the configurations are not equal and cfgb is preferred.
 */
int flashrom_wp_compare_chip_configs(const struct flashrom_wp_chip_config *cfga, const struct flashrom_wp_chip_config *cfgb)
{
	int ord = 0;

	for (int i = cfga->srp_bit_count - 1; i >= 0; i--) {
		if (ord == 0)
			ord = cfga->srp[i] - cfgb->srp[i];
	}

	if (ord == 0)
		ord = cfga->cmp - cfgb->cmp;
	if (ord == 0)
		ord = cfga->sec - cfgb->sec;
	if (ord == 0)
		ord = cfga->tb  - cfgb->tb;

	for (int i = cfga->bp_bit_count - 1; i >= 0; i--) {
		if (ord == 0)
			ord = cfga->bp[i] - cfgb->bp[i];
	}

	return ord;
}

/** Struct for storing a range and the WP configuration that selects it. */
struct wp_range_cfg_pair {
	struct wp_range range;
	struct wp_chip_config cfg;
};

/**
 * Used for sorting range/configuraration pairs in get_range_cfg_pairs().
 * Ensures that when two configurations produce the same range, the preferred
 * configuration is ordered first.
 */
static int range_sort_compare_func(const void *aa, const void *bb)
{
	const struct wp_range_cfg_pair
		*a = (const struct wp_range_cfg_pair *)aa,
		*b = (const struct wp_range_cfg_pair *)bb;

	int ord = 0;

	/* List shorter ranges first. */
	if (ord == 0)
		ord = a->range.len - b->range.len;

	/* For equal length ranges, list the one with a lower start address
	 * first. */
	if (ord == 0)
		ord = a->range.start - b->range.start;

	/* Ranges a and b are identical, order them by the status/config
	 * register bits that are used to select them. */
	if (ord == 0)
		ord = flashrom_wp_compare_chip_configs(&a->cfg, &b->cfg);

	return ord;
}

static bool can_write_bit(const struct reg_bit_info bit)
{
	return bit.reg != INVALID_REG && bit.writability == RW;
}

/**
 * Enumerates all valid WP configurations for the chip and determines what
 * protection range each one will select.  Returns a list of deduplicated
 * range/configuration pairs.
 */
static int get_range_cfg_pairs(const struct flashctx *flash, const struct wp_chip_config *current_cfg, struct wp_range_cfg_pair *ranges, size_t *count)
{
	/* Make a copy of the current config to use as a basis when generating
	 * new configurations that select different ranges. */
	struct wp_chip_config cfg = *current_cfg;

	/* Create a list of bits that affect the chip's protection range and
	 * that can be changed. Some chips have range bits that cannot be
	 * changed (e.g. TB in a OTP register), and their original value must
	 * be perserved to avoid enumerating ranges that are not actually
	 * available. */
	const struct reg_bit_map *bits = &flash->chip->reg_bits;
	uint8_t *range_bits[20];
	size_t bit_count = 0;

	for (size_t i = 0; can_write_bit(bits->bp[i]); i++)
		range_bits[bit_count++] = &cfg.bp[i];

	if (can_write_bit(bits->tb))
		range_bits[bit_count++] = &cfg.tb;

	if (can_write_bit(bits->sec))
		range_bits[bit_count++] = &cfg.sec;

	if (can_write_bit(bits->cmp))
		range_bits[bit_count++] = &cfg.cmp;

	/* Enumerate all values the range bits can take and find the range
	 * associated with each one. */
	*count = (1 << bit_count);
	for (uint32_t range_index = 0; range_index < *count; range_index++) {
		/* Extract bits from the range index and assign them to bits in
		 * the cfg structure. */
		for (size_t i = 0; i < bit_count; i++)
			*range_bits[i] = (range_index >> i) & 1;

		/* Get range using chip-specific decoding function */
		ranges[range_index].cfg = cfg;
		flashrom_wp_get_range(flash, &cfg, &ranges[range_index].range);

		/* Debug: print config and range */
		char cfg_buf[FLASHROM_WP_OUT_STR_SIZE];
		char range_buf[FLASHROM_WP_OUT_STR_SIZE];
		flashrom_wp_config_to_str(&cfg, cfg_buf);
		flashrom_wp_range_to_str(flash, &ranges[range_index].range, range_buf);
		msg_gdbg("Enumerated range:  %s :  %s\n", cfg_buf, range_buf);
	}

	/* Sort ranges */
	qsort(ranges, *count, sizeof(*ranges), range_sort_compare_func);

	/* Remove duplicates */
	size_t output_index = 0;
	struct wp_range *last_range = NULL;
	for (size_t i = 0; i < *count; i++) {
		bool different_to_last =
			(last_range == NULL) ||
			(ranges[i].range.start != last_range->start) ||
			(ranges[i].range.len   != last_range->len);

		if (different_to_last) {
			/* Move range to the next free position */
			ranges[output_index] = ranges[i];
			output_index++;
			/* Keep track of last non-duplicate range */
			last_range = &ranges[i].range;
		}
	}
	/* Reduce count to only include non-duplicate ranges */
	*count = output_index;

	return 0;
}

/**
 * @brief Get a list of all protection ranges that are available on a flash chip.
 *
 * Note: some chips have read-only or OTP bits that affect the protection range.
 * This function assumes those bits cannot be changed and only returns ranges
 * that can be activated without changing them.
 *
 * @param[in]  cfg    The flash chip's current WP configuration.
 * @param[out] ranges Array of available ranges. The caller must pass an array
 * 		      with least FLASHROM_WP_MAX_RANGES elements.
 * @param[out] count  The number of available ranges.
 *
 * @return 0 on success
 */
int flashrom_wp_get_available_ranges(const struct flashctx *flash, const struct wp_chip_config *cfg, struct wp_range *ranges, size_t *count)
{
	struct wp_range_cfg_pair range_cfg_pairs[FLASHROM_WP_MAX_RANGES];

	if (get_range_cfg_pairs(flash, cfg, range_cfg_pairs, count))
		return 1;

	for (size_t i = 0; i < *count; i++)
		ranges[i] = range_cfg_pairs[i].range;

	return 0;
}

/**
 * @brief Get the range selected by a WP configuration.
 *
 * @param[in]  cfg   A flash chip's WP configuration.
 * @param[out] range The range selected by the configuration.
 *
 * @return 0 on success
 */
int flashrom_wp_get_range(const struct flashctx *flash, const struct wp_chip_config *cfg, struct wp_range *range)
{
	flash->chip->decode_range(cfg, flashrom_flash_getsize(flash), range);

	return 0;
}

/**
 * @brief Modify a WP configuration to select a specified range.
 *
 * Note: the modified configuration must be written back to the chip using
 * flashrom_wp_write_chip_config().
 *
 * @param[in,out] cfg   The configuration to be modified.
 * @param[in]     range The range to select.
 *
 * @return 0 on success
 */
int flashrom_wp_set_range(const struct flashctx *flash, struct wp_chip_config *cfg, const struct wp_range *range)
{
	struct wp_range_cfg_pair range_cfg_pairs[FLASHROM_WP_MAX_RANGES];
	size_t count;

	if (get_range_cfg_pairs(flash, cfg, range_cfg_pairs, &count))
		return 1;

	/* Search for matching range */
	for (size_t i = 0; i < count; i++) {
		struct wp_range *range_i = &range_cfg_pairs[i].range;
		if (range_i->start == range->start && range_i->len == range->len) {
			/* Overwrite cfg with matching range */
			*cfg = range_cfg_pairs[i].cfg;
			return 0;
		}
	}

	return 1;
}

/**
 * @brief Get the mode selected by a WP configuration.
 *
 * @param[in]  cfg  A flash chip's WP configuration.
 * @param[out] mode The mode selected by the configuration.
 *
 * @return 0 on success
 */

int flashrom_wp_get_mode(const struct wp_chip_config *cfg, enum wp_mode *mode)
{
	enum wp_mode mode_table[] = {
		WP_MODE_DISABLED,
		WP_MODE_HARDWARE,
		WP_MODE_POWER_CYCLE,
		WP_MODE_PERMANENT,
	};

	uint8_t srp = 0;
	for (size_t i = 0; i < cfg->srp_bit_count; i++)
		srp |= cfg->srp[i] << i;

	if (srp > 3)
		return 1;

	*mode = mode_table[srp];
	return 0;
}

/**
 * @brief Modify a WP configuration so that it will select a specified mode.
 *
 * Note: the modified configuration must be written back to the chip using
 * flashrom_wp_write_chip_config().
 *
 * @param[in,out] cfg  The configuration to be modified.
 * @param[in]     mode The mode to select.
 *
 * @return 0 on success
 */
int flashrom_wp_set_mode(struct wp_chip_config *cfg, const enum wp_mode mode)
{
	/* Always need SRP0 to select hardware/software protection */
	if (cfg->srp_bit_count < 1)
		return 1;

	if(mode == WP_MODE_DISABLED) {
		/* Clear all SRP bits */
		for (size_t i = 0; i < cfg->srp_bit_count; i++)
			cfg->srp[i] = 0;

		return 0;
	}

	if(mode == WP_MODE_HARDWARE) {
		/* Clear all SRP bits */
		for (size_t i = 0; i < cfg->srp_bit_count; i++)
			cfg->srp[i] = 0;

		cfg->srp[0] = 1;

		return 0;
	}

	/*
	 * Don't try to enable power cycle or permanent protection for
	 * now. Those modes may be possible to activate on some chips,
	 * but they are usually unavailable by default or require special
	 * commands to activate.
	 */
	return 1;
}

/**
 * @brief Create a string representing a WP configuration.
 *
 * @param[in]  cfg The configuration to convert to a string.
 * @param[out] buf The buffer to write the string representation to.
 *                 Must be at least FLASHROM_WP_OUT_STR_SIZE chars.
 *
 * @return 0 on success
 */
int flashrom_wp_config_to_str(const struct wp_chip_config *cfg, char *buf)
{
	for (int i = cfg->srp_bit_count - 1; i >= 0; i--)
		buf += sprintf(buf, "SRP%d=%u ", i, cfg->srp[i]);

	if (cfg->cmp_bit_present)
		buf += sprintf(buf, "CMP=%u ", cfg->cmp);

	if (cfg->sec_bit_present)
		buf += sprintf(buf, "SEC=%u ", cfg->sec);

	if (cfg->tb_bit_present)
		buf += sprintf(buf, "TB=%u ",  cfg->tb);

	for (int i = cfg->bp_bit_count - 1; i >= 0; i--)
		buf += sprintf(buf, "BP%d=%u ", i, cfg->bp[i]);

	return 0;
}

/**
 * @brief Create a string representing a WP range.
 *
 * @param[in]  range The range to convert to a string.
 * @param[out] buf   The buffer to write the string representation to.
 *                   Must be at least FLASHROM_WP_OUT_STR_SIZE chars.
 *
 * @return 0 on success
 */
int flashrom_wp_range_to_str(const struct flashctx *flash, const struct wp_range *range, char *buf)
{
	uint32_t chip_len = flashrom_flash_getsize(flash);

	/* Start address and length */
	buf += sprintf(buf, "start=0x%08x length=0x%08x ", range->start, range->len);

	/* Easily readable description like 'none' or 'lower 1/8' */
	if (range->len == 0) {
		strcpy(buf, "(none)");
	} else if (range->len == chip_len) {
		strcpy(buf, "(all)");
	} else {
		uint32_t range_len = range->len;

		/* Remove common factors of 2 to simplify range length fraction. */
		while ((chip_len % 2) == 0 && (range_len % 2) == 0) {
			chip_len /= 2;
			range_len /= 2;
		}

		const char *location = (range->start == 0) ? "lower" : "upper";
		sprintf(buf, "(%s %d/%d)", location, range_len, chip_len);
	}

	return 0;
}

/**
 * @brief Create a string representing a WP mode.
 *
 * @param[in]  mode The mode to convert to a string.
 * @param[out] buf  The buffer to write the string representation to.
 *                  Must be at least FLASHROM_WP_OUT_STR_SIZE chars.
 *
 * @return 0 on success
 */
int flashrom_wp_mode_to_str(const enum wp_mode mode, char *buf)
{
	switch (mode) {
	case WP_MODE_DISABLED:
		strcpy(buf, "disabled");
		return 0;
	case WP_MODE_HARDWARE:
		strcpy(buf, "hardware");
		return 0;
	case WP_MODE_POWER_CYCLE:
		strcpy(buf, "power_cycle");
		return 0;
	case WP_MODE_PERMANENT:
		strcpy(buf, "permanent");
		return 0;
	}

	return 1;
}
