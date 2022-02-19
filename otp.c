/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2016 Hatim Kanchwala <hatim at hatimak.me>
 * Copyright (C) 2021 3mdeb Embedded Systems Consulting
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "otp.h"

#include "chipdrivers.h"
#include "flash.h"

/*
 * TODO: Datasheets show 4 registers for program, but single 1024 B register
 *       for read and/or erase.
 * TODO: These chips have one control bit for all OTP regions.
 *
 *       GD25VQ16C, GD25VQ40C, GD25VQ80C, GD25Q16B, GD25Q32B, GD25Q64B,
 *       GD25Q80(B), GD25Q128B
 */

static bool bp_is_stashed;
static uint8_t stashed_bp_value;

/* Determines number of OTP regions of a flash. */
static int count_otp_regions(const struct flashctx *flash)
{
	int count = 0;
	struct otp_region *regions = flash->chip->otp->regions;

	while (regions[count].size != 0)
		count++;
	return count;
}

/**
 * @brief Determine if OTP operations are supported for the chip.
 *
 * @param[in] flash Initialized flash context.
 *
 * @return @c true  if WP operations are supported,
 *         @c false if WP operations are not suported.
 */
bool flashrom_otp_chip_supported(const struct flashrom_flashctx *flash)
{
	if (flash->chip->otp == NULL)
		return false;

	const int kind = (flash->chip->otp->feature_bits & (OTP_KIND_MODE | OTP_KIND_REGS));
	if (kind != OTP_KIND_MODE && kind != OTP_KIND_REGS)
		return false;

	const int nregions = count_otp_regions(flash);
	if (nregions == 0)
		return false;

	for (int i = 0; i < nregions; i++)
		if (flash->chip->otp->regions[i].user_lock.reg == INVALID_REG)
			return false;

	return true;
}

/**
 * @brief Retrieve list of OTP regions for a flash chip.
 *
 * @param[in]  flash   An initialized flash context with a supported chip.
 * @param[out] regions Array of at least @c FLASHROM_OTP_MAX_REGIONS elements.
 * @param[out] count   Number of filled in regions.
 *
 * @return 0 on success
 */
int flashrom_otp_get_regions(struct flashrom_flashctx *flash,
			     struct flashrom_otp_region *regions,
			     size_t *count)
{
	*count = count_otp_regions(flash);

	for (size_t i = 0; i < *count; i++) {
		regions[i].size = flash->chip->otp->regions[i].size;
		if (flashrom_otp_status(flash, i, &regions[i].locked))
			return 1;
	}

	return 0;
}

static int read_reg_bit(struct flashctx *flash, struct reg_bit_info bit, uint8_t *value)
{
	*value = 0;

	if (bit.reg == INVALID_REG)
		return 1;

	if (spi_read_register(flash, bit.reg, value))
		return 1;

	*value = (*value >> bit.bit_index) & 1;

	return 0;
}

static int write_reg_bit(struct flashctx *flash, struct reg_bit_info bit, uint8_t value)
{
	uint8_t reg_value;
	if (read_reg_bit(flash, bit, &reg_value))
		return 1;

	reg_value &= ~(1 << bit.bit_index);
	reg_value |= ((value & 1) << bit.bit_index);

	return spi_write_register(flash, bit.reg, reg_value);
}

/* Some standard error checking used by program and erase functions. */
static int otp_error_check(struct flashctx *flash, int region, size_t len)
{
	const int nregions = count_otp_regions(flash);
	if (region < 0 || region >= nregions) {
		msg_cdbg("Trying to access non-existent OTP region %d\n%s has only %d OTP regions\n",
			 region + 1, flash->chip->name, nregions);
		return 1;
	}
	if (len > flash->chip->otp->regions[region].size) {
		msg_cdbg("OTP region for %s is %d bytes\n", flash->chip->name,
			 flash->chip->otp->regions[region].size);
		return 1;
	}
	return 0;
}

static int get_bp_bits(struct flashctx *flash, uint8_t *bp)
{
	struct flashrom_wp_chip_config cfg;
	if (flashrom_wp_read_chip_config(flash, &cfg))
		return 1;

	*bp = 0;
	for (size_t i = 0; i < cfg.bp_bit_count; i++)
		*bp = (*bp << 1) | cfg.bp[i];

	return 0;
}

static int set_bp_bits(struct flashctx *flash, uint8_t bp)
{
	struct flashrom_wp_chip_config cfg;
	if (flashrom_wp_read_chip_config(flash, &cfg))
		return 1;

	for (size_t i = 0; i < cfg.bp_bit_count; i++)
		cfg.bp[i] = (bp >> (cfg.bp_bit_count - i + 1)) & 1;

	return flashrom_wp_write_chip_config(flash, &cfg);
}

static int enter_otp_mode(struct flashctx *flash)
{
	if (!(flash->chip->otp->feature_bits & OTP_KIND_MODE))
		return 0;

	uint8_t bp;
	if (get_bp_bits(flash, &bp)) {
		msg_cerr("Failed to read BP bits before entering OTP mode...\n");
		return 1;
	}

	if ((flash->chip->otp->feature_bits & OTP_MODE_CLEAR_BP) && bp != 0) {
		msg_cdbg("Need to unset all BP bits before entering OTP mode...\n");
		msg_cdbg("BP bits will be restored to 0x%02x\n", bp);
		stashed_bp_value = bp;
		bp_is_stashed = true;

		if (set_bp_bits(flash, 0)) {
			msg_cdbg("Couldn't unset BP bits\n");
			return 1;
		}
	}

	return spi_otp_mode_enter(flash);
}

static int exit_otp_mode(struct flashctx *flash)
{
	if (!(flash->chip->otp->feature_bits & OTP_KIND_MODE))
		return 0;

	int result = spi_otp_mode_exit(flash);
	if (result) {
		msg_cdbg("Couldn't exit OTP mode\n");
		return result;
	}

	/* Should only be set if OTP_MODE_CLEAR_BP is present. */
	if (bp_is_stashed) {
		bp_is_stashed = false;
		msg_cdbg("Restoring BP bits to their state prior to entering OTP mode ...\n");
		if (set_bp_bits(flash, stashed_bp_value))
			msg_cdbg("Couldn't restore BP bits\n");
	}

	return result;
}

/**
 * @brief Query status of an OTP region for a flash chip.
 *
 * @param[in]  flash  An initialized flash context with a supported chip.
 * @param[in]  region Base zero index of the OTP region.
 * @param[out] locked Whether the region is already locked.
 *
 * @return 0 on success
 */
int flashrom_otp_status(struct flashrom_flashctx *flash, int region, bool *locked)
{
	struct otp *otp = flash->chip->otp;

	if (otp_error_check(flash, region, 0)) {
		msg_cerr("%s failed\n", __func__);
		return 1;
	}

	if (enter_otp_mode(flash)) {
		msg_cerr("Error: Failed to enter OTP mode.\n");
		return 1;
	}

	int result = 0;
	*locked = false;

	uint8_t user_bit = 0;
	if (read_reg_bit(flash, otp->regions[region].user_lock, &user_bit)) {
		msg_cerr("Error: Failed to query user lock of OTP region %d.\n", region + 1);
		result = 1;
	} else {
		*locked = user_bit;
	}

	const struct reg_bit_info factory_lock = otp->regions[region].factory_lock;
	if (!*locked && factory_lock.reg != INVALID_REG) {
		uint8_t factory_bit = 0;
		if (read_reg_bit(flash, factory_lock, &factory_bit)) {
			msg_cerr("Error: Failed to query factory lock of OTP region %d.\n", region + 1);
			result = 1;
		} else {
			*locked = factory_bit;
		}
	}

	if (exit_otp_mode(flash)) {
		msg_cerr("Error: Failed to leave OTP mode.\n");
		return 1;
	}

	return result;
}

/**
 * @brief Read @p len bytes from OTP region.
 *
 * @param[in]  flash  An initialized flash context with a supported chip.
 * @param[in]  region Base zero index of the OTP region.
 * @param[out] buf    Buffer for the data.
 * @param[in]  len    Buffer size.
 *
 * @return 0 on success
 */
int flashrom_otp_read(struct flashctx *flash, int region, void *buf, size_t len)
{
	struct otp *otp = flash->chip->otp;

	int result = otp_error_check(flash, region, len);
	if (result) {
		msg_cerr("%s failed\n", __func__);
		return result;
	}

	if (enter_otp_mode(flash)) {
		msg_cerr("Error: Failed to enter OTP mode.\n");
		return 1;
	}

	if (flash->chip->otp->feature_bits & OTP_KIND_MODE)
		result = flash->chip->read(flash, buf, otp->regions[region].addr, len);
	else if (flash->chip->otp->feature_bits & OTP_KIND_REGS)
		result = spi_sec_reg_read(flash, buf, otp->regions[region].addr, len);
	else
		result = 1;

	if (exit_otp_mode(flash)) {
		msg_cerr("Error: Failed to leave OTP mode.\n");
		return 1;
	}

	if (result)
		msg_cerr("%s failed\n", __func__);
	return result;
}

/**
 * @brief Write @p len bytes to OTP region.
 *
 * @param[in] flash  An initialized flash context with a supported chip.
 * @param[in] region Base zero index of the OTP region.
 * @param[in] buf    Buffer with the data.
 * @param[in] len    Buffer size.
 *
 * @return 0 on success
 */
int flashrom_otp_write(struct flashctx *flash, int region, const void *buf, size_t len)
{
	struct otp *otp = flash->chip->otp;

	int result = otp_error_check(flash, region, len);
	if (result) {
		msg_cerr("%s failed\n", __func__);
		return result;
	}

	bool locked;
	if (flashrom_otp_status(flash, region, &locked))
		return 1;

	if (locked) {
		msg_cdbg("OTP region %d is permanently locked and cannot be written to\n",
			 region + 1);
		msg_cerr("%s failed\n", __func__);
		return 1;
	}

	if (enter_otp_mode(flash)) {
		msg_cerr("Error: Failed to enter OTP mode.\n");
		return 1;
	}

	if (flash->chip->otp->feature_bits & OTP_KIND_MODE)
		result = flash->chip->write(flash, buf, otp->regions[region].addr, len);
	else if (flash->chip->otp->feature_bits & OTP_KIND_REGS)
		result = spi_sec_reg_prog(flash, buf, flash->chip->otp->regions[region].addr, len);
	else
		result = 1;

	if (exit_otp_mode(flash)) {
		msg_cerr("Error: Failed to leave OTP mode.\n");
		return 1;
	}

	if (result)
		msg_cerr("%s failed\n", __func__);
	return result;
}

/**
 * @brief Erase OTP region.
 *
 * @param[in] flash  An initialized flash context with a supported chip.
 * @param[in] region Base zero index of the OTP region.
 *
 * @return 0 on success
 */
int flashrom_otp_erase(struct flashctx *flash, int region)
{
	struct otp *otp = flash->chip->otp;

	int result = otp_error_check(flash, region, 0);
	if (result) {
		msg_cdbg("%s failed\n", __func__);
		return result;
	}

	bool locked;
	if (flashrom_otp_status(flash, region, &locked))
		return 1;

	if (locked) {
		msg_cdbg("OTP region %d is permanently locked and cannot be written to\n",
			 region + 1);
		msg_cdbg("%s failed\n", __func__);
		return 1;
	}

	if (enter_otp_mode(flash)) {
		msg_cerr("Error: Failed to enter OTP mode.\n");
		return 1;
	}

	if (flash->chip->otp->feature_bits & OTP_KIND_MODE)
		result = spi_block_erase_20(flash, otp->regions[region].addr, otp->regions[region].size);
	else if (flash->chip->otp->feature_bits & OTP_KIND_REGS)
		result = spi_sec_reg_erase(flash, flash->chip->otp->regions[region].addr);
	else
		result = 1;

	if (exit_otp_mode(flash)) {
		msg_cerr("Error: Failed to leave OTP mode.\n");
		return 1;
	}

	if (result)
		msg_cdbg("%s failed\n", __func__);
	return result;
}

/**
 * @brief Lock OTP region.
 *
 * @param[in] flash  An initialized flash context with a supported chip.
 * @param[in] region Base zero index of the OTP region.
 *
 * @return 0 on success or if the region is already locked
 */
int flashrom_otp_lock(struct flashctx *flash, int region)
{
	struct otp *otp = flash->chip->otp;

	if (otp_error_check(flash, region, 0)) {
		msg_cerr("%s failed\n", __func__);
		return 1;
	}

	bool locked;
	if (flashrom_otp_status(flash, region, &locked))
		return 1;

	if (locked) {
		msg_cdbg("OTP modifier bit is already set and it's one-time-programmable\n");
		return 1;
	}

	if ((otp->feature_bits & OTP_MODE_LOCK_WHILE_IN) && enter_otp_mode(flash)) {
		msg_cerr("Error: Failed to enter OTP mode.\n");
		return 1;
	}

	int result = write_reg_bit(flash, otp->regions[region].user_lock, 1);

	if ((otp->feature_bits & OTP_MODE_LOCK_WHILE_IN) && exit_otp_mode(flash)) {
		msg_cerr("Error: Failed to leave OTP mode.\n");
		return 1;
	}

	if (result || flashrom_otp_status(flash, region, &locked) || !locked) {
		msg_cerr("Unable to set OTP modifier bit\n");
		return 1;
	}

	return 0;
}
