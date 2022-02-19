/*
 * This file is part of the flashrom project.
 *
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
 */

#include <include/test.h>
#include <string.h>

#include "chipdrivers.h"
#include "flash.h"
#include "libflashrom.h"
#include "otp.h"
#include "programmer.h"

/*
 * Tests in this file do not use any mocking, because using OTP emulation in
 * dummyflasher programmer is sufficient
 */

enum { MAX_REGION_SIZE = 512 };

/* This data is used in multiple tests */
static uint8_t empty[MAX_REGION_SIZE];
static uint8_t image[MAX_REGION_SIZE];

static void setup(struct flashrom_flashctx *flash, struct flashchip *chip, const char *programmer_param)
{
	flash->chip = chip;

	assert_int_equal(0, programmer_init(&programmer_dummy, programmer_param));
	/* Assignment below normally happens while probing, but this test is not probing. */
	flash->mst = &registered_masters[0];

	for (unsigned int i = 0; i < MAX_REGION_SIZE; i++) {
		empty[i] = 0xff;
		image[i] = i;
	}
}

static void teardown(void)
{
	assert_int_equal(0, programmer_shutdown());
}

/* Setup the struct for W25Q128.V, all values come from flashchips.c */
static const struct flashchip chip_W25Q128_V = {
	.vendor		= "aklm&dummyflasher",
	.total_size	= 16 * 1024,
	.tested		= TEST_OK_PREW,
	.read		= spi_chip_read,
	.write		= spi_chip_write_256,
	.unlock         = spi_disable_blockprotect,
	.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP |
			  FEATURE_WRSR2 | FEATURE_RDSR2,
	.block_erasers  =
	{
		{
			.eraseblocks = { {4 * 1024, 4096} },
			.block_erase = spi_block_erase_20,
		}, {
			.eraseblocks = { {32 * 1024, 512} },
			.block_erase = spi_block_erase_52,
		}, {
			.eraseblocks = { {64 * 1024, 256} },
			.block_erase = spi_block_erase_d8,
		}, {
			.eraseblocks = { {16 * 1024 * 1024, 1} },
			.block_erase = spi_block_erase_60,
		}, {
			.eraseblocks = { {16 * 1024 * 1024, 1} },
			.block_erase = spi_block_erase_c7,
		}
	},
	.otp		= &gd_w256_3_otp,
};

/* Setup the struct for EN25QH128, all values come from flashchips.c */
static const struct flashchip chip_EN25QH128 = {
	.vendor		= "aklm&dummyflasher",
	.total_size	= 16384,
	.page_size	= 256,
	.feature_bits	= FEATURE_WRSR_WREN | FEATURE_QPI,
	.tested		= TEST_OK_PREW,
	.block_erasers	=
	{
		{
			.eraseblocks = { {4 * 1024, 4096} },
			.block_erase = spi_block_erase_20,
		}, {
			.eraseblocks = { {64 * 1024, 256} },
			.block_erase = spi_block_erase_d8,
		}, {
			.eraseblocks = { { 16384 * 1024, 1} },
			.block_erase = spi_block_erase_60,
		}, {
			.eraseblocks = { { 16384 * 1024, 1} },
			.block_erase = spi_block_erase_c7,
		}
	},
	.unlock		= spi_disable_blockprotect_bp3_srwd,
	.write		= spi_chip_write_256,
	.read		= spi_chip_read,
	.otp		= &en512_16384otp,
};

/* Setup the struct for MX25L6436, all values come from flashchips.c */
static const struct flashchip chip_MX25L6436 = {
	.vendor		= "aklm&dummyflasher",
	.total_size	= 8192,
	.page_size	= 256,
	.feature_bits	= FEATURE_WRSR_WREN | FEATURE_OTP | FEATURE_SCUR,
	.tested		= TEST_OK_PREW,
	.block_erasers	=
	{
		{
			.eraseblocks = { {4 * 1024, 2048} },
			.block_erase = spi_block_erase_20,
		}, {
			.eraseblocks = { {32 * 1024, 256} },
			.block_erase = spi_block_erase_52,
		}, {
			.eraseblocks = { {64 * 1024, 128} },
			.block_erase = spi_block_erase_d8,
		}, {
			.eraseblocks = { {8 * 1024 * 1024, 1} },
			.block_erase = spi_block_erase_60,
		}, {
			.eraseblocks = { {8 * 1024 * 1024, 1} },
			.block_erase = spi_block_erase_c7,
		}
	},
	.unlock		= spi_disable_blockprotect_bp3_srwd,
	.write		= spi_chip_write_256,
	.read		= spi_chip_read, /* Fast read (0x0B) and multi I/O supported */
	.otp		= &mx512otp,
};

void otp_regs_status_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV");

	setup(&flash, &mock_chip, param_dup);

	assert_true(flashrom_otp_chip_supported(&flash));

	size_t nregions;
	struct flashrom_otp_region regions[FLASHROM_OTP_MAX_REGIONS];
	assert_int_equal(0, flashrom_otp_get_regions(&flash, regions, &nregions));
	assert_int_equal(3, nregions);
	assert_int_equal(256, regions[0].size);
	assert_false(regions[0].locked);
	assert_int_equal(256, regions[1].size);
	assert_false(regions[1].locked);
	assert_int_equal(256, regions[2].size);
	assert_false(regions[2].locked);

	bool locked;
	assert_int_equal(0, flashrom_otp_status(&flash, 0, &locked));
	assert_false(locked);
	assert_int_equal(0, flashrom_otp_status(&flash, 1, &locked));
	assert_false(locked);
	assert_int_equal(0, flashrom_otp_status(&flash, 2, &locked));
	assert_false(locked);

	teardown();

	free(param_dup);
}

void otp_mode_status_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_EN25QH128;

	char *param_dup = strdup("bus=spi,emulate=EN25QH128");

	setup(&flash, &mock_chip, param_dup);

	assert_true(flashrom_otp_chip_supported(&flash));

	size_t nregions;
	struct flashrom_otp_region regions[FLASHROM_OTP_MAX_REGIONS];
	assert_int_equal(0, flashrom_otp_get_regions(&flash, regions, &nregions));
	assert_int_equal(1, nregions);
	assert_int_equal(512, regions[0].size);
	assert_false(regions[0].locked);

	bool locked;
	assert_int_equal(0, flashrom_otp_status(&flash, 0, &locked));
	assert_false(locked);

	teardown();

	free(param_dup);
}

void otp_regs_locking_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV");

	setup(&flash, &mock_chip, param_dup);

	assert_int_equal(0, flashrom_otp_lock(&flash, 0));
	assert_int_equal(0, flashrom_otp_lock(&flash, 2));
	/* No such regions */
	assert_int_equal(1, flashrom_otp_lock(&flash, -1));
	assert_int_equal(1, flashrom_otp_lock(&flash, 3));

	size_t nregions;
	struct flashrom_otp_region regions[FLASHROM_OTP_MAX_REGIONS];
	assert_int_equal(0, flashrom_otp_get_regions(&flash, regions, &nregions));
	assert_int_equal(3, nregions);
	assert_int_equal(256, regions[0].size);
	assert_true(regions[0].locked);
	assert_int_equal(256, regions[1].size);
	assert_false(regions[1].locked);
	assert_int_equal(256, regions[2].size);
	assert_true(regions[2].locked);

	assert_int_equal(0, flashrom_otp_lock(&flash, 1));

	bool locked;
	assert_int_equal(0, flashrom_otp_status(&flash, 0, &locked));
	assert_true(locked);
	assert_int_equal(0, flashrom_otp_status(&flash, 1, &locked));
	assert_true(locked);
	assert_int_equal(0, flashrom_otp_status(&flash, 2, &locked));
	assert_true(locked);

	teardown();

	free(param_dup);
}

void otp_mode_locking_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_EN25QH128;

	char *param_dup = strdup("bus=spi,emulate=EN25QH128");

	setup(&flash, &mock_chip, param_dup);

	assert_int_equal(0, flashrom_otp_lock(&flash, 0));

	size_t nregions;
	struct flashrom_otp_region regions[FLASHROM_OTP_MAX_REGIONS];
	assert_int_equal(0, flashrom_otp_get_regions(&flash, regions, &nregions));
	assert_int_equal(1, nregions);
	assert_int_equal(512, regions[0].size);
	assert_true(regions[0].locked);

	teardown();

	free(param_dup);
}

void otp_regs_ops_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	enum { REGION_SIZE = 256 };

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;
	uint8_t buf[REGION_SIZE];

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV");

	setup(&flash, &mock_chip, param_dup);

	/* Write image for the first region */
	assert_int_equal(0, flashrom_otp_write(&flash, 0, image, REGION_SIZE));

	/* Check that we read back what we've written */
	assert_int_equal(0, flashrom_otp_read(&flash, 0, buf, REGION_SIZE));
	assert_memory_equal(buf, image, REGION_SIZE);

	/* Check that other regions are still empty */
	assert_int_equal(0, flashrom_otp_read(&flash, 1, buf, REGION_SIZE));
	assert_memory_equal(buf, empty, REGION_SIZE);
	assert_int_equal(0, flashrom_otp_read(&flash, 2, buf, REGION_SIZE));
	assert_memory_equal(buf, empty, REGION_SIZE);

	/* Can erase regions */
	assert_int_equal(0, flashrom_otp_erase(&flash, 0));
	assert_int_equal(0, flashrom_otp_read(&flash, 0, buf, REGION_SIZE));
	assert_memory_equal(buf, empty, REGION_SIZE);

	teardown();

	free(param_dup);
}

void otp_mode_ops_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	enum { REGION_SIZE = 512 };

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_EN25QH128;
	uint8_t buf[REGION_SIZE];

	char *param_dup = strdup("bus=spi,emulate=EN25QH128");

	setup(&flash, &mock_chip, param_dup);

	/* Write image */
	assert_int_equal(0, flashrom_otp_write(&flash, 0, image, REGION_SIZE));

	/* Check that we read back what we've written */
	assert_int_equal(0, flashrom_otp_read(&flash, 0, buf, REGION_SIZE));
	assert_memory_equal(buf, image, REGION_SIZE);

	teardown();

	free(param_dup);
}

void otp_regs_in_locked_state_test_success(void **state)
{
	(void) state; /* unused */

	enum { REGION_SIZE = 256 };

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;
	uint8_t buf[REGION_SIZE];

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV");

	setup(&flash, &mock_chip, param_dup);

	/* Write first region and lock it */
	assert_int_equal(0, flashrom_otp_write(&flash, 0, image, REGION_SIZE));
	assert_int_equal(0, flashrom_otp_lock(&flash, 0));

	/* Lost ability to write or erase it */
	assert_int_equal(1, flashrom_otp_write(&flash, 0, image, REGION_SIZE));
	assert_int_equal(1, flashrom_otp_erase(&flash, 0));

	/* Can still write or erase other regions */
	assert_int_equal(0, flashrom_otp_write(&flash, 1, image, REGION_SIZE));
	assert_int_equal(0, flashrom_otp_write(&flash, 2, image, REGION_SIZE));
	assert_int_equal(0, flashrom_otp_erase(&flash, 1));
	assert_int_equal(0, flashrom_otp_erase(&flash, 2));

	/* Region's content is correct after all manipulations */
	assert_int_equal(0, flashrom_otp_read(&flash, 0, buf, REGION_SIZE));
	assert_memory_equal(buf, image, REGION_SIZE);

	teardown();

	free(param_dup);
}

void otp_mode_in_locked_state_test_success(void **state)
{
	(void) state; /* unused */

	enum { REGION_SIZE = 512 };

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_EN25QH128;
	uint8_t buf[REGION_SIZE];

	char *param_dup = strdup("bus=spi,emulate=EN25QH128");

	setup(&flash, &mock_chip, param_dup);

	/* Write first region and lock it */
	assert_int_equal(0, flashrom_otp_write(&flash, 0, image, REGION_SIZE));
	assert_int_equal(0, flashrom_otp_lock(&flash, 0));

	/* Lost ability to write or erase it */
	assert_int_equal(1, flashrom_otp_write(&flash, 0, image, REGION_SIZE));
	assert_int_equal(1, flashrom_otp_erase(&flash, 0));

	/* Region's content is correct after all manipulations */
	assert_int_equal(0, flashrom_otp_read(&flash, 0, buf, REGION_SIZE));
	assert_memory_equal(buf, image, REGION_SIZE);

	teardown();

	free(param_dup);
}

void otp_scur_user_lock_test_success(void **state)
{
	(void) state; /* unused */

	enum { REGION_SIZE = 512 };

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_MX25L6436;
	uint8_t buf[REGION_SIZE];

	char *param_dup = strdup("bus=spi,emulate=MX25L6436");

	setup(&flash, &mock_chip, param_dup);

	/* Write region and lock it */
	assert_int_equal(0, flashrom_otp_write(&flash, 0, image, REGION_SIZE));
	assert_int_equal(0, flashrom_otp_lock(&flash, 0));

	/* Lost ability to write or erase it */
	assert_int_equal(1, flashrom_otp_write(&flash, 0, image, REGION_SIZE));
	assert_int_equal(1, flashrom_otp_erase(&flash, 0));

	/* Region's content is correct after all manipulations */
	assert_int_equal(0, flashrom_otp_read(&flash, 0, buf, REGION_SIZE));
	assert_memory_equal(buf, image, REGION_SIZE);

	teardown();

	free(param_dup);
}

void otp_scur_factory_lock_test_success(void **state)
{
	(void) state; /* unused */

	enum { REGION_SIZE = 512 };

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_MX25L6436;
	uint8_t buf[REGION_SIZE];

	char *param_dup = strdup("bus=spi,emulate=MX25L6436,spi_scur=0x01");

	setup(&flash, &mock_chip, param_dup);

	/* Can't write, erase or lock (second time) OTP region */
	assert_int_equal(1, flashrom_otp_write(&flash, 0, image, REGION_SIZE));
	assert_int_equal(1, flashrom_otp_erase(&flash, 0));
	assert_int_equal(1, flashrom_otp_lock(&flash, 0));

	/* Region's content is still empty after all manipulations */
	assert_int_equal(0, flashrom_otp_read(&flash, 0, buf, REGION_SIZE));
	assert_memory_equal(buf, empty, REGION_SIZE);

	teardown();

	free(param_dup);
}
