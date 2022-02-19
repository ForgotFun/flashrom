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
#include <stdio.h>
#include <string.h>

#include "chipdrivers.h"
#include "flash.h"
#include "libflashrom.h"
#include "programmer.h"

/*
 * Tests in this file do not use any mocking, because using write-protect
 * emulation in dummyflasher programmer is sufficient
 */

#define LAYOUT_TAIL_REGION_START 0x1000

static void setup_chip(struct flashrom_flashctx *flash, struct flashrom_layout **layout,
		       struct flashchip *chip, const char *programmer_param)
{
	flash->chip = chip;

	if (layout) {
		const size_t tail_start = LAYOUT_TAIL_REGION_START;
		const size_t tail_len = chip->total_size * KiB - 1;

		assert_int_equal(0, flashrom_layout_new(layout));
		assert_int_equal(0, flashrom_layout_add_region(*layout, 0, tail_start - 1, "head"));
		assert_int_equal(0, flashrom_layout_add_region(*layout, tail_start, tail_len, "tail"));

		flashrom_layout_set(flash, *layout);
	}

	assert_int_equal(0, programmer_init(&programmer_dummy, programmer_param));
	/* Assignment below normally happens while probing, but this test is not probing. */
	flash->mst = &registered_masters[0];
}

static void teardown(struct flashrom_layout **layout)
{
	assert_int_equal(0, programmer_shutdown());
	if (layout)
		flashrom_layout_release(*layout);
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
	.reg_bits	=
	{
		.srp    = {{STATUS1, 7, RW}, {STATUS2, 0, RW}},
		.bp     = {{STATUS1, 2, RW}, {STATUS1, 3, RW}, {STATUS1, 4, RW}},
		.tb     = {STATUS1, 5, RW},
		.sec    = {STATUS1, 6, RW},
		.cmp    = {STATUS2, 6, RW},
	},
	.decode_range	= decode_range_w25,
};

void invalid_wp_range_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;
	struct flashrom_wp_chip_config cfg;

	struct flashrom_wp_range range = {
		.start = 0x1000,
		.len = 0x1000,
	};

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV,hwwp=no");

	setup_chip(&flash, NULL, &mock_chip, param_dup);

	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));
	assert_int_equal(1, flashrom_wp_set_range(&flash, &cfg, &range));

	teardown(NULL);

	free(param_dup);
}

void set_wp_range_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;
	struct flashrom_wp_chip_config cfg;

	struct flashrom_wp_range range = { 0 };

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV,hwwp=no");

	setup_chip(&flash, NULL, &mock_chip, param_dup);

	assert_true(flashrom_wp_chip_supported(&flash));

	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));

	/* Use last 4 KiB for a range. */
	range.len = 4 * KiB;
	range.start = mock_chip.total_size * KiB - range.len;
	assert_int_equal(0, flashrom_wp_set_range(&flash, &cfg, &range));

	/* Check that range was set correctly. */
	assert_int_equal(0, flashrom_wp_get_range(&flash, &cfg, &range));
	assert_int_equal(16 * MiB - 4 * KiB, range.start);
	assert_int_equal(4 * KiB, range.len);

	teardown(NULL);

	free(param_dup);
}

void switch_wp_mode_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;
	struct flashrom_wp_chip_config cfg;

	enum flashrom_wp_mode mode;

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV,hwwp=yes");

	setup_chip(&flash, NULL, &mock_chip, param_dup);

	assert_true(flashrom_wp_chip_supported(&flash));

	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));

	/* Check initial mode. */
	assert_int_equal(0, flashrom_wp_get_mode(&cfg, &mode));
	assert_int_equal(WP_MODE_DISABLED, mode);

	/* Enable hardware protection, which can't be unset because simulated
	 * HW WP pin is in active state. */
	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_HARDWARE));
	assert_int_equal(0, flashrom_wp_write_chip_config(&flash, &cfg));
	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));
	assert_int_equal(0, flashrom_wp_get_mode(&cfg, &mode));
	assert_int_equal(WP_MODE_HARDWARE, mode);

	/*
	 * Check that write-protection mode can't be unset and this is not
	 * considered to be an error at the level of library calls (verification
	 * should be done higher).
	 */
	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_DISABLED));
	assert_int_equal(0, flashrom_wp_write_chip_config(&flash, &cfg));

	/* Final mode should be "hardware". */
	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));
	assert_int_equal(0, flashrom_wp_get_mode(&cfg, &mode));
	assert_int_equal(WP_MODE_HARDWARE, mode);

	teardown(NULL);

	free(param_dup);
}

void set_wp_mode_disabled_2srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 2,
		.srp = {0xff, 0xff},
	};

	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_DISABLED));
	assert_int_equal(0, cfg.srp[0]);
	assert_int_equal(0, cfg.srp[1]);
}

void set_wp_mode_disabled_1srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 1,
		.srp = {0xff},
	};

	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_DISABLED));
	assert_int_equal(0, cfg.srp[0]);
}

void set_wp_mode_hardware_2srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 2,
		.srp = {0xff, 0xff},
	};

	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_HARDWARE));
	assert_int_equal(1, cfg.srp[0]);
	assert_int_equal(0, cfg.srp[1]);
}

void set_wp_mode_hardware_1srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 1,
		.srp = {0xff},
	};

	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_HARDWARE));
	assert_int_equal(1, cfg.srp[0]);
}

void set_wp_mode_power_cycle_2srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 2,
		.srp = {0xff, 0xff},
	};

	assert_int_equal(1, flashrom_wp_set_mode(&cfg, WP_MODE_POWER_CYCLE));
	assert_int_equal(0xff, cfg.srp[0]);
	assert_int_equal(0xff, cfg.srp[1]);
}

void set_wp_mode_power_cycle_1srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 1,
	};
	assert_int_equal(1, flashrom_wp_set_mode(&cfg, WP_MODE_POWER_CYCLE));
}

void set_wp_mode_permanent_2srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 2,
		.srp = {0xff, 0xff},
	};

	assert_int_equal(1, flashrom_wp_set_mode(&cfg, WP_MODE_PERMANENT));
	assert_int_equal(0xff, cfg.srp[0]);
	assert_int_equal(0xff, cfg.srp[1]);
}

void set_wp_mode_permanent_1srp_test_success(void **state)
{
	struct flashrom_wp_chip_config cfg = {
		.srp_bit_count = 1,
	};
	assert_int_equal(1, flashrom_wp_set_mode(&cfg, WP_MODE_PERMANENT));
}

void wp_init_from_status_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashchip mock_chip = chip_W25Q128_V;

	enum flashrom_wp_mode mode;
	struct flashrom_wp_range range;
	struct flashrom_wp_chip_config cfg;

	/*
	 * CMP  (S14) = 1 (range complement)
	 * SRP1 (S8)  = 1
	 * SRP0 (S7)  = 1 (`SRP1 == 1 && SRP0 == 1` is permanent mode)
	 * SEC  (S6)  = 1 (base unit is a 4 KiB sector)
	 * TB   (S5)  = 1 (bottom up range)
	 * BP2  (S4)  = 0
	 * BP1  (S3)  = 1
	 * BP0  (S2)  = 1 (bp: BP2-0 == 0b011 == 3)
	 *
	 * Range coefficient is `2 ** (bp - 1)`, which is 4 in this case.
	 * Multiplaying that by base unit gives 16 KiB protected region at the
	 * bottom (start of the chip), which is then complemented.
	 */
	char *param_dup = strdup("bus=spi,emulate=W25Q128FV,spi_status=0x41ec");

	setup_chip(&flash, NULL, &mock_chip, param_dup);

	/* Verify that WP mode reflects SPI status */
	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));
	assert_int_equal(0, flashrom_wp_get_mode(&cfg, &mode));
	assert_int_equal(WP_MODE_PERMANENT, mode);
	assert_int_equal(0, flashrom_wp_get_range(&flash, &cfg, &range));
	assert_int_equal(0x004000, range.start);
	assert_int_equal(0xffc000, range.len);

	teardown(NULL);

	free(param_dup);
}

void full_chip_erase_with_wp_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashrom_layout *layout;
	struct flashchip mock_chip = chip_W25Q128_V;
	struct flashrom_wp_chip_config cfg;

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV,hwwp=yes");

	setup_chip(&flash, &layout, &mock_chip, param_dup);
	/* Layout regions are created by setup_chip(). */
	assert_int_equal(0, flashrom_layout_include_region(layout, "head"));
	assert_int_equal(0, flashrom_layout_include_region(layout, "tail"));

	/* Write protection takes effect only after changing SRP values, so at
	 * this stage WP is not enabled and erase completes successfully. */
	assert_int_equal(0, do_erase(&flash));

	/* Protect first 4 KiB. */
	struct flashrom_wp_range range = {
		.start = 0,
		.len = 4 * KiB,
	};
	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));
	assert_int_equal(0, flashrom_wp_set_range(&flash, &cfg, &range));
	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_HARDWARE));
	assert_int_equal(0, flashrom_wp_write_chip_config(&flash, &cfg));

	/* Try erasing the chip again. Now that WP is active, the first 4 KiB is
	 * protected and we're trying to erase the whole chip, erase should
	 * fail. */
	assert_int_equal(1, do_erase(&flash));

	teardown(&layout);

	free(param_dup);
}

void partial_chip_erase_with_wp_dummyflasher_test_success(void **state)
{
	(void) state; /* unused */

	struct flashrom_flashctx flash = { 0 };
	struct flashrom_layout *layout;
	struct flashchip mock_chip = chip_W25Q128_V;
	struct flashrom_wp_chip_config cfg;

	char *param_dup = strdup("bus=spi,emulate=W25Q128FV,hwwp=yes");

	setup_chip(&flash, &layout, &mock_chip, param_dup);
	/* Layout region is created by setup_chip(). */
	assert_int_equal(0, flashrom_layout_include_region(layout, "tail"));

	/* Protect first 4 KiB. */
	struct flashrom_wp_range range = {
		.start = 0,
		.len = LAYOUT_TAIL_REGION_START,
	};
	assert_int_equal(0, flashrom_wp_read_chip_config(&flash, &cfg));
	assert_int_equal(0, flashrom_wp_set_range(&flash, &cfg, &range));
	assert_int_equal(0, flashrom_wp_set_mode(&cfg, WP_MODE_HARDWARE));
	assert_int_equal(0, flashrom_wp_write_chip_config(&flash, &cfg));

	/* First 4 KiB is the only protected part of the chip and we included
	 * only region covers unprotected part, so erase operation should
	 * succeed. */
	assert_int_equal(0, do_erase(&flash));

	teardown(&layout);

	free(param_dup);
}
