/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2010 Google Inc.
 * Copyright (C) 2012 secunet Security Networks AG
 * (Written by Nico Huber <nico.huber@secunet.com> for secunet)
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

#ifndef __LIBFLASHROM_H__
#define __LIBFLASHROM_H__ 1

#include <sys/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

int flashrom_init(int perform_selfcheck);
int flashrom_shutdown(void);
/** @ingroup flashrom-general */
enum flashrom_log_level {
	FLASHROM_MSG_ERROR	= 0,
	FLASHROM_MSG_WARN	= 1,
	FLASHROM_MSG_INFO	= 2,
	FLASHROM_MSG_DEBUG	= 3,
	FLASHROM_MSG_DEBUG2	= 4,
	FLASHROM_MSG_SPEW	= 5,
};
/** @ingroup flashrom-general */
typedef int(flashrom_log_callback)(enum flashrom_log_level, const char *format, va_list);
void flashrom_set_log_callback(flashrom_log_callback *);

/** @ingroup flashrom-query */
enum flashrom_test_state {
	FLASHROM_TESTED_OK  = 0,
	FLASHROM_TESTED_NT  = 1,
	FLASHROM_TESTED_BAD = 2,
	FLASHROM_TESTED_DEP = 3,
	FLASHROM_TESTED_NA  = 4,
};

struct flashrom_flashchip_info {
	const char *vendor;
	const char *name;
	unsigned int total_size;
	struct flashrom_tested {
		enum flashrom_test_state probe;
		enum flashrom_test_state read;
		enum flashrom_test_state erase;
		enum flashrom_test_state write;
	} tested;
};

struct flashrom_board_info {
	const char *vendor;
	const char *name;
	enum flashrom_test_state working;
};

struct flashrom_chipset_info {
	const char *vendor;
	const char *chipset;
	uint16_t vendor_id;
	uint16_t chipset_id;
	enum flashrom_test_state status;
};

const char *flashrom_version_info(void);
struct flashrom_flashchip_info *flashrom_supported_flash_chips(void);
struct flashrom_board_info *flashrom_supported_boards(void);
struct flashrom_chipset_info *flashrom_supported_chipsets(void);
int flashrom_data_free(void *const p);

/** @ingroup flashrom-prog */
struct flashrom_programmer;
int flashrom_programmer_init(struct flashrom_programmer **, const char *prog_name, const char *prog_params);
int flashrom_programmer_shutdown(struct flashrom_programmer *);

struct flashrom_flashctx;
int flashrom_flash_probe(struct flashrom_flashctx **, const struct flashrom_programmer *, const char *chip_name);
size_t flashrom_flash_getsize(const struct flashrom_flashctx *);
int flashrom_flash_erase(struct flashrom_flashctx *);
void flashrom_flash_release(struct flashrom_flashctx *);

/** @ingroup flashrom-flash */
enum flashrom_flag {
	FLASHROM_FLAG_FORCE,
	FLASHROM_FLAG_FORCE_BOARDMISMATCH,
	FLASHROM_FLAG_VERIFY_AFTER_WRITE,
	FLASHROM_FLAG_VERIFY_WHOLE_CHIP,
};
void flashrom_flag_set(struct flashrom_flashctx *, enum flashrom_flag, bool value);
bool flashrom_flag_get(const struct flashrom_flashctx *, enum flashrom_flag);

int flashrom_image_read(struct flashrom_flashctx *, void *buffer, size_t buffer_len);
int flashrom_image_write(struct flashrom_flashctx *, void *buffer, size_t buffer_len, const void *refbuffer);
int flashrom_image_verify(struct flashrom_flashctx *, const void *buffer, size_t buffer_len);

struct flashrom_layout;
int flashrom_layout_new(struct flashrom_layout **);
int flashrom_layout_read_from_ifd(struct flashrom_layout **, struct flashrom_flashctx *, const void *dump, size_t len);
int flashrom_layout_read_fmap_from_rom(struct flashrom_layout **,
		struct flashrom_flashctx *, off_t offset, size_t length);
int flashrom_layout_read_fmap_from_buffer(struct flashrom_layout **layout,
		struct flashrom_flashctx *, const uint8_t *buf, size_t len);
int flashrom_layout_add_region(struct flashrom_layout *, size_t start, size_t end, const char *name);
int flashrom_layout_include_region(struct flashrom_layout *, const char *name);
void flashrom_layout_release(struct flashrom_layout *);
void flashrom_layout_set(struct flashrom_flashctx *, const struct flashrom_layout *);

/** @ingroup flashrom-wp */
struct flashrom_wp_chip_config;

enum flashrom_wp_mode {
	WP_MODE_DISABLED,	/**< Only software protected */
	WP_MODE_HARDWARE,	/**< Hardware WP pin determines status */
	WP_MODE_POWER_CYCLE,	/**< WP active until power off/on cycle */
	WP_MODE_PERMANENT,	/**< WP permanently enabled */
};

struct flashrom_wp_range {
	uint32_t start;
	uint32_t len;
};

/* Value is arbitrary, but needs to be at least 64 for chips with 6 BP bits */
#define FLASHROM_WP_MAX_RANGES 128
/* Value is arbitrary */
#define FLASHROM_WP_OUT_STR_SIZE 256

bool flashrom_wp_chip_supported(const struct flashrom_flashctx *);

int flashrom_wp_read_chip_config(const struct flashrom_flashctx *, struct flashrom_wp_chip_config *);
int flashrom_wp_write_chip_config(struct flashrom_flashctx *, const struct flashrom_wp_chip_config *);
int flashrom_wp_compare_chip_configs(const struct flashrom_wp_chip_config *, const struct flashrom_wp_chip_config *);

int flashrom_wp_get_available_ranges(const struct flashrom_flashctx *, const struct flashrom_wp_chip_config *, struct flashrom_wp_range *ranges, size_t *count);
int flashrom_wp_get_range(const struct flashrom_flashctx *, const struct flashrom_wp_chip_config *, struct flashrom_wp_range *);
int flashrom_wp_set_range(const struct flashrom_flashctx *, struct flashrom_wp_chip_config *, const struct flashrom_wp_range *);

int flashrom_wp_get_mode(const struct flashrom_wp_chip_config *, enum flashrom_wp_mode *);
int flashrom_wp_set_mode(struct flashrom_wp_chip_config *, const enum flashrom_wp_mode);

int flashrom_wp_config_to_str(const struct flashrom_wp_chip_config *, char *);
int flashrom_wp_range_to_str(const struct flashrom_flashctx *, const struct flashrom_wp_range *, char *);
int flashrom_wp_mode_to_str(const enum flashrom_wp_mode mode, char *);

/** @ingroup flashrom-otp */
struct flashrom_otp_region {
	uint32_t size;
	bool locked;
};

#define FLASHROM_OTP_MAX_REGIONS 4

bool flashrom_otp_chip_supported(const struct flashrom_flashctx *);

int flashrom_otp_get_regions(struct flashrom_flashctx *, struct flashrom_otp_region *regions, size_t *count);
int flashrom_otp_status(struct flashrom_flashctx *, int region, bool *locked);
int flashrom_otp_lock(struct flashrom_flashctx *, int region);

int flashrom_otp_read(struct flashrom_flashctx *, int region, void *buffer, size_t buffer_len);
int flashrom_otp_write(struct flashrom_flashctx *, int region, const void *buffer, size_t buffer_len);
int flashrom_otp_erase(struct flashrom_flashctx *, int region);

#endif				/* !__LIBFLASHROM_H__ */
