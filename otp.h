/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2016 Hatim Kanchwala <hatim at hatimak.me>
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

#ifndef __OTP_H__
#define __OTP_H__ 1

#include <stdint.h>

#include "flash.h"

struct flashctx;

/* Bits for otp.feature_bits field */
/* Need to enter special mode to work with OTP */
#define OTP_KIND_MODE		(1 << 0)
/* Need to use special opcodes to interact with OTP */
#define OTP_KIND_REGS		(1 << 1)
/* Block protect bits must be cleared before entering OTP mode */
#define OTP_MODE_CLEAR_BP	(1 << 2)
/* OTP lock must be set while in OTP mode */
#define OTP_MODE_LOCK_WHILE_IN	(1 << 3)
/* OTP registers are read as one (FIXME: not implemented) */
#define OTP_REGS_FUSED_READ	(1 << 4)
/* OTP registers are erased as one (FIXME: not implemented) */
#define OTP_REGS_FUSED_ERASE	(1 << 5)

struct otp {
	int feature_bits;	/* must contain either OTP_KIND_MODE or OTP_KIND_REGS */

	/* These opcodes are different for different manufacturers. */
	uint8_t otp_enter_opcode;
	uint8_t otp_exit_opcode;

	struct otp_region {
		/* This address corresponds to the first byte in the OTP memory region. */
		uint32_t addr;
		uint32_t size; /* in bytes */

		/*
		 * Lock-down bits. Setting at least one of them makes OTP
		 * regions read-only. Once set, they can't be unset.
		 *
		 * All chips have at least user lock bit, which is mandatory for
		 * OTP configuration to count as valid. User bit might actually
		 * be set by a manufacturer after writing ESN. Some chips have
		 * a designated factory lock-down bit instead and defining it here is
		 * optional.
		 */
		struct reg_bit_info user_lock;
		struct reg_bit_info factory_lock;
	} regions[FLASHROM_OTP_MAX_REGIONS + 1]; /* We need one more than maximum */
};

extern struct otp mx512otp;
extern struct otp en128_2048otp;
extern struct otp en256_512otp;
extern struct otp en512_4096otp;
extern struct otp en256_1024otp;
extern struct otp en512_2048otp;
extern struct otp en512_16384otp;
extern struct otp en512_8192otp;
extern struct otp gd_w256_3_otp;
extern struct otp gd512_3_otp;

#endif /* !__OTP_H__ */
