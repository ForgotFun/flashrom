/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2016 Hatim Kanchwala <hatim@hatimak.me>
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
#include "spi.h"

/*
 * Macronix (OTP mode with security register)
 */

/* MX25L6436E/MX25L6445E/MX25L6465E/MX25L6473E/MX25L6473F */
struct otp mx512otp = {
	.feature_bits = OTP_KIND_MODE,
	.otp_enter_opcode = JEDEC_ENSO,
	.otp_exit_opcode = JEDEC_EXSO,
	.regions =
	{
		{
			.addr = 0x000000,
			.size = 512,
			.user_lock = {SECREG, 1, OTP},
			.factory_lock = {SECREG, 0, RO},
		},
	},
};

/*
 * Eon (OTP mode)
 *
 * Because OTP region is mapped at the end of address space, structures differ
 * based on region and flash sizes.
 */

/* EN25Q16 */
struct otp en128_2048otp = {
	.feature_bits = OTP_KIND_MODE | OTP_MODE_CLEAR_BP | OTP_MODE_LOCK_WHILE_IN,
	.otp_enter_opcode = JEDEC_ENTER_OTP,
	.otp_exit_opcode = JEDEC_WRDI,
	.regions =
	{
		{
			.addr = 0x1FF000,
			.size = 128,
			.user_lock = {STATUS1, 7, OTP},
		},
	},
};

/* EN25Q40 */
struct otp en256_512otp = {
	.feature_bits = OTP_KIND_MODE | OTP_MODE_CLEAR_BP | OTP_MODE_LOCK_WHILE_IN,
	.otp_enter_opcode = JEDEC_ENTER_OTP,
	.otp_exit_opcode = JEDEC_WRDI,
	.regions =
	{
		{
			.addr = 0x07F000,
			.size = 256,
			.user_lock = {STATUS1, 7, OTP},
		},
	},
};

/* EN25Q80(A) */
struct otp en256_1024otp = {
	.feature_bits = OTP_KIND_MODE | OTP_MODE_CLEAR_BP | OTP_MODE_LOCK_WHILE_IN,
	.otp_enter_opcode = JEDEC_ENTER_OTP,
	.otp_exit_opcode = JEDEC_WRDI,
	.regions =
	{
		{
			.addr = 0x0FF000,
			.size = 256,
			.user_lock = {STATUS1, 7, OTP},
		},
	},
};

/* EN25QH16 */
struct otp en512_2048otp = {
	.feature_bits = OTP_KIND_MODE | OTP_MODE_CLEAR_BP | OTP_MODE_LOCK_WHILE_IN,
	.otp_enter_opcode = JEDEC_ENTER_OTP,
	.otp_exit_opcode = JEDEC_WRDI,
	.regions =
	{
		{
			.addr = 0x1FF000,
			.size = 512,
			.user_lock = {STATUS1, 7, OTP},
		},
	},
};

/* EN25Q32(A/B), EN25QH32 */
struct otp en512_4096otp = {
	.feature_bits = OTP_KIND_MODE | OTP_MODE_CLEAR_BP | OTP_MODE_LOCK_WHILE_IN,
	.otp_enter_opcode = JEDEC_ENTER_OTP,
	.otp_exit_opcode = JEDEC_WRDI,
	.regions =
	{
		{
			.addr = 0x3FF000,
			.size = 512,
			.user_lock = {STATUS1, 7, OTP},
		},
	},
};

/* EN25Q64, EN25QH64 */
struct otp en512_8192otp = {
	.feature_bits = OTP_KIND_MODE | OTP_MODE_CLEAR_BP | OTP_MODE_LOCK_WHILE_IN,
	.otp_enter_opcode = JEDEC_ENTER_OTP,
	.otp_exit_opcode = JEDEC_WRDI,
	.regions =
	{
		{
			.addr = 0x7FF000,
			.size = 512,
			.user_lock = {STATUS1, 7, OTP},
		},
	},
};

/* EN25Q128, EN25QH128 */
struct otp en512_16384otp = {
	.feature_bits = OTP_KIND_MODE | OTP_MODE_CLEAR_BP | OTP_MODE_LOCK_WHILE_IN,
	.otp_enter_opcode = JEDEC_ENTER_OTP,
	.otp_exit_opcode = JEDEC_WRDI,
	.regions =
	{
		{
			.addr = 0xFFF000,
			.size = 512,
			.user_lock = {STATUS1, 7, OTP},
		},
	},
};

/*
 * GigaDevice and Winbond (secure registers)
 *
 * Sizes and addresses differ, although all regions tend to be of the same size.
 */

/* W25Q40.V */
struct otp gd_w256_3_otp = {
	.feature_bits = OTP_KIND_REGS,
	.regions =
	{
		{
			.addr = 0x001000,
			.size = 256,
			.user_lock = {STATUS2, 3, OTP},
		}, {
			.addr = 0x002000,
			.size = 256,
			.user_lock = {STATUS2, 4, OTP},
		}, {
			.addr = 0x003000,
			.size = 256,
			.user_lock = {STATUS2, 5, OTP},
		},
	},
};

/* GD25VQ21B, GD25VQ41B, GD25Q128C */
struct otp gd512_3_otp = {
	.feature_bits = OTP_KIND_REGS,
	.regions =
	{
		{
			.addr = 0x001000,
			.size = 512,
			.user_lock = {STATUS2, 3, OTP},
		}, {
			.addr = 0x002000,
			.size = 512,
			.user_lock = {STATUS2, 4, OTP},
		}, {
			.addr = 0x003000,
			.size = 512,
			.user_lock = {STATUS2, 5, OTP},
		},
	},
};
