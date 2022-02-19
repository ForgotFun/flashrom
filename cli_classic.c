/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2000 Silicon Integrated System Corporation
 * Copyright (C) 2004 Tyan Corp <yhlu@tyan.com>
 * Copyright (C) 2005-2008 coresystems GmbH
 * Copyright (C) 2008,2009,2010 Carl-Daniel Hailfinger
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

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>
#include "flash.h"
#include "flashchips.h"
#include "fmap.h"
#include "programmer.h"
#include "libflashrom.h"

static void cli_classic_usage(const char *name)
{
	printf("Usage: %s [-h|-R|-L|"
#if CONFIG_PRINT_WIKI == 1
	       "-z|"
#endif
	       "\n\t-p <programmername>[:<parameters>] [-c <chipname>]\n"
	       "\t\t(--flash-name|--flash-size|\n"
	       "\t\t [-E|-x|(-r|-w|-v) <file>]\n"
	       "\t\t [(-l <layoutfile>|--ifd| --fmap|--fmap-file <file>) [-i <region>[:<file>]]...]\n"
	       "\t\t [-n] [-N] [-f])]\n"
	       "\t[-V[V[V]]] [-o <logfile>]\n\n", name);

	printf(" -h | --help                        print this help text\n"
	       " -R | --version                     print version (release)\n"
	       " -r | --read <file>                 read flash and save to <file>\n"
	       " -w | --write <file|->              write <file> or the content provided\n"
	       "                                    on the standard input to flash\n"
	       " -v | --verify <file|->             verify flash against <file>\n"
	       "                                    or the content provided on the standard input\n"
	       " -E | --erase                       erase flash memory\n"
	       " -V | --verbose                     more verbose output\n"
	       " -c | --chip <chipname>             probe only for specified flash chip\n"
	       " -f | --force                       force specific operations (see man page)\n"
	       " -n | --noverify                    don't auto-verify\n"
	       " -N | --noverify-all                verify included regions only (cf. -i)\n"
	       " -x | --extract                     extract regions to files\n"
	       " -l | --layout <layoutfile>         read ROM layout from <layoutfile>\n"
	       "      --wp-disable                  disable write protection\n"
	       "      --wp-enable                   enable write protection\n"
	       "      --wp-list                     list supported write protection ranges\n"
	       "      --wp-status                   show write protection status\n"
	       "      --wp-range=<start>,<len>      set write protection range (use --wp-range=0,0\n"
	       "                                    to unprotect the entire flash)\n"
	       "      --wp-region <region>          set write protection region\n"
	       "      --otp-status                  print information about OTP regions\n"
	       "      --otp-region <otp-region>     OTP region number (base 1) to operate on\n"
	       "      --otp-read <file>             read OTP region and save it to <file>\n"
	       "      --otp-write <file>            write <file> to OTP region\n"
	       "      --otp-erase                   erase OTP region\n"
	       "      --otp-lock                    lock OTP region\n"
	       "      --flash-name                  read out the detected flash name\n"
	       "      --flash-size                  read out the detected flash size\n"
	       "      --fmap                        read ROM layout from fmap embedded in ROM\n"
	       "      --fmap-file <fmapfile>        read ROM layout from fmap in <fmapfile>\n"
	       "      --ifd                         read layout from an Intel Firmware Descriptor\n"
	       " -i | --image <region>[:<file>]     only read/write image <region> from layout\n"
	       "                                    (optionally with data from <file>)\n"
	       " -o | --output <logfile>            log output to <logfile>\n"
	       "      --flash-contents <ref-file>   assume flash contents to be <ref-file>\n"
	       " -L | --list-supported              print supported devices\n"
#if CONFIG_PRINT_WIKI == 1
	       " -z | --list-supported-wiki         print supported devices in wiki syntax\n"
#endif
	       " -p | --programmer <name>[:<param>] specify the programmer device. One of\n");
	list_programmers_linebreak(4, 80, 0);
	printf(".\n\nYou can specify one of -h, -R, -L, "
#if CONFIG_PRINT_WIKI == 1
	         "-z, "
#endif
	         "-E, -r, -w, -v or no operation.\n"
	       "If no operation is specified, flashrom will only probe for flash chips.\n");
}

static void cli_classic_abort_usage(const char *msg)
{
	if (msg)
		fprintf(stderr, "%s", msg);
	printf("Please run \"flashrom --help\" for usage info.\n");
	exit(1);
}

static void cli_classic_validate_singleop(int *operation_specified)
{
	if (++(*operation_specified) > 1) {
		cli_classic_abort_usage("More than one operation specified. Aborting.\n");
	}
}

static int check_filename(char *filename, const char *type)
{
	if (!filename || (filename[0] == '\0')) {
		fprintf(stderr, "Error: No %s file specified.\n", type);
		return 1;
	}
	/* Not an error, but maybe the user intended to specify a CLI option instead of a file name. */
	if (filename[0] == '-' && filename[1] != '\0')
		fprintf(stderr, "Warning: Supplied %s file name starts with -\n", type);
	return 0;
}

/* Ensure a file is open by means of fstat */
static bool check_file(FILE *file)
{
#ifndef STANDALONE
	struct stat statbuf;

	if (fstat(fileno(file), &statbuf) < 0)
		return false;
#endif /* !STANDALONE */
	return true;
}

static int parse_wp_range(uint32_t *start, uint32_t *len)
{
	char *endptr = NULL, *token = NULL;

	if (!optarg) {
		msg_gerr("Error: No wp-range values provided\n");
		return -1;
	}

	token = strtok(optarg, ",");
	if (!token) {
		msg_gerr("Error: Invalid wp-range argument format\n");
		return -1;
	}
	*start = strtoul(token, &endptr, 0);

	token = strtok(NULL, ",");
	if (!token) {
		msg_gerr("Error: Invalid wp-range argument format\n");
		return -1;
	}
	*len = strtoul(token, &endptr, 0);

	return 0;
}

static int write_wp_config(struct flashctx *flash, struct flashrom_wp_chip_config *cfg)
{
	/* Write */
	int ret = flashrom_wp_write_chip_config(flash, cfg);

	if (ret) {
		msg_gerr("Writing WP configuration to chip failed!\n");
		return ret;
	}

	/* Verify */
	struct flashrom_wp_chip_config cfg_readback;
	ret = flashrom_wp_read_chip_config(flash, &cfg_readback);

	if (ret) {
		msg_gerr("Reading back WP configuration for verification failed!\n");
		return ret;
	}

	ret = flashrom_wp_compare_chip_configs(cfg, &cfg_readback);
	if (ret) {
		msg_gerr("Writing new WP configuration failed during verification:\n");

		char buf[FLASHROM_WP_OUT_STR_SIZE];
		flashrom_wp_config_to_str(cfg, buf);
		msg_gerr("Expected configuration: %s\n", buf);

		flashrom_wp_config_to_str(&cfg_readback, buf);
		msg_gerr("Actual configuration:   %s\n", buf);
	}

	return ret;
}

static int wp_cli(
		struct flashctx *flash,
		bool enable_wp,
		bool disable_wp,
		bool print_wp_status,
		bool print_available_ranges,
		bool set_wp_range,
		uint32_t wp_start,
		uint32_t wp_len,
		const char* wp_mode_opt)
{
	struct flashrom_wp_chip_config cfg;
	enum flashrom_wp_mode mode;
	struct flashrom_wp_range range;
	char buf[FLASHROM_WP_OUT_STR_SIZE];

	if (!flashrom_wp_chip_supported(flash)) {
		msg_gerr("Error: write protect support is not implemented for this flash chip.\n");
		return 1;
	}

	int ret = flashrom_wp_read_chip_config(flash, &cfg);
	if (ret) {
		msg_gerr("Reading current WP configuration failed!\n");
		return ret;
	}

	if (set_wp_range) {
		range.start = wp_start;
		range.len = wp_len;
		ret = flashrom_wp_set_range(flash, &cfg, &range);
		if (ret) {
			msg_gerr("The chip does not support the requested range.\n");
			return ret;
		}

		/* Write range before other operations (i.e. enabling HW protection) */
		ret = write_wp_config(flash, &cfg);
		if (ret)
			return ret;

		msg_ginfo("Sucessfully set the requested protection range.\n");
	}

	if (enable_wp || disable_wp) {
		mode = disable_wp ? WP_MODE_DISABLED : WP_MODE_HARDWARE;
		ret = flashrom_wp_set_mode(&cfg, mode);
		if (ret) {
			msg_gerr("The chip does not support the requested mode.\n");
			return ret;
		}

		/* Write mode before other operations */
		ret = write_wp_config(flash, &cfg);
		if (ret)
			return ret;

		msg_ginfo("Sucessfully set the requested mode.\n");
	}

	if (print_available_ranges) {
		struct flashrom_wp_range ranges[FLASHROM_WP_MAX_RANGES];
		size_t count;

		ret = flashrom_wp_get_available_ranges(flash, &cfg, ranges, &count);
		if (ret)
			return ret;

		msg_ginfo("Available write protection ranges:\n");
		for (size_t idx = 0; idx < count; idx++) {
			flashrom_wp_range_to_str(flash, &ranges[idx], buf);
			msg_ginfo("\t%s\n", buf);
		}
	}

	if (print_wp_status) {
		ret |= flashrom_wp_get_range(flash, &cfg, &range);
		ret |= flashrom_wp_get_mode(&cfg, &mode);

		if (ret)
			return ret;

		flashrom_wp_config_to_str(&cfg, buf);
		msg_ginfo("WP config bits: %s\n", buf);

		flashrom_wp_range_to_str(flash, &range, buf);
		msg_ginfo("Protection range: %s\n", buf);

		flashrom_wp_mode_to_str(mode, buf);
		msg_ginfo("Protection mode: %s\n", buf);
	}

	return ret;
}

/* Parses OTP region number from an option value.  Returns negative number on
 * parsing error. */
static int parse_otp_region(const char *value, int nregions)
{
	if (!value) {
		msg_gdbg("OTP region not specified, using default region 1.\n");
		return 0;
	}

	char *endptr = NULL;
	int region = strtoul(value, &endptr, 0);
	if (*endptr != '\0') {
		msg_gerr("Error: Invalid otp-region argument format.\n");
		return -1;
	}

	if (region < 1 || region > nregions) {
		msg_gerr("Error: Value of otp-region must in the range [1, %d].\n",
			 nregions);
		return -1;
	}

	return region - 1;
}

static int print_otp_status(struct flashctx *flash)
{
	size_t nregions;
	struct flashrom_otp_region regions[FLASHROM_OTP_MAX_REGIONS];
	if (flashrom_otp_get_regions(flash, regions, &nregions)) {
		msg_cerr("Failed to list OTP regions of the chip.\n");
		return 1;
	}

	msg_cinfo("%s contains %d OTP region%s:\n",
		  flash->chip->name, (int)nregions, (nregions == 0) ? "" : "s");

	for (unsigned int i = 0; i < nregions; i++) {
		msg_cinfo(" %d. %d bytes\n", i + 1, regions[i].size);

		if (regions[i].locked)
			msg_cinfo("    Permanently locked and cannot be erased or written to.\n");
		else
			msg_cinfo("    Not yet locked.\n");
	}

	return 0;
}

static int otp_cli(struct flashctx *flash, int any_otp_op,
		   int otp_status, int otp_read, int otp_write, int otp_erase, int otp_lock,
		   const char *otp_region_opt, const char *filename)
{
	int ret;

	size_t nregions;
	struct flashrom_otp_region regions[FLASHROM_OTP_MAX_REGIONS];

	if (!any_otp_op)
		return 0;

	if (!flashrom_otp_chip_supported(flash)) {
		msg_gerr("Error: OTP support is not implemented for this flash chip.\n");
		return 1;
	}

	int region = -1;
	if (otp_read || otp_write || otp_erase || otp_lock) {
		if (flashrom_otp_get_regions(flash, regions, &nregions)) {
			msg_cerr("Error: Failed to list OTP regions of the chip.\n");
			return 1;
		}

		if (nregions > 1 && !otp_region_opt) {
			msg_cerr("Error: Chip contains several OTP regions, but no --otp-region given.\n");
			return 1;
		}

		region = parse_otp_region(otp_region_opt, nregions);
		if (region < 0)
			return 1;
	}

	if (otp_read) {
		const uint32_t len = regions[region].size;
		uint8_t *buf = calloc(len, sizeof(*buf));
		if (!buf) {
			msg_gerr("Error: Memory allocation failed.\n");
			return 1;
		}
		msg_gdbg("Reading OTP region...\n");
		if (flashrom_otp_read(flash, region, buf, len)) {
			msg_cerr("Error: Reading OTP region failed.\n");
			free(buf);
			return 1;
		}

		ret = write_buf_to_file(buf, len, filename);
		free(buf);
		if (ret)
			return 1;
	}

	if (otp_write) {
		const uint32_t len = regions[region].size;
		uint8_t *buf = calloc(len, sizeof(*buf));
		if (!buf) {
			msg_gerr("Error: Memory allocation failed.\n");
			return 1;
		}

		ret = read_buf_from_file(buf, len, filename);
		if (ret) {
			msg_gerr("Error: Reading from file \"%s\" failed.\n", filename);
			free(buf);
			return 1;
		}
		msg_gdbg("Reading form file \"%s\" complete.\n", filename);

		msg_cinfo("Erasing OTP region...\n");
		if (flashrom_otp_erase(flash, region)) {
			msg_cerr("Error: Erasing OTP region failed.\n");
			free(buf);
			return 1;
		}
		msg_cinfo("Erasing OTP region done.\n");

		msg_cinfo("Writing OTP region...\n");
		ret = flashrom_otp_write(flash, region, buf, len);
		if (ret) {
			free(buf);
			msg_cerr("Error: Writing OTP region failed.\n");
			return 1;
		}
		msg_cinfo("Writing OTP region done.\n");

		uint8_t *verify_buf = calloc(len, sizeof(*verify_buf));
		if (!verify_buf) {
			free(buf);
			msg_gerr("Error: Memory allocation failed.\n");
			return 1;
		}

		msg_cinfo("Verifying written OTP region...\n");
		ret = flashrom_otp_read(flash, region, verify_buf, len);

		const bool ok = (memcmp(buf, verify_buf, len) == 0);
		free(verify_buf);
		free(buf);

		if (ret) {
			msg_gerr("Error: Reading OTP region failed.\n");
			return 1;
		}

		if (!ok) {
			msg_gerr("Error: Writing OTP region failed verification.\n");
			return 1;
		}

		msg_cinfo("Verifying written OTP region done.\n");
	}

	if (otp_erase) {
		msg_cinfo("Erasing OTP region ...\n");
		if (flashrom_otp_erase(flash, region)) {
			msg_cerr("Error: Erasing OTP region failed.\n");
			return 1;
		}
		msg_cinfo("Erasing OTP region done.\n");
	}

	if (otp_lock) {
		msg_gdbg("Trying to lock OTP region...\n");
		if (flashrom_otp_lock(flash, region)) {
			msg_cerr("Error: Failed to lock OTP region %d.\n", region + 1);
			return 1;
		}
		msg_cinfo("Successfully locked OTP region %d.\n", region + 1);
	}

	if (otp_status)
		return print_otp_status(flash);

	return 0;
}

int main(int argc, char *argv[])
{
	const struct flashchip *chip = NULL;
	/* Probe for up to eight flash chips. */
	struct flashctx flashes[8] = {{0}};
	struct flashctx *fill_flash;
	const char *name;
	int namelen, opt, i, j;
	int startchip = -1, chipcount = 0, option_index = 0, force = 0, ifd = 0, fmap = 0;
#if CONFIG_PRINT_WIKI == 1
	int list_supported_wiki = 0;
#endif
	int flash_name = 0, flash_size = 0;
	int enable_wp = 0, disable_wp = 0, print_wp_status = 0;
	int set_wp_range = 0, set_wp_region = 0, print_available_ranges = 0;
	int otp_status = 0, otp_read = 0, otp_write = 0, otp_erase = 0, otp_lock = 0;
	int read_it = 0, extract_it = 0, write_it = 0, erase_it = 0, verify_it = 0;
	int dont_verify_it = 0, dont_verify_all = 0, list_supported = 0, operation_specified = 0;
	struct flashrom_layout *layout = NULL;
	static const struct programmer_entry *prog = NULL;
	enum {
		OPTION_IFD = 0x0100,
		OPTION_FMAP,
		OPTION_FMAP_FILE,
		OPTION_FLASH_CONTENTS,
		OPTION_FLASH_NAME,
		OPTION_FLASH_SIZE,
		OPTION_WP_STATUS,
		OPTION_WP_SET_RANGE,
		OPTION_WP_SET_REGION,
		OPTION_WP_ENABLE,
		OPTION_WP_DISABLE,
		OPTION_WP_LIST,
		OPTION_OTP_STATUS,
		OPTION_OTP_REGION,
		OPTION_OTP_READ,
		OPTION_OTP_WRITE,
		OPTION_OTP_ERASE,
		OPTION_OTP_LOCK,
	};
	int ret = 0;
	uint32_t wp_start = 0, wp_len = 0;

	static const char optstring[] = "r:Rw:v:nNVEfc:l:i:p:Lzho:x";
	static const struct option long_options[] = {
		{"read",		1, NULL, 'r'},
		{"write",		1, NULL, 'w'},
		{"erase",		0, NULL, 'E'},
		{"verify",		1, NULL, 'v'},
		{"noverify",		0, NULL, 'n'},
		{"noverify-all",	0, NULL, 'N'},
		{"extract",		0, NULL, 'x'},
		{"chip",		1, NULL, 'c'},
		{"verbose",		0, NULL, 'V'},
		{"force",		0, NULL, 'f'},
		{"layout",		1, NULL, 'l'},
		{"ifd",			0, NULL, OPTION_IFD},
		{"fmap",		0, NULL, OPTION_FMAP},
		{"fmap-file",		1, NULL, OPTION_FMAP_FILE},
		{"image",		1, NULL, 'i'},
		{"flash-contents",	1, NULL, OPTION_FLASH_CONTENTS},
		{"flash-name",		0, NULL, OPTION_FLASH_NAME},
		{"flash-size",		0, NULL, OPTION_FLASH_SIZE},
		{"get-size",		0, NULL, OPTION_FLASH_SIZE}, // (deprecated): back compatibility.
		{"wp-status", 		0, 0, OPTION_WP_STATUS},
		{"wp-range", 		required_argument, NULL, OPTION_WP_SET_RANGE},
		{"wp-region",		1, 0, OPTION_WP_SET_REGION},
		{"wp-enable", 		optional_argument, 0, OPTION_WP_ENABLE},
		{"wp-disable", 		0, 0, OPTION_WP_DISABLE},
		{"wp-list", 		0, 0, OPTION_WP_LIST},
		{"otp-status",		0, NULL, OPTION_OTP_STATUS},
		{"otp-region",		1, NULL, OPTION_OTP_REGION},
		{"otp-read",		1, NULL, OPTION_OTP_READ},
		{"otp-write",		1, NULL, OPTION_OTP_WRITE},
		{"otp-erase",		0, NULL, OPTION_OTP_ERASE},
		{"otp-lock",		0, NULL, OPTION_OTP_LOCK},
		{"list-supported",	0, NULL, 'L'},
		{"list-supported-wiki",	0, NULL, 'z'},
		{"programmer",		1, NULL, 'p'},
		{"help",		0, NULL, 'h'},
		{"version",		0, NULL, 'R'},
		{"output",		1, NULL, 'o'},
		{NULL,			0, NULL, 0},
	};

	char *filename = NULL;
	char *referencefile = NULL;
	char *layoutfile = NULL;
	char *fmapfile = NULL;
#ifndef STANDALONE
	char *logfile = NULL;
#endif /* !STANDALONE */
	char *tempstr = NULL;
	char *pparam = NULL;
	struct layout_include_args *include_args = NULL;
	char *wp_mode_opt = NULL;
	char *wp_region = NULL;
	char *otp_region_opt = NULL;

	/*
	 * Safety-guard against a user who has (mistakenly) closed
	 * stdout or stderr before exec'ing flashrom.  We disable
	 * logging in this case to prevent writing log data to a flash
	 * chip when a flash device gets opened with fd 1 or 2.
	 */
	if (check_file(stdout) && check_file(stderr)) {
		flashrom_set_log_callback(
			(flashrom_log_callback *)&flashrom_print_cb);
	}

	print_version();
	print_banner();

	if (selfcheck())
		exit(1);

	setbuf(stdout, NULL);
	/* FIXME: Delay all operation_specified checks until after command
	 * line parsing to allow --help overriding everything else.
	 */
	while ((opt = getopt_long(argc, argv, optstring,
				  long_options, &option_index)) != EOF) {
		switch (opt) {
		case 'r':
			cli_classic_validate_singleop(&operation_specified);
			filename = strdup(optarg);
			read_it = 1;
			break;
		case 'w':
			cli_classic_validate_singleop(&operation_specified);
			filename = strdup(optarg);
			write_it = 1;
			break;
		case 'v':
			//FIXME: gracefully handle superfluous -v
			cli_classic_validate_singleop(&operation_specified);
			if (dont_verify_it) {
				cli_classic_abort_usage("--verify and --noverify are mutually exclusive. Aborting.\n");
			}
			filename = strdup(optarg);
			verify_it = 1;
			break;
		case 'n':
			if (verify_it) {
				cli_classic_abort_usage("--verify and --noverify are mutually exclusive. Aborting.\n");
			}
			dont_verify_it = 1;
			break;
		case 'N':
			dont_verify_all = 1;
			break;
		case 'x':
			cli_classic_validate_singleop(&operation_specified);
			extract_it = 1;
			break;
		case 'c':
			chip_to_probe = strdup(optarg);
			break;
		case 'V':
			verbose_screen++;
			if (verbose_screen > FLASHROM_MSG_DEBUG2)
				verbose_logfile = verbose_screen;
			break;
		case 'E':
			cli_classic_validate_singleop(&operation_specified);
			erase_it = 1;
			break;
		case 'f':
			force = 1;
			break;
		case 'l':
			if (layoutfile)
				cli_classic_abort_usage("Error: --layout specified more than once. Aborting.\n");
			if (ifd)
				cli_classic_abort_usage("Error: --layout and --ifd both specified. Aborting.\n");
			if (fmap)
				cli_classic_abort_usage("Error: --layout and --fmap-file both specified. Aborting.\n");
			layoutfile = strdup(optarg);
			break;
		case OPTION_IFD:
			if (layoutfile)
				cli_classic_abort_usage("Error: --layout and --ifd both specified. Aborting.\n");
			if (fmap)
				cli_classic_abort_usage("Error: --fmap-file and --ifd both specified. Aborting.\n");
			ifd = 1;
			break;
		case OPTION_FMAP_FILE:
			if (fmap)
				cli_classic_abort_usage("Error: --fmap or --fmap-file specified "
					"more than once. Aborting.\n");
			if (ifd)
				cli_classic_abort_usage("Error: --fmap-file and --ifd both specified. Aborting.\n");
			if (layoutfile)
				cli_classic_abort_usage("Error: --fmap-file and --layout both specified. Aborting.\n");
			fmapfile = strdup(optarg);
			fmap = 1;
			break;
		case OPTION_FMAP:
			if (fmap)
				cli_classic_abort_usage("Error: --fmap or --fmap-file specified "
					"more than once. Aborting.\n");
			if (ifd)
				cli_classic_abort_usage("Error: --fmap and --ifd both specified. Aborting.\n");
			if (layoutfile)
				cli_classic_abort_usage("Error: --layout and --fmap both specified. Aborting.\n");
			fmap = 1;
			break;
		case 'i':
			if (register_include_arg(&include_args, optarg))
				cli_classic_abort_usage(NULL);
			break;
		case OPTION_FLASH_CONTENTS:
			if (referencefile)
				cli_classic_abort_usage("Error: --flash-contents specified more than once."
							"Aborting.\n");
			referencefile = strdup(optarg);
			break;
		case OPTION_FLASH_NAME:
			cli_classic_validate_singleop(&operation_specified);
			flash_name = 1;
			break;
		case OPTION_FLASH_SIZE:
			cli_classic_validate_singleop(&operation_specified);
			flash_size = 1;
			break;
		case OPTION_WP_STATUS:
			print_wp_status = 1;
			break;
		case OPTION_WP_LIST:
			print_available_ranges = 1;
			break;
		case OPTION_WP_SET_RANGE:
			if (parse_wp_range(&wp_start, &wp_len) < 0)
				cli_classic_abort_usage("Incorrect wp-range arguments provided.\n");

			set_wp_range = 1;
			break;
		case OPTION_WP_ENABLE:
			enable_wp = 1;
			if (optarg)
				wp_mode_opt = strdup(optarg);
			break;
		case OPTION_WP_DISABLE:
			disable_wp = 1;
			break;
		case OPTION_OTP_STATUS:
			otp_status = 1;
			break;
		case OPTION_OTP_REGION:
			otp_region_opt = strdup(optarg);
			break;
		case OPTION_OTP_READ:
			cli_classic_validate_singleop(&operation_specified);
			filename = strdup(optarg);
			otp_read = 1;
			break;
		case OPTION_OTP_WRITE:
			cli_classic_validate_singleop(&operation_specified);
			filename = strdup(optarg);
			otp_write = 1;
			break;
		case OPTION_OTP_ERASE:
			cli_classic_validate_singleop(&operation_specified);
			otp_erase = 1;
			break;
		case OPTION_OTP_LOCK:
			cli_classic_validate_singleop(&operation_specified);
			otp_lock = 1;
			break;
		case 'L':
			cli_classic_validate_singleop(&operation_specified);
			list_supported = 1;
			break;
		case 'z':
#if CONFIG_PRINT_WIKI == 1
			cli_classic_validate_singleop(&operation_specified);
			list_supported_wiki = 1;
#else
			cli_classic_abort_usage("Error: Wiki output was not "
					"compiled in. Aborting.\n");
#endif
			break;
		case 'p':
			if (prog != NULL) {
				cli_classic_abort_usage("Error: --programmer specified "
					"more than once. You can separate "
					"multiple\nparameters for a programmer "
					"with \",\". Please see the man page "
					"for details.\n");
			}
			size_t p;
			for (p = 0; p < programmer_table_size; p++) {
				name = programmer_table[p]->name;
				namelen = strlen(name);
				if (strncmp(optarg, name, namelen) == 0) {
					switch (optarg[namelen]) {
					case ':':
						pparam = strdup(optarg + namelen + 1);
						if (!strlen(pparam)) {
							free(pparam);
							pparam = NULL;
						}
						prog = programmer_table[p];
						break;
					case '\0':
						prog = programmer_table[p];
						break;
					default:
						/* The continue refers to the
						 * for loop. It is here to be
						 * able to differentiate between
						 * foo and foobar.
						 */
						continue;
					}
					break;
				}
			}
			if (prog == NULL) {
				fprintf(stderr, "Error: Unknown programmer \"%s\". Valid choices are:\n",
					optarg);
				list_programmers_linebreak(0, 80, 0);
				msg_ginfo(".\n");
				cli_classic_abort_usage(NULL);
			}
			break;
		case 'R':
			/* print_version() is always called during startup. */
			cli_classic_validate_singleop(&operation_specified);
			exit(0);
			break;
		case 'h':
			cli_classic_validate_singleop(&operation_specified);
			cli_classic_usage(argv[0]);
			exit(0);
			break;
		case 'o':
#ifdef STANDALONE
			cli_classic_abort_usage("Log file not supported in standalone mode. Aborting.\n");
#else /* STANDALONE */
			if (logfile) {
				fprintf(stderr, "Warning: -o/--output specified multiple times.\n");
				free(logfile);
			}

			logfile = strdup(optarg);
			if (logfile[0] == '\0') {
				cli_classic_abort_usage("No log filename specified.\n");
			}
#endif /* STANDALONE */
			break;
		case OPTION_WP_SET_REGION:
			set_wp_region = 1;
			wp_region = strdup(optarg);
			break;
		default:
			cli_classic_abort_usage(NULL);
			break;
		}
	}

	if (optind < argc)
		cli_classic_abort_usage("Error: Extra parameter found.\n");
	if ((read_it | write_it | verify_it) && check_filename(filename, "image"))
		cli_classic_abort_usage(NULL);
	if (layoutfile && check_filename(layoutfile, "layout"))
		cli_classic_abort_usage(NULL);
	if (fmapfile && check_filename(fmapfile, "fmap"))
		cli_classic_abort_usage(NULL);
	if (referencefile && check_filename(referencefile, "reference"))
		cli_classic_abort_usage(NULL);

#ifndef STANDALONE
	if (logfile && check_filename(logfile, "log"))
		cli_classic_abort_usage(NULL);
	if (logfile && open_logfile(logfile))
		cli_classic_abort_usage(NULL);
#endif /* !STANDALONE */

#if CONFIG_PRINT_WIKI == 1
	if (list_supported_wiki) {
		print_supported_wiki();
		goto out;
	}
#endif

	if (list_supported) {
		if (print_supported())
			ret = 1;
		goto out;
	}

#ifndef STANDALONE
	start_logging();
#endif /* !STANDALONE */

	print_buildinfo();
	msg_gdbg("Command line (%i args):", argc - 1);
	for (i = 0; i < argc; i++) {
		msg_gdbg(" %s", argv[i]);
	}
	msg_gdbg("\n");

	if (layoutfile && layout_from_file(&layout, layoutfile)) {
		ret = 1;
		goto out;
	}

	if (!ifd && !fmap && process_include_args(layout, include_args)) {
		ret = 1;
		goto out;
	}
	/* Does a chip with the requested name exist in the flashchips array? */
	if (chip_to_probe) {
		for (chip = flashchips; chip && chip->name; chip++)
			if (!strcmp(chip->name, chip_to_probe))
				break;
		if (!chip || !chip->name) {
			msg_cerr("Error: Unknown chip '%s' specified.\n", chip_to_probe);
			msg_gerr("Run flashrom -L to view the hardware supported in this flashrom version.\n");
			ret = 1;
			goto out;
		}
		/* Keep chip around for later usage in case a forced read is requested. */
	}

	if (prog == NULL) {
		const struct programmer_entry *const default_programmer = CONFIG_DEFAULT_PROGRAMMER_NAME;

		if (default_programmer) {
			prog = default_programmer;
			/* We need to strdup here because we free(pparam) unconditionally later. */
			pparam = strdup(CONFIG_DEFAULT_PROGRAMMER_ARGS);
			msg_pinfo("Using default programmer \"%s\" with arguments \"%s\".\n",
				  default_programmer->name, pparam);
		} else {
			msg_perr("Please select a programmer with the --programmer parameter.\n"
#if CONFIG_INTERNAL == 1
				 "To choose the mainboard of this computer use 'internal'. "
#endif
				 "Valid choices are:\n");
			list_programmers_linebreak(0, 80, 0);
			msg_ginfo(".\n");
			ret = 1;
			goto out;
		}
	}

	/* FIXME: Delay calibration should happen in programmer code. */
	myusec_calibrate_delay();

	if (programmer_init(prog, pparam)) {
		msg_perr("Error: Programmer initialization failed.\n");
		ret = 1;
		goto out_shutdown;
	}
	tempstr = flashbuses_to_text(get_buses_supported());
	msg_pdbg("The following protocols are supported: %s.\n", tempstr);
	free(tempstr);

	for (j = 0; j < registered_master_count; j++) {
		startchip = 0;
		while (chipcount < (int)ARRAY_SIZE(flashes)) {
			startchip = probe_flash(&registered_masters[j], startchip, &flashes[chipcount], 0);
			if (startchip == -1)
				break;
			chipcount++;
			startchip++;
		}
	}

	if (chipcount > 1) {
		msg_cinfo("Multiple flash chip definitions match the detected chip(s): \"%s\"",
			  flashes[0].chip->name);
		for (i = 1; i < chipcount; i++)
			msg_cinfo(", \"%s\"", flashes[i].chip->name);
		msg_cinfo("\nPlease specify which chip definition to use with the -c <chipname> option.\n");
		ret = 1;
		goto out_shutdown;
	} else if (!chipcount) {
		msg_cinfo("No EEPROM/flash device found.\n");
		if (!force || !chip_to_probe) {
			msg_cinfo("Note: flashrom can never write if the flash chip isn't found "
				  "automatically.\n");
		}
		if (force && read_it && chip_to_probe) {
			struct registered_master *mst;
			int compatible_masters = 0;
			msg_cinfo("Force read (-f -r -c) requested, pretending the chip is there:\n");
			/* This loop just counts compatible controllers. */
			for (j = 0; j < registered_master_count; j++) {
				mst = &registered_masters[j];
				/* chip is still set from the chip_to_probe earlier in this function. */
				if (mst->buses_supported & chip->bustype)
					compatible_masters++;
			}
			if (!compatible_masters) {
				msg_cinfo("No compatible controller found for the requested flash chip.\n");
				ret = 1;
				goto out_shutdown;
			}
			if (compatible_masters > 1)
				msg_cinfo("More than one compatible controller found for the requested flash "
					  "chip, using the first one.\n");
			for (j = 0; j < registered_master_count; j++) {
				mst = &registered_masters[j];
				startchip = probe_flash(mst, 0, &flashes[0], 1);
				if (startchip != -1)
					break;
			}
			if (startchip == -1) {
				// FIXME: This should never happen! Ask for a bug report?
				msg_cinfo("Probing for flash chip '%s' failed.\n", chip_to_probe);
				ret = 1;
				goto out_shutdown;
			}
			if (map_flash(&flashes[0]) != 0) {
				free(flashes[0].chip);
				ret = 1;
				goto out_shutdown;
			}
			msg_cinfo("Please note that forced reads most likely contain garbage.\n");
			ret = read_flash_to_file(&flashes[0], filename);
			unmap_flash(&flashes[0]);
			free(flashes[0].chip);
			goto out_shutdown;
		}
		ret = 1;
		goto out_shutdown;
	} else if (!chip_to_probe) {
		/* repeat for convenience when looking at foreign logs */
		tempstr = flashbuses_to_text(flashes[0].chip->bustype);
		msg_gdbg("Found %s flash chip \"%s\" (%d kB, %s).\n",
			 flashes[0].chip->vendor, flashes[0].chip->name, flashes[0].chip->total_size, tempstr);
		free(tempstr);
	}

	fill_flash = &flashes[0];

	print_chip_support_status(fill_flash->chip);

	unsigned int limitexceeded = count_max_decode_exceedings(fill_flash);
	if (limitexceeded > 0 && !force) {
		enum chipbustype commonbuses = fill_flash->mst->buses_supported & fill_flash->chip->bustype;

		/* Sometimes chip and programmer have more than one bus in common,
		 * and the limit is not exceeded on all buses. Tell the user. */
		if ((bitcount(commonbuses) > limitexceeded)) {
			msg_pdbg("There is at least one interface available which could support the size of\n"
				 "the selected flash chip.\n");
		}
		msg_cerr("This flash chip is too big for this programmer (--verbose/-V gives details).\n"
			 "Use --force/-f to override at your own risk.\n");
		ret = 1;
		goto out_shutdown;
	}

	const bool any_wp_op =
		set_wp_range || set_wp_region || enable_wp ||
		disable_wp || print_wp_status || print_available_ranges;

	const bool any_otp_op =
		otp_status || otp_read || otp_write || otp_erase || otp_lock;

	const bool any_op = read_it || write_it || verify_it || erase_it ||
		flash_name || flash_size || extract_it || any_wp_op ||
		any_otp_op;


	if (!any_op) {
		msg_ginfo("No operations were specified.\n");
		goto out_shutdown;
	}

	if (enable_wp && disable_wp) {
		msg_ginfo("Error: --wp-enable and --wp-disable are mutually exclusive\n");
		ret = 1;
		goto out_shutdown;
	}
	if (set_wp_range && set_wp_region) {
		msg_gerr("Error: Cannot use both --wp-range and --wp-region simultaneously.\n");
		ret = 1;
		goto out_shutdown;
	}

	if (flash_name) {
		if (fill_flash->chip->vendor && fill_flash->chip->name) {
			printf("vendor=\"%s\" name=\"%s\"\n",
				fill_flash->chip->vendor,
				fill_flash->chip->name);
		} else {
			ret = -1;
		}
		goto out_shutdown;
	}

	if (flash_size) {
		printf("%d\n", fill_flash->chip->total_size * 1024);
		goto out_shutdown;
	}

	if (ifd && (flashrom_layout_read_from_ifd(&layout, fill_flash, NULL, 0) ||
			   process_include_args(layout, include_args))) {
		ret = 1;
		goto out_shutdown;
	} else if (fmap && fmapfile) {
		struct stat s;
		if (stat(fmapfile, &s) != 0) {
			msg_gerr("Failed to stat fmapfile \"%s\"\n", fmapfile);
			ret = 1;
			goto out_shutdown;
		}

		size_t fmapfile_size = s.st_size;
		uint8_t *fmapfile_buffer = malloc(fmapfile_size);
		if (!fmapfile_buffer) {
			ret = 1;
			goto out_shutdown;
		}

		if (read_buf_from_file(fmapfile_buffer, fmapfile_size, fmapfile)) {
			ret = 1;
			free(fmapfile_buffer);
			goto out_shutdown;
		}

		if (flashrom_layout_read_fmap_from_buffer(&layout, fill_flash, fmapfile_buffer, fmapfile_size) ||
		    process_include_args(layout, include_args)) {
			ret = 1;
			free(fmapfile_buffer);
			goto out_shutdown;
		}
		free(fmapfile_buffer);
	} else if (fmap && (flashrom_layout_read_fmap_from_rom(&layout, fill_flash, 0,
		       fill_flash->chip->total_size * 1024) || process_include_args(layout, include_args))) {
		ret = 1;
		goto out_shutdown;
	}
	flashrom_layout_set(fill_flash, layout);

	if (any_wp_op) {
		if (set_wp_region && wp_region) {
			ret = get_region_range(layout, wp_region, &wp_start, &wp_len);
			if (ret)
				goto out_release;
			set_wp_range = true;
		}
		ret = wp_cli(
			fill_flash,
			enable_wp,
			disable_wp,
			print_wp_status,
			print_available_ranges,
			set_wp_range,
			wp_start,
			wp_len,
			wp_mode_opt
		);
		if (ret)
			goto out_release;
	}

	ret = otp_cli(fill_flash, any_otp_op, otp_status, otp_read, otp_write, otp_erase, otp_lock,
		      otp_region_opt, filename);
	if (ret)
		goto out_release;

	flashrom_flag_set(fill_flash, FLASHROM_FLAG_FORCE, !!force);
#if CONFIG_INTERNAL == 1
	flashrom_flag_set(fill_flash, FLASHROM_FLAG_FORCE_BOARDMISMATCH, !!force_boardmismatch);
#endif
	flashrom_flag_set(fill_flash, FLASHROM_FLAG_VERIFY_AFTER_WRITE, !dont_verify_it);
	flashrom_flag_set(fill_flash, FLASHROM_FLAG_VERIFY_WHOLE_CHIP, !dont_verify_all);

	/* FIXME: We should issue an unconditional chip reset here. This can be
	 * done once we have a .reset function in struct flashchip.
	 * Give the chip time to settle.
	 */
	programmer_delay(100000);
	if (read_it)
		ret = do_read(fill_flash, filename);
	else if (extract_it)
		ret = do_extract(fill_flash);
	else if (erase_it)
		ret = do_erase(fill_flash);
	else if (write_it)
		ret = do_write(fill_flash, filename, referencefile);
	else if (verify_it)
		ret = do_verify(fill_flash, filename);

out_release:
	flashrom_layout_release(layout);
out_shutdown:
	programmer_shutdown();
out:
	for (i = 0; i < chipcount; i++) {
		flashrom_layout_release(flashes[i].default_layout);
		free(flashes[i].chip);
	}

	cleanup_include_args(&include_args);
	free(filename);
	free(fmapfile);
	free(referencefile);
	free(layoutfile);
	free(pparam);
	/* clean up global variables */
	free((char *)chip_to_probe); /* Silence! Freeing is not modifying contents. */
	chip_to_probe = NULL;
#ifndef STANDALONE
	free(logfile);
	ret |= close_logfile();
#endif /* !STANDALONE */
	return ret;
}
