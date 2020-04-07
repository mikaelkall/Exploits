/*	$nostromo: crypt.c,v 1.17 2016/04/12 19:02:58 hacki Exp $ */

/*
 * Copyright (c) 2004 - 2016 Marcus Glocker <marcus@nazgul.ch>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <crypt.h>
#include "../libbsd/strlcpy.h"
#include "../libbsd/strlcat.h"
#endif

#define DEFAULT_FILENAME "/var/nostromo/conf/.htpasswd"

/*
 * Prototypes
 */
void	usage(int);

/*
 * Global variables
 */
static const char salt_charset[64] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

static const struct {
	char	name[16];
	int	id;
	char	id_sub;
	int	rounds;
	int	salt_len;
#define ALG_NR 4
#define ALG_DEFAULT 2
} algs[ALG_NR] = {
	{ "DES",	0, ' ', 0,  2 },
	{ "MD5",	1, ' ', 0,  8 },
	{ "Blowfish-a",	2, 'a', 4, 22 },
	{ "Blowfish-b",	2, 'b', 4, 22 }
};

/*
 * Function
 */
void
usage(int mode)
{
	int		 i;
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-h] "
	    "[-u username] [-p password] [-a algorithm] [-f filename]\n",
	    __progname);

	if (mode == 1) {
		fprintf(stderr, "\noptions:\n");
		fprintf(stderr, "  -h\t\t: This help.\n");
		fprintf(stderr, "  -u username\t: Username to create.\n");
		fprintf(stderr, "  -p password\t: Password to hash.\n");
		fprintf(stderr, "  -a algorithm\t: Hashing algorithms:\n");
		for (i = 0; i < ALG_NR; i++) {
			fprintf(stderr, "\t\t  %s", algs[i].name);
			if (i == ALG_DEFAULT)
				fprintf(stderr, " (default)");
			fprintf(stderr, "\n");
		}
		fprintf(stderr, "  -f filename\t: Password file "
		    "(default: %s).\n", DEFAULT_FILENAME);
	}

	exit(1);
}

int
main(int argc, char *argv[])
{
	FILE	*file;
	int	 i, n, ch, alg;
	char	*password;
	char	 salt[32], setting[64];
	int	 opt_username, opt_password, opt_algorithm, opt_filename;
	char	 arg_username[64], arg_password[64], arg_algorithm[64];
	char	 arg_filename[64];

	alg = opt_username = opt_password = opt_algorithm = opt_filename = 0;

	/*
	 * Parse command line options.
	 */
	while ((ch = getopt(argc, argv, "hf:a:u:p:")) != -1) {
		switch (ch) {
		case 'h':
			usage(1);
			break;
		case 'u':
			strlcpy(arg_username, optarg, sizeof(arg_username));
			opt_username = 1;
			break;
		case 'p':
			strlcpy(arg_password, optarg, sizeof(arg_password));
			opt_password = 1;
			break;
		case 'a':
			strlcpy(arg_algorithm, optarg, sizeof(arg_algorithm));
			opt_algorithm = 1;
			break;
		case 'f':
			strlcpy(arg_filename, optarg, sizeof(arg_filename));
			opt_filename = 1;
			break;
		default:
			usage(0);
			/* NOTREACHED */
		}
	}

	/*
	 * Validate command line options.
	 */
	if (opt_username == 0 || opt_password == 0) {
		warnx("Username and password are mandatory!");
		usage(0);
	}

	if (opt_algorithm == 0) {
		alg = ALG_DEFAULT;
	} else {
		for (i = 0; i < ALG_NR; i++) {
			if (strcasecmp(algs[i].name, arg_algorithm) == 0) {
				alg = i;
				break;
			}
		}
		if (i == ALG_NR) {
			warnx("Algorithm '%s' is unknown!", arg_algorithm);
			usage(1);
		}
	}

	if (opt_filename == 0)
		strlcpy(arg_filename, DEFAULT_FILENAME, sizeof(arg_filename));

	/*
	 * Generate random salt.
	 */
	srand(time(NULL));

	memset(salt, 0, sizeof(salt));
	for (i = 0; i < algs[alg].salt_len; i++) {
#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__)
		n = arc4random_uniform(63);
#else
		/* shift random number to 7-bits signed (0 - 63) */
		n = rand() >> 25;
#endif
		salt[i] = salt_charset[n];
	}

	/*
	 * Create setting string.
	 */
	switch (algs[alg].id) {
	/* DES */
	case 0:
		snprintf(setting, sizeof(setting), "%s", salt);
		break;
	/* MD5 */
	case 1:
		snprintf(setting, sizeof(setting), "$%d$%s",
		    algs[alg].id, salt);
		break;
	/* Blowfish a + b */
	case 2:
		snprintf(setting, sizeof(setting), "$%d%c$%02d$%s",
		    algs[alg].id, algs[alg].id_sub, algs[alg].rounds, salt);
		break;
	default:
		usage(0);
		/* NOTREACHED */
	}

	/*
	 * Encrypt password.
	 */
	password = crypt(arg_password, setting);
	if (password == NULL) {
		warnx("Algorithm '%s' isn't supproted by OS!", algs[alg].name);
		usage(1);
	}

	/*
	 * Write password line.
	 */
	file = fopen(arg_filename, "a");
	if (file == NULL)
		err(1, "fopen");
	fprintf(file, "%s:%s\n", arg_username, password);
	fclose(file);

	/*
	 * Inform user that we are done.
	 */
	printf("User '%s' added to file '%s' with '%s' algorithm.\n",
	    arg_username, arg_filename, algs[alg].name);

	return (0);
}
