/*
 * Copyright (c) 2004, 2005 Marcus Glocker <marcus@nazgul.ch>
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
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __linux__
#include "../libbsd/strlcpy.h"
#endif

/* fparse()
 *	parses a two column-data file (parameter parameter-value)
 *	ignores comment (#)
 *	spaces in the second column (parameter-value) are read
 * Return:
 *	<row number> = success, -1 = failed
 *
 */

int
fparse(char *dst, const char *src, const char *file, const int dsize)
{
	int		fd;
	int		d = 0, i = 0, r = 1, size = 8192;
	char		a[2][8192], t[8192], *b, *b_copy;
	struct stat	s;

	if ((fd = open(file, O_RDONLY)) == -1)
		return -1;
	if (stat(file, &s) == 0) {
		if ((b = malloc(s.st_size + 1)) == NULL)
			return -1;
		b[s.st_size] = '\0';
		b_copy = b;
	} else {
		return -1;
	}
	if (read(fd, b, s.st_size) == -1)
		return -1;
	close(fd);

	for (; *b != '\0'; b++) {
		if (*b == '#') {
			while (*b != '\n')
				b++;
			r++;
		}
		if (*b != ' ' && *b != '\t' && *b != '\n') {
			if (i != size - 1) {
				t[i] = *b;
				i++;
			}
		}
		if (i == 0)
			continue;
		if (*b == ' ' || *b == '\t' || *b == '\n') {
			if (d == 1 && b[0] == ' ') {
				if (i != size - 1) {
					t[i] = *b;
					i++;
				}
			} else {
				t[i] = '\0';
				strlcpy(a[d], t, sizeof(a[d]));
				i = 0;
				if (d == 0) {
					d++;
				} else {
					r++;
					if (strcmp(a[d - 1], src) == 0) {
						strlcpy(dst, a[d], dsize);
						free(b_copy);
						return r;
					}
					d--;
				}
			}
		}
	}

	free(b_copy);
	return -1;
}
