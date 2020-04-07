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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* flogd()
 *	writes a string into a file including current date as first entry
 *	arguments possible
 * Return:
 *	0 = success, -1 = failed
 *
 */

int
flogd(const char *file, const char *string, ...)
{
	FILE		*sfile;
	char		*d;
	va_list		ap;
	time_t		tnow;
	struct tm	*t;

	if ((sfile = fopen(file, "a")) == NULL)
		return -1;

	time(&tnow);
	t = localtime(&tnow);
	d = asctime(t);
	d[strlen(d) - 1] = '\0';
	fprintf(sfile, "[%s] ", d);

	va_start(ap, string);
	vfprintf(sfile, string, ap);
	va_end(ap);

	fclose(sfile);

	return 0;
}
