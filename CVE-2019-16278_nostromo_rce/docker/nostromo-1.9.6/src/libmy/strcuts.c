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

#include <string.h>

/* strcuts()
 *	cuts a string from a string starting at start char until end char
 * Return:
 *	0 = success, -1 = failed
 *
 */

int
strcuts(char *dst, const char *src, const char start, const char end,
	const int dsize)
{
	int	i, j, len;

	len = strlen(src);

	for (i = 0, j = 0; src[i] != start && start != '\0'; i++) {
		/* start not found */
		if (i >= len)
			return -1;
	}

	if (start == '\0') {
		dst[0] = src[0];
		j++;
		i++;
	} else {
		i++;
	}

	for (; src[i] != end && i < len && j != dsize - 1; i++, j++)
		dst[j] = src[i];

	/* terminate string */
	dst[j] = '\0';

	/* end not found */
	if (src[i] != end)
		return -1;

	return 0;	
}
