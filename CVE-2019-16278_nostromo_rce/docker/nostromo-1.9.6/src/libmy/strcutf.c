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

/* strcutf()
 *	separates filename from path
 * Return:
 *	0 = success
 *
 */

int
strcutf(char *dst1, char *dst2, const char *src, const int dsize1,
	const int dsize2)
{
	int	i, j, k, x, slash;

	for (i = 0, slash = 0; src[i] != '\0'; i++) {
		if (src[i] == '/')
			slash++;
	}

	for (i = 0, j = 0, k = 0, x = 0; src[i] != '\0'; i++) {
		if (x == slash && j != dsize1 - 1) {
			dst1[j] = src[i];
			j++;
		} else if (k != dsize2-1) {
			dst2[k] = src[i];
			k++;
		}
		if (src[i] == '/' && x != slash)
			x++;
	}

	/* terminate string */
	dst1[j] = '\0';	/* filename */
	dst2[k] = '\0';	/* path */

	return 0;
}
