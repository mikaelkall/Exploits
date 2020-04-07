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

/* data */

static const unsigned char decode[256] = {
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
	 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
	255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
	255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

/*
 * base64d()
 * 	decodes base64 from src to plain at dst
 * Return:
 *	0 = success, -1 = failed
 */

int
strb64d(char *dst, const char *src, const int dsize)
{
	int		ch, i, j = 0;
	char		out[3];
	unsigned char	in_a[4], in_b[4];

	dst[0] = '\0';

	while (1) {
		for (i = 0; i < 4; i++, j++) {
			if (src[j] == '\0')
				goto quit;
			ch = src[j];

			/* ignore if char is not base64 */
			if (decode[ch] == 255) {
				i--;
				continue;
			}

			/* save it */
			in_a[i] = ch;
			in_b[i] = decode[ch];
		}

		/* split the 24-bit field in 3 8-bit */
		out[0] = (in_b[0] << 2) | (in_b[1] >> 4);
		out[1] = (in_b[1] << 4) | (in_b[2] >> 2);
		out[2] = (in_b[2] << 6) |  in_b[3];

		/* padding */
		i = in_a[2] == '=' ? 1 : (in_a[3] == '=' ? 2 : 3);

		/* copy the decoded ascii characters to dst */
		if ((dsize - strlen(dst)) < i)
			return -1;
		else
			strncat(dst, out, i);
	}

	quit:
	return 0;
}
