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

/* strcutl()
 *	cuts a specific line in a string separated by LF's
 * Return:
 *	<total number of lines> = success, -1 = failed
 *
 */

int
strcutl(char *dst, const char *src, const int line, const int dsize)
{
	int	i = 0, j = 0, cl = 0;

	/* first count all lines */
	while (1) {
		if (src[i] == '\n' && src[i + 1] == '\0') {
			cl++;
			break;
		}
		if (src[i] == '\0') {
			cl++;
			break;
		}
		if (src[i] == '\n')
			cl++;

		i++;
	}

	/* do we have the requested line ? */
	if (line > cl || line == 0)
		return -1;

	/* go to line start */
	for (i = 0, j = 0; j != line - 1; i++)
		if (src[i] == '\n')
			j++;

	/* read requested line */
	for (j = 0; src[i] != '\n' && src[i] != '\0' && j != dsize - 1; i++) {
		if (src[i] != '\r') {
			dst[j] = src[i];
			j++;
		}
	}

	/* terminate string */
	dst[j] = '\0';

	return cl;
}
