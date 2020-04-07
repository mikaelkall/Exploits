/*	$nostromo: config.h,v 1.18 2016/04/12 19:02:06 hacki Exp $ */

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

/*
 * You can tune nostromo with this parameters.  Please do just change
 * this parameters if you fully understand them.  Wrong parameters can
 * cause server crashs or bad performance.
 */

/*
 * maximal listener sockets
 */
#define LST	32

/*
 * maximal concurrent connections
 */
#define CON	1024

/*
 * maximal request headers we receive at once
 */
#define HDN	16

/*
 * maximal header size (bytes)
 */
#define HDS	8192

/*
 * maximal block size we send data to client (bytes)
 */
#define BS	8192

/*
 * socket send buffer size (bytes), 0 = keep operating system default
 */
#define SBS	0

/*
 * network session timeout: client<->server (seconds)
 */
#define TON	15

/*
 * CGI session timeout: cgi<->server (seconds)
 */
#define TOC	60

/*
 * default server ports
 */
#define PRT	80
#define PRTS	443
