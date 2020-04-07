/*	$nostromo: proto.h,v 1.46 2016/04/12 19:02:06 hacki Exp $ */

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
 * main.c
 */
void		usage(const int);
void		sig_handler(const int);
void		send_full(const int, const int);
void		send_chunk(const int, const int);
void		send_file(const int, const int);
int		sdlisten(int, int);
int		load_config(int);

/*
 * http.c
 */
int		http_decode_header_uri(char *, const int);
int		http_verify(char *, const int, const char *, const int,
		    const int);
int		http_proc(const char *, char *, const int, const int,
		    const int);
int		http_cgi_getexec(char *, char *, const char *, const int,
		    const int);
int		http_cgi_header(char *, char *, const int, const int);
int		http_header_comp(char *, const int);
int		http_body_comp(char *, const int, const int, const int);
int		http_access_htaccess(char *, const char *, const int);
int		http_alog(const int, const int);
int		http_headeropt_exist(const char *, char *);
int		http_chunk_ovr(const int);
char *		http_chunk(const char *, const int);
char *		http_date(struct tm *);
char *		http_uridecode(const char *);
char *		http_head(const char *, const char *, const char *, const int);
char *		http_body(const char *, const char *, const char *, const int);
struct header *	http_header(const char *, const char *, const int, const int,
		    const int);

/*
 * sys.c
 */
int		sys_mime(char *, const int, const char *, const int,
		    const char *);
int		sys_bac_init(void);
void		sys_bac_free(void);
void		sys_bac_add(const char *, const char *);
int		sys_bac_match(const char *, const char *);
int		sys_access_auth(const char *, const char *);
#ifdef __OpenBSD__
int		sys_access_bsdauth(const char *, const char *);
void		sys_daemon_bsdauth(void);
#endif
int		sys_read(const int, char *, const int);
int		sys_read_a(const int, char *, const int);
int		sys_read_ssl(SSL *, char *, const int);
int		sys_write(const int, const char *, const int);
int		sys_write_a(const int, const char *, const int);
int		sys_write_ssl(SSL *, const char *, const int);
int		sys_resetnonblock(const int);
int		sys_close_except(const int);
void		sys_log(const int, const char *, ...);
int		sys_compar(const void *, const void *);
char *		sys_date(struct tm *);
char *		sys_benv(const char *, ...);
void		sys_sighandler(int);
