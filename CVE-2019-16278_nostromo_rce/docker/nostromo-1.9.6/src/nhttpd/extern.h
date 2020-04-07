/*	$nostromo: extern.h,v 1.65 2016/04/12 19:02:06 hacki Exp $ */

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

#include <stdint.h>
#include <signal.h>

#include "config.h"

/*
 * typedefs
 */
typedef unsigned short int us_int;

/*
 * general variables
 */
extern volatile sig_atomic_t	quit;
extern int			debug;
extern int			mimes_size;
#ifdef __OpenBSD__
extern int			fdbsdauth[2];
#endif
extern char			*mimes;
extern char			logn[1024];

/*
 * constant strings
 */
extern const char *month[12];
extern const char *day[7];
extern const char *http_s_200;
extern const char *http_s_206;
extern const char *http_s_301;
extern const char *http_s_302;
extern const char *http_s_304;
extern const char *http_s_400;
extern const char *http_s_401;
extern const char *http_s_403;
extern const char *http_s_404;
extern const char *http_s_413;
extern const char *http_s_500;
extern const char *http_s_501;
extern const char *http_s_503;
extern const char *http_fn_dat;
extern const char *http_fn_srv;
extern const char *http_fn_lmd;
extern const char *http_fn_clt;
extern const char *http_fn_ims;
extern const char *http_fn_ref;
extern const char *http_fn_agt;
extern const char *http_fn_con;
extern const char *http_fn_alv;
extern const char *http_fn_cok;
extern const char *http_fn_teg;
extern const char *http_fn_cte;
extern const char *http_fn_loc;
extern const char *http_fn_hos;
extern const char *http_fn_aut;
extern const char *http_fn_auw;
extern const char *http_fn_ran;
extern const char *http_fn_rac;
extern const char *http_fn_aen;
extern const char *http_fv_srv;
extern const char *http_fv_pr0;
extern const char *http_fv_pr1;
extern const char *http_fv_cgi;
extern const char *http_fv_teg;
extern const char *http_fv_lch;
extern const char *http_fv_con_alv;
extern const char *http_fv_con_cls;

/*
 * strings
 */
extern char http_fv_alv[128];
extern char http_fv_cte[128];
extern char http_url[128];
extern char http_urls[128];
extern char http_sig[128];
extern char http_path[128];

/*
 * server configuration values
 */
struct cfg {
	int	serverport;		/* Listener Port */
	char	serverportc[8];		/* Listener Port in char */
	char	serverip4[24];		/* IPv4 Address */
	char	serverip6[24];		/* IPv6 Address */
	char	servername[1024];	/* Servers connect URL */
	char	serverlisten[1024];	/* Servers listener interfaces */
	char	serveradmin[1024];	/* Server Admin Email */
	char	serverroot[1024];	/* Full Path to server root */
	char	servermimes[1024];	/* Filename for mime types */
	int	logpid_flag;		/* Pid log Flag */
	char	logpid[1024];		/* Filename for server pid */
	int	logaccess_flag;		/* Access log Flag */
	char	logaccess[1024];	/* Filename for access log */
	char	docroot[1024];		/* Full Path to server document root */
	char	docindex[1024];		/* Filename for index documents */
	char	user[1024];		/* Server runs under that user */
	char	htaccess[1024];		/* Filename for basic auth */
	char	htpasswd[1024];		/* Full Filename for basic auth users */
	char	file[1024];		/* Full Filename for config file */
#ifdef __OpenBSD__
	int	bsdauth;		/* BSD auth Flag */
#endif
	int	ssl;			/* SSL Flag */
	int	sslport;		/* SSL Listener Port */
	char	sslportc[8];		/* SSL Listener Port in char */
	char	sslcert[1024];		/* SSL Full Filename for server cert */
	char	sslcertkey[1024];	/* SSL Full Filename for server key */
	char	c401[1024];		/* Filename for 401 custom response */
	char	c403[1024];		/* Filename for 403 custom response */
	char	c404[1024];		/* Filename for 404 custom response */
	char	homedirs[1024];		/* Full Path to homedirs */
	char	homedirs_public[1024];	/* Path to homedirs public directory */
};
extern struct cfg config;

/*
 * information structure for header
 */
struct header {
	char	rq_method[1024];	/* Request Method */
	char	rq_uri[1024];		/* Request URI */
	char	rq_protocol[1024];	/* Request HTTP Protocol */
	char	rq_files[1024];		/* Request Filename */
	char	rq_filep[1024];		/* Request Path */
	char	rq_filef[1024];		/* Request Filename with Path */
	char	rq_query[1024];		/* Request Query String */
	char	rq_option[1024];	/* Request Option String */
	char	rq_script[1024];	/* Request Script String */
	char	rq_index[1024];		/* Request Index Filename */
	char	rq_docrootv[1024];	/* Request Virtual Docroot */
	char	rq_fv_usr[1024];	/* Request Remote User */
	char	rq_fv_cte[1024];	/* Request Value Content-Type: */
	char	rq_fv_ims[1024];	/* Request Value If-Modified-Since: */
	char	rq_fv_ref[1024];	/* Request Value Referer: */
	char	rq_fv_agt[1024];	/* Request Value User-Agent: */
	char	rq_fv_con[1024];	/* Request Value Connection: */
	char	rq_fv_cok[1024];	/* Request Value Cookie: */
	char	rq_fv_clt[1024];	/* Request Value Content-Length: */
	char	rq_fv_hos[1024];	/* Request Value Host: */
	char	rq_fv_aut[1024];	/* Request Value Authorization: */
	char	rq_fv_ran[1024];	/* Request Value Range: */
	char	rq_fv_aen[1024];	/* Request Value Accept-Encoding: */
	char	rp_fv_dat[1024];	/* Response Value Date: */
	char	rp_fv_dam[1024];	/* Response Value ? */
	char	rp_fv_cte[1024];	/* Response Value Content-Type: */
	char	rp_fv_loc[1024];	/* Response Value Location: */
	char	rp_fv_auw[1024];	/* Response Value WWW-Authenticate: */
	char	rp_header[8192];	/* Response Header */
	intmax_t	rp_fsize;	/* Repsonse File Size */
	intmax_t	rp_foffs;	/* Response File Offset */
	int	rp_hsize;		/* Response Header Size */
	us_int	rp_status;		/* Response Status */
	us_int	x_chk;			/* Flag for Chunking */
	us_int	x_opt;			/* Flag for Option */
	us_int	x_qry;			/* Flag for Query */
	us_int	x_sct;			/* Flag for Script */
	us_int	x_ims;			/* Flag for If-Modified-Since: */
	us_int	x_ref;			/* Flag for Referer: */
	us_int	x_agt;			/* Flag for User-Agent: */
	us_int	x_con;			/* Flag for Connection: */
	us_int	x_cok;			/* Flag for Cookie: */
	us_int	x_cte;			/* Flag for Content-Type: */
	us_int	x_clt;			/* Flag for Content-Lenght: */
	us_int	x_hos;			/* Flag for Host: */
	us_int	x_aut;			/* Flag for Authorization: */
	us_int	x_ran;			/* Flag for Range: */
	us_int	x_aen;			/* Flag for Range: */
	us_int	x_cgi;			/* Flag for CGI */
	us_int	x_idx;			/* Flag for Index */
	us_int	x_dov;			/* Flag for Virutal Host */
};

/*
 * information structure for each connection
 */
struct connection {
	SSL	*ssl;			/* Connection, SSL Object */
	char	pt[8];			/* Connection, Client Port */
	char	ip[24];			/* Connection, Client IP */
	char	*rbuf;			/* Connection, Read buf */
	char	*wbuf;			/* Connection, Write buf */
	intmax_t	roff;		/* Connection, Read buf offset */
	intmax_t	wred;		/* Connection, Write buf read bytes */
	intmax_t	wsnd;		/* Connection, Write buf sent bytes */
	int	to;			/* Connection, Timeout */
	int	pfdo;			/* Connection, Open File descriptors */
	int	pfdn[HDN];		/* Partitial, File descriptor */
	intmax_t	pfds[HDN];	/* Partitial, Bytes sent */
	int	psta[HDN];		/* Partitial, Response Status */
	char	*pfdh[HDN];		/* Partitial, Response Header */
	char	*plreq[HDN];		/* Partitial, Log Request */
	char	*plref[HDN];		/* Partitial, Log Referer */
	char	*plagt[HDN];		/* Partitial, Log Client */
	char	*pllog[HDN];		/* Partitial, Log File */
	us_int	x_chk[HDN];		/* Partitial, Flag for Chunked block */
	us_int	x_ful[HDN];		/* Partitial, Flag for Full block */
	us_int	x_ssl;			/* Connection, Flag for SSL */
	us_int	x_ip6;			/* Connection, Flag for IPv6 */
	us_int	x_sta;			/* Connection, Flag for State */
};
extern struct connection c[];

struct listener {
	int	sd;			/* Listener socket */
	us_int 	sdtype;			/* Listener socket type.  Can be: */
#define IPALL	1			/* Set for every listener socket */
#define IP4	2			/* Set for IPv4 socket */
#define IP4SSL	4			/* Set for IPv4 SSL socket */
#define IP6	8			/* Set for IPv6 socket */
#define IP6SSL	16			/* Set for IPv6 SSL socket */
};
extern struct listener l[];

/*
 * basic authentication cache
 */
struct ba_cache {
	time_t	timestamp;		/* Timestamp when entry was added */
	char	username[1024];		/* Username */
	char	password[1024];		/* Password in clear text! */
#define BAC_ENTRIES 128
};
extern struct ba_cache **bac;
