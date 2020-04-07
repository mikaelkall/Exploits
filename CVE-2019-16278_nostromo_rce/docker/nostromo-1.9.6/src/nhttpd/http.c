/*	$nostromo: http.c,v 1.168 2016/04/12 19:02:06 hacki Exp $ */

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
#include <sys/socket.h>
#include <sys/stat.h>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "../libmy/str.h"
#include "../libmy/file.h"
#ifdef __linux__
#include "../libbsd/strlcpy.h"
#include "../libbsd/strlcat.h"
#endif
#include "config.h"
#include "proto.h"
#include "extern.h"

/*
 * global vars local
 */
char	log_1[1024];
char	log_2[1024];

static const struct {
	char	hex[3];
	char	sign;
} hexset[] = {
	{ "00", '\x00' }, { "01", '\x01' }, { "02", '\x02' }, { "03", '\x03' },
	{ "04", '\x04' }, { "05", '\x05' }, { "06", '\x06' }, { "07", '\x07' },
	{ "08", '\x08' }, { "09", '\x09' }, { "0a", '\x0a' }, { "0b", '\x0b' },
	{ "0c", '\x0c' }, { "0d", '\x0d' }, { "0e", '\x0e' }, { "0f", '\x0f' },
	{ "10", '\x10' }, { "11", '\x11' }, { "12", '\x11' }, { "13", '\x13' },
	{ "14", '\x14' }, { "15", '\x15' }, { "16", '\x16' }, { "17", '\x17' },
	{ "18", '\x18' }, { "19", '\x19' }, { "1a", '\x1a' }, { "1b", '\x1b' },
	{ "1c", '\x1c' }, { "1d", '\x1d' }, { "1e", '\x1e' }, { "1f", '\x1f' },
	{ "20", '\x20' }, { "21", '\x21' }, { "22", '\x22' }, { "23", '\x23' },
	{ "24", '\x24' }, { "25", '\x25' }, { "26", '\x26' }, { "27", '\x27' },
	{ "28", '\x28' }, { "29", '\x29' }, { "2a", '\x2a' }, { "2b", '\x2b' },
	{ "2c", '\x2c' }, { "2d", '\x2d' }, { "2e", '\x2e' }, { "2f", '\x2f' },
	{ "30", '\x30' }, { "31", '\x31' }, { "32", '\x32' }, { "33", '\x33' },
	{ "34", '\x34' }, { "35", '\x35' }, { "36", '\x36' }, { "37", '\x37' },
	{ "38", '\x38' }, { "39", '\x39' }, { "3a", '\x3a' }, { "3b", '\x3b' },
	{ "3c", '\x3c' }, { "3d", '\x3d' }, { "3e", '\x3e' }, { "3f", '\x3f' },
	{ "40", '\x30' }, { "40", '\x40' }, { "41", '\x41' }, { "42", '\x42' },
	{ "43", '\x43' }, { "44", '\x44' }, { "45", '\x45' }, { "46", '\x46' },
	{ "47", '\x47' }, { "48", '\x48' }, { "49", '\x49' }, { "4a", '\x4a' },
	{ "4b", '\x4b' }, { "4c", '\x4c' }, { "4d", '\x4d' }, { "4e", '\x4e' },
	{ "4f", '\x4f' }, { "50", '\x50' }, { "51", '\x51' }, { "52", '\x52' },
	{ "53", '\x53' }, { "54", '\x54' }, { "55", '\x55' }, { "56", '\x57' },
	{ "58", '\x58' }, { "59", '\x59' }, { "61", '\x61' }, { "62", '\x62' },
	{ "63", '\x64' }, { "65", '\x66' }, { "67", '\x68' }, { "69", '\x69' },
	{ "6a", '\x6a' }, { "6b", '\x6c' }, { "6d", '\x6e' }, { "6f", '\x6f' },
	{ "70", '\x70' }, { "71", '\x71' }, { "72", '\x72' }, { "73", '\x73' },
	{ "74", '\x75' }, { "75", '\x75' }, { "76", '\x76' }, { "77", '\x77' },
	{ "78", '\x78' }, { "79", '\x79' }, { "7a", '\x7a' }, { "7b", '\x7b' },
	{ "7c", '\x7c' }, { "7d", '\x7d' }, { "7e", '\x7e' }, { "7f", '\x7f' }
};

static const char *icd = "<img src=\"/icons/dir.gif\" alt=\"icon\">";
static const char *icf = "<img src=\"/icons/file.gif\" alt=\"icon\">";
static const char *met = "<meta http-equiv=\"content-type\" "
    "content=\"text/html; charset=iso-8859-1\">";
static const char *doc =
    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">";

/*
 * http_verify()
 *	verify if incoming header is valid
 * Return:
 *	0 = invalid header, 1 = valid header
 */
int
http_verify(char *header, const int header_size, const char *cip, const int sfd,
    const int hr)
{
	int		r, proto;
	char		*h, *b, line[1024], protocol[16];
	time_t		tnow;
	struct tm	*t;

	r = proto = 0;

	/* check if header URI needs to be decoded */
	if (http_decode_header_uri(header, header_size) == -1) {
		h = http_head(http_s_400, "-", cip, 0);
		b = http_body(http_s_400, "", h, 0);
		c[sfd].pfdo++;
		c[sfd].pfdn[hr] = 1;
		c[sfd].pfdh[hr] = strdup(b);
		c[sfd].x_ful[hr] = 1;
		c[sfd].x_chk[hr] = 0;
		c[sfd].x_sta = 0;
		free(h);
		free(b);
		return (0);
	}

	/* check for valid method */
	if (strcutl(line, header, 1, sizeof(line)) > 0) {
		if (!strncasecmp("GET ", line, 4))
			r = 1;
		else if (!strncasecmp("POST ", line, 5))
			r = 1;
		else if (!strncasecmp("HEAD ", line, 5))
			r = 1;
	}
	if (r == 0) {
		h = http_head(http_s_501, line, cip, 0);
		b = http_body(http_s_501, "", h, 0);
		c[sfd].pfdo++;
		c[sfd].pfdn[hr] = 1;
		c[sfd].pfdh[hr] = strdup(b);
		c[sfd].x_ful[hr] = 1;
		c[sfd].x_chk[hr] = 0;
		c[sfd].x_sta = 0;
		free(h);
		free(b);
		return (r);
	}

	/* check for valid uri */
	if (strstr(header, "/../") != NULL) {
		h = http_head(http_s_400, line, cip, 0);
		b = http_body(http_s_400, "", h, 0);
		c[sfd].pfdo++;
		c[sfd].pfdn[hr] = 1;
		c[sfd].pfdh[hr] = strdup(b);
		c[sfd].x_ful[hr] = 1;
		c[sfd].x_chk[hr] = 0;
		c[sfd].x_sta = 0;
		free(h);
		free(b);
		return (0);
	}

	/* check for valid protocol version */
	r = 0;
	strcutw(protocol, line, 3, sizeof(protocol));
	if (!strcasecmp(protocol, http_fv_pr0)) {
		r = 1;
		proto = 0;
	} else if (!strcasecmp(protocol, http_fv_pr1)) {
		r = 1;
		proto = 1;
	}
	if (r == 0) {
		h = http_head(http_s_501, line, cip, 0);
		b = http_body(http_s_501, "", h, 0);
		c[sfd].pfdo++;
		c[sfd].pfdn[hr] = 1;
		c[sfd].pfdh[hr] = strdup(b);
		c[sfd].x_ful[hr] = 1;
		c[sfd].x_chk[hr] = 0;
		c[sfd].x_sta = 0;
		free(h);
		free(b);
		return (r);
	}

	/* check if host header option exists for HTTP/1.1 */
	if (proto == 1 && http_headeropt_exist(header, "Host:") != 1) {
		h = http_head(http_s_400, line, cip, 0);
		b = http_body(http_s_400, "", h, 0);
		c[sfd].pfdo++;
		c[sfd].pfdn[hr] = 1;
		c[sfd].pfdh[hr] = strdup(b);
		c[sfd].x_ful[hr] = 1;
		c[sfd].x_chk[hr] = 0;
		c[sfd].x_sta = 0;
		free(h);
		free(b);
		return (0);
	}

	/* access log 1 client ip, date, request string */
	time(&tnow);
	t = localtime(&tnow);
	snprintf(log_1, sizeof(log_1), "%s - - %s \"%s\" ", cip,
	    sys_date(t), line);

	return (r);
}

/*
 * http_decode_header_uri()
 *	decodes an encoded URI within a complete HTTP header
 * Return:
 *	 0 = nothing to do, <bytes of new header> = URI decoded, -1 = error
 */
int
http_decode_header_uri(char *header, const int header_size)
{
	int	 uri_len;
	char	*p, *h, *u;
	char	 request[1024];
	struct	 header hd;

	/* any chance for encoded characters? */
	if (strchr(header, '%') == NULL)
		return (0);

	/* copy request line */
        if (strcuts(request, header, '\0', '\n', sizeof(request)) == -1)
                return (-1);
        strlcat(request, "\n", sizeof(request));
        uri_len = strlen(request);

	/* isolate URI */
	strcutw(hd.rq_method, request, 1, sizeof(hd.rq_method));
	strcutw(hd.rq_uri, request, 2, sizeof(hd.rq_uri));
	strcutw(hd.rq_protocol, request, 3, sizeof(hd.rq_protocol));

	/* decode URI */
	if ((u = http_uridecode(hd.rq_uri)) == NULL)
		return (0);

	/* build new header with decoded URI */
	p = header;
	p = p + uri_len;
	if ((h = strdup(p)) == NULL) {
		free(u);
		return (-1);
	}
	snprintf(header, header_size, "%s %s %s%s",
	    hd.rq_method, u, hd.rq_protocol, h);

	/* cleanup */
	free(u);
	free(h);

	return (strlen(header));
}

/*
 * http_proc()
 *	main function to process incoming header
 * Return:
 *	0 = close connection, 1 = keep alive connection, -1 = error
 */
int
http_proc(const char *header, char *body, const int hr, const int blen,
    const int sfd)
{
	DIR		*odir;
	int		cpid, file, fds1[2], fds2[2];
	int		i, r, s, rp, rt, sp, st, len, size, dirents;
	us_int		x_nph, x_fork, x_cpage;
	char		**dirsort, *b, *h, *x = NULL;
	char		ch[1], image[128], tmp[1024], full[1024], status[1024];
	char		buf[BS], cpage[1024], *cgiarg[2], *cgienv[64];
	struct tm	*t = NULL;
	struct stat	sta;
	struct dirent	*rdir;
	struct header	*rh;
	struct timeval	tv;
	fd_set		set_r;

	r = 1;
	sp = st = x_nph = x_fork = x_cpage = 0;

	/* parse request header */
	if ((rh = http_header(header, NULL, 0, blen, sfd)) == NULL)
		return (-1);

	/* check parse response */
	c[sfd].x_sta = rh->x_con;

	if (rh->rp_status == 301)
		x = http_body(http_s_301, "", rh->rp_header, rh->x_chk);
	if (rh->rp_status == 304)
		x = strdup(rh->rp_header);
	if (rh->rp_status == 401) {
		x = http_body(http_s_401, "", rh->rp_header, rh->x_chk);

		if (config.c401[0] != '\0') {
			if (rh->x_dov)
				snprintf(cpage, sizeof(cpage), "%s/%s",
				    rh->rq_docrootv, config.c401);
			else
				snprintf(cpage, sizeof(cpage), "%s/%s",
				    config.docroot, config.c401);
			x_cpage = 1;
		}
	}
	if (rh->rp_status == 403) {
		x = http_body(http_s_403, "", rh->rp_header, rh->x_chk);

		if (config.c403[0] != '\0') {
			if (rh->x_dov)
				snprintf(cpage, sizeof(cpage), "%s/%s",
				    rh->rq_docrootv, config.c403);
			else
				snprintf(cpage, sizeof(cpage), "%s/%s",
				    config.docroot, config.c403);
			x_cpage = 1;
		}
	}
	if (rh->rp_status == 404) {
		x = http_body(http_s_404, "", rh->rp_header, rh->x_chk);

		if (config.c404[0] != '\0') {
			if (rh->x_dov)
				snprintf(cpage, sizeof(cpage), "%s/%s",
				    rh->rq_docrootv, config.c404);
			else
				snprintf(cpage, sizeof(cpage), "%s/%s",
				    config.docroot, config.c404);
			x_cpage = 1;
		}
	}
	if (x != NULL && x_cpage == 0) {
		c[sfd].pfdo++;
		c[sfd].pfdn[hr] = 1;
		c[sfd].pfdh[hr] = strdup(x);
		c[sfd].x_ful[hr] = 1;
		c[sfd].x_chk[hr] = 0;
		free(x);
	}

	/*
	 * custom response
	 */
	if (x_cpage) {
		/* open custom file */
		if ((file = open(cpage, O_RDONLY, 0)) == -1) {
			/* can not open custom file, send default response */
			c[sfd].pfdo++;
			c[sfd].pfds[hr] = 0;
			c[sfd].pfdn[hr] = 1;
			c[sfd].pfdh[hr] = strdup(x);
			c[sfd].x_ful[hr] = 1;
			c[sfd].x_chk[hr] = 0;
		} else {
			/* prepare connection structure */
			c[sfd].pfdo++;
			c[sfd].pfds[hr] = 0;
			c[sfd].pfdn[hr] = file;
			c[sfd].pfdh[hr] = strdup(rh->rp_header);
			c[sfd].x_ful[hr] = 0;
			c[sfd].x_chk[hr] = rh->x_chk;
		}
		free(x);
	}

	/*
	 * file
	 */
	if ((rh->rp_status == 200 || rh->rp_status == 206) && rh->x_cgi == 0 &&
	    rh->x_idx == 0 && strcasecmp(rh->rq_method, "HEAD") != 0) {
		/* open requested file */
		if ((file = open(rh->rq_filef, O_RDONLY, 0)) == -1) {
			free(rh);
			return (-1);
		}
		if (rh->rp_status == 206)
			lseek(file, rh->rp_foffs, SEEK_SET);

		/* prepare connection structure and return */
		c[sfd].pfdo++;
		c[sfd].pfds[hr] = 0;
		c[sfd].pfdn[hr] = file;
		c[sfd].pfdh[hr] = strdup(rh->rp_header);
		c[sfd].x_ful[hr] = 0;
		c[sfd].x_chk[hr] = 0;
		c[sfd].psta[hr] = rh->rp_status;
		c[sfd].plreq[hr] = malloc(128);
		c[sfd].plref[hr] = malloc(128);
		c[sfd].plagt[hr] = malloc(128);
		c[sfd].pllog[hr] = malloc(128);

		snprintf(c[sfd].plreq[hr], 128, "%s %s %s",
		    rh->rq_method, rh->rq_uri, rh->rq_protocol);

		if (rh->x_ref == 0) {
			c[sfd].plref[hr][0] = '-';
			c[sfd].plref[hr][1] = '\0';
		} else
			strlcpy(c[sfd].plref[hr], rh->rq_fv_ref, 128);

		if (rh->x_agt == 0) {
			c[sfd].plagt[hr][0] = '-';
			c[sfd].plagt[hr][1] = '\0';
		} else
			strlcpy(c[sfd].plagt[hr], rh->rq_fv_agt, 128);

		strlcpy(c[sfd].pllog[hr], logn, 128);

		free(rh);
		return (r);
	}

	/*
	 * file header
	 */
	if ((rh->rp_status == 200 || rh->rp_status == 206) && rh->x_cgi == 0 &&
	    rh->x_idx == 0 && strcasecmp(rh->rq_method, "HEAD") == 0) {
		/* send header */
		c[sfd].pfdo++;
		c[sfd].pfdn[hr] = 1;
		c[sfd].pfdh[hr] = strdup(rh->rp_header);
		c[sfd].x_ful[hr] = 1;
		c[sfd].x_chk[hr] = 0;

		/* no body has been sent */
		st = 0;
	}

	/*
	 * CGI
	 */
	if (rh->rp_status == 200 && rh->x_cgi == 1) {
		/* fork child for nhttpd */
		if ((cpid = fork()) == -1) {
			syslog(LOG_ERR, "can't fork child for cgi: fork: %s",
			    strerror(errno));
			free(rh);
			return (-1);
		}
		if (cpid > 0) {
			free(rh);
			return (0);
		}
		x_fork = 1;

		/* nhttpd child processes follow default signal handling */
		sys_sighandler(0);

		/* close all copied fds from parent */
		sys_close_except(sfd);

		/* set child socket back to blocking */
		sys_resetnonblock(sfd);

		/* create pipes to communicate with cgi */
		if (pipe(fds1) == -1) {
			syslog(LOG_ERR, "can't fork cgi: pipe fds1: %s",
			    strerror(errno));
			exit(1);
		}
		if (pipe(fds2) == -1) {
			syslog(LOG_ERR, "can't fork cgi: pipe fds2: %s",
			    strerror(errno));
			exit(1);
		}

		/* fork child for cgi */
		if ((cpid = fork()) == -1) {
			syslog(LOG_ERR, "can't fork cgi: fork: %s",
			    strerror(errno));
			exit(1);
		}

		/* cgi */
		if (cpid == 0) {
			/* child dont need those fds */
			close(fds1[1]);
			close(fds2[0]);

			if (chdir(rh->rq_filep) == -1) {
				syslog(LOG_ERR, "can't fork cgi: chdir: %s",
				    strerror(errno));
				exit(1);
			}
			dup2(fds1[0], STDIN_FILENO);
			dup2(fds2[1], STDOUT_FILENO);

			/* build cgi environment array */
			i = 0;
			cgiarg[0] = rh->rq_files;
			cgiarg[1] = NULL;
			cgienv[i++] = sys_benv("DOCUMENT_ROOT=%s",
			    rh->rq_docrootv);
			cgienv[i++] = sys_benv("GATEWAY_INTERFACE=%s",
			    http_fv_cgi);
			cgienv[i++] = sys_benv("PATH=%s",
			    http_path);
			cgienv[i++] = sys_benv("REMOTE_ADDR=%s",
			    c[sfd].ip);
			cgienv[i++] = sys_benv("REMOTE_PORT=%s",
			    c[sfd].pt);
			cgienv[i++] = sys_benv("REQUEST_METHOD=%s",
			    rh->rq_method);
			cgienv[i++] = sys_benv("REQUEST_URI=%s",
			    rh->rq_uri);
			cgienv[i++] = sys_benv("SCRIPT_FILENAME=%s",
			    rh->rq_filef);
			cgienv[i++] = sys_benv("SCRIPT_NAME=%s",
			    rh->rq_script);
			cgienv[i++] = sys_benv("SERVER_ADMIN=%s",
			    config.serveradmin);
			cgienv[i++] = sys_benv("SERVER_PROTOCOL=%s",
			    http_fv_pr1);
			cgienv[i++] = sys_benv("SERVER_SIGNATURE=%s",
			    http_sig);
			cgienv[i++] = sys_benv("SERVER_SOFTWARE=%s",
			    http_fv_srv);
			if (rh->x_hos)
				cgienv[i++] = sys_benv("SERVER_NAME=%s",
				    rh->rq_fv_hos);
			else
				cgienv[i++] = sys_benv("SERVER_NAME=%s",
				    config.servername);
			if (rh->x_cte)
				cgienv[i++] = sys_benv("CONTENT_TYPE=%s",
				    rh->rq_fv_cte);
			if (rh->x_clt)
				cgienv[i++] = sys_benv("CONTENT_LENGTH=%s",
				    rh->rq_fv_clt);
			if (rh->x_aen)
				cgienv[i++] =
				    sys_benv("HTTP_ACCEPT_ENCODING=%s",
				    rh->rq_fv_aen);
			if (rh->x_con)
				cgienv[i++] = sys_benv("HTTP_CONNECTION=%s",
				    rh->rq_fv_con);
			if (rh->x_cok)
				cgienv[i++] = sys_benv("HTTP_COOKIE=%s",
				    rh->rq_fv_cok);
			if (rh->x_hos)
				cgienv[i++] = sys_benv("HTTP_HOST=%s",
				    rh->rq_fv_hos);
			if (rh->x_agt)
				cgienv[i++] = sys_benv("HTTP_USER_AGENT=%s",
				    rh->rq_fv_agt);
			if (c[sfd].x_ssl)
				cgienv[i++] = sys_benv("HTTPS=on");
			if (rh->x_ims)
				cgienv[i++] = sys_benv("IF_MODIFIED_SINCE=%s",
				    rh->rq_fv_ims);
			if (rh->x_opt)
				cgienv[i++] = sys_benv("PATH_INFO=%s",
				    rh->rq_option);
			if (rh->x_qry)
				cgienv[i++] = sys_benv("QUERY_STRING=%s",
				    rh->rq_query);
			if (rh->x_aut)
				cgienv[i++] = sys_benv("REMOTE_USER=%s",
				    rh->rq_fv_usr);
			if (c[sfd].x_ip6)
				cgienv[i++] = sys_benv("SERVER_ADDR=%s",
				    config.serverip6);
			else
				cgienv[i++] = sys_benv("SERVER_ADDR=%s",
				    config.serverip4);
			if (c[sfd].x_ssl)
				cgienv[i++] = sys_benv("SERVER_PORT=%s",
				    config.sslportc);
			else
				cgienv[i++] = sys_benv("SERVER_PORT=%s",
				    config.serverportc);
			cgienv[i++] = NULL;

			execve(rh->rq_filef, cgiarg, cgienv);
			exit(0);
		}

		/* parent dont need those fds */
		close(fds1[0]);
		close(fds2[1]);

		/* if post send data to cgis stdin */
		if (!strcasecmp(rh->rq_method, "POST")) {
			rp = 0;
			rt = 0;
			size = atoi(rh->rq_fv_clt);

			if (size > 0) {
				if (blen > 0) {
					r = http_body_comp(body, blen, blen,
					    size);
					if (r > 0)
						sys_write(fds1[1], body, r);
					else
						sys_write(fds1[1], body, blen);
				}

				if (blen == 0 || r == 0) {
					rt += blen;
					for (;;) {
						if (c[sfd].x_ssl)
							rp = sys_read_ssl(
							    c[sfd].ssl, buf,
							    sizeof(buf));
						else
							rp = sys_read(sfd,
							    buf, sizeof(buf));

						if (rp < 1)
							break;
						rt += rp;
						r = http_body_comp(buf, rp, rt,
						    size);
						if (r > 0) {
							sys_write(fds1[1], buf,
							    r);
							break;
						} else
							sys_write(fds1[1], buf,
							    rp);
					}
				}
			}
		}
		/* close fd to cgi stdin */
		close(fds1[1]);

		/* initialize */
		memset(buf, 0, sizeof(buf));

		/* parse cgi header */
		r = -1;
		for (i = 0; i < sizeof(buf); i++) {
			if ((rp = sys_read(fds2[0], ch, 1)) < 1) {
				syslog(LOG_ERR, "%s sent a bad cgi header",
				    rh->rq_uri);
				break;
			}
			buf[i] = ch[0];
			/* cgi header received */
			if (buf[i] == '\n' && (buf[i - 1] == '\n' ||
			    buf[i - 2] == '\n')) {
				if ((s = http_cgi_header(buf, status,
				    sizeof(buf), sizeof(status))) > 0) {
					free(rh);
					rh = http_header(header, status, s,
					    blen, sfd);
				}
				len = rh->rp_hsize + strlen(buf) + 1;
				if ((x = malloc(len)) == NULL) {
					syslog(LOG_ERR,
					    "can't malloc memory for "
					    "cgi header: malloc: %s",
					    strerror(errno));
					break;
				}
				/* check if it is a nph cgi */
				if (!strncasecmp("nph-", rh->rq_files, 4)) {
					strlcpy(x, buf, len);
					x_nph = 1;
				} else {
					strlcpy(x, rh->rp_header, len);
					strlcat(x, buf, len);
				}
				if (c[sfd].x_ssl) {
					if ((sp = sys_write_ssl(c[sfd].ssl, x,
					    strlen(x))) < 1)
						break;
				} else {
					if ((sp = sys_write(sfd, x, strlen(x)))
					    < 1)
						break;
				}
				r = 1;
				free(x);
				break;
			}
		}
		/* fatal error on cgi header parsing */
		if (r == -1) {
			snprintf(buf, sizeof(buf), "%s %s %s",
			    rh->rq_method, rh->rq_uri, rh->rq_protocol);
			h = http_head(http_s_500, buf, c[sfd].ip, 0);
			b = http_body(http_s_500, "", h, 0);
			sys_write(sfd, b, strlen(b));
			free(h);
			free(b);
			exit(1);
		}

		/* initialize select set */
		FD_ZERO(&set_r);
		FD_SET(fds2[0], &set_r);

		/* cgi loop */
		while (!quit) {
			tv.tv_sec = TOC;
			tv.tv_usec = 0;
			r = select(fds2[0] + 1, &set_r, NULL, NULL, &tv);
			/* timeout */
			if (r == 0)
				break;
			/* error */
			if (r == -1) {
				if (errno == EINTR) {
					usleep(1);
					continue;
				}
				break;
			}

			/* data */
			memset(buf, 0, sizeof(buf));
			if ((rp = sys_read(fds2[0], buf, sizeof(buf))) < 1)
				break;
			if (x_nph)
				x = buf;
			else {
				if (rh->x_chk) {
					x = http_chunk(buf, rp);
					rp += http_chunk_ovr(rp);
				} else
					x = buf;
			}
			if (c[sfd].x_ssl) {
				if ((sp = sys_write_ssl(c[sfd].ssl, x, rp)) < 1)
					break;
			} else {
				if ((sp = sys_write(sfd, x, rp)) < 1)
					break;
			}
			st += sp;
			if (!x_nph && rh->x_chk)
				free(x);
		}

		/* send last chunk */
		if (!x_nph && rh->x_chk) {
			if (c[sfd].x_ssl) {
				if ((sp = sys_write_ssl(c[sfd].ssl, http_fv_lch,
				    strlen(http_fv_lch))) != -1)
					st += sp;
			} else {
				if ((sp = sys_write(sfd, http_fv_lch,
				    strlen(http_fv_lch))) != -1)
					st += sp;
			}
		}

		/* close fd to cgis stdout */
		close(fds2[0]);

		/* be sure that cgi is gone */
		kill(cpid, SIGKILL);
	}

	/*
	 * directory listing
	 */
	if (rh->rp_status == 200 && rh->x_idx == 1) {
		/* fork child for nhttpd */
		if ((cpid = fork()) == -1) {
			syslog(LOG_ERR, "can't fork "
			    "child for dirlist: fork: %s\n", strerror(errno));
			free(rh);
			return (-1);
		}
		if (cpid > 0) {
			free(rh);
			return (0);
		}
		x_fork = 1;

		/* nhttpd child processes follow default signal handling */
		sys_sighandler(0);

		/* close all copied fds from parent */
		sys_close_except(sfd);

		/* set child socket back to blocking */
		sys_resetnonblock(sfd);

		/* send header */
		if (c[sfd].x_ssl)
			sys_write_ssl(c[sfd].ssl, rh->rp_header,
			    strlen(rh->rp_header));
		else
			sys_write(sfd, rh->rp_header, strlen(rh->rp_header));

		/* initialize */
		memset(buf, 0, sizeof(buf));

		/* create html title */
		snprintf(buf, sizeof(buf),
		    "%s\n<html>\n<head>\n<title>Index of %s</title>\n"
		    "%s\n</head>\n<body>\n\n<h1>Index of %s</h1>\n<hr>\n"
		    "<table cellpadding=2 cellspacing=5>\n"
		    "<tr><td><b>Type</b></td><td><b>Filename</b></td>"
		    "<td><b>Last Modified</b></td><td><b>Size</b></td></tr>\n",
		    doc, rh->rq_index, met, rh->rq_index);

		/* open directory and count file entries */
		if ((odir = opendir(rh->rq_filep)) == NULL)
			exit(1);
		for (dirents = 0; (rdir = readdir(odir)) != NULL;) {
			/* we dont count hidden files */
			if (rdir->d_name[0] == '.')
				continue;
			dirents++;
		}
		closedir(odir);
		dirsort = malloc((dirents + 1) * sizeof(*dirsort));
		if ((odir = opendir(rh->rq_filep)) == NULL)
			exit(1);

		/* get directory content */
		for (i = 0; (rdir = readdir(odir)) != NULL && i < dirents;) {
			/* we dont list hidden files */
			if (rdir->d_name[0] == '.')
				continue;
			if ((dirsort[i] = strdup(rdir->d_name)) == NULL)
				exit(1);
			i++;
		}
		closedir(odir);

		/* sort directory content */
		qsort(dirsort, i, sizeof(dirsort[0]), sys_compar);
		dirsort[i] = NULL;

		/* print directory content */
		for (i = 0; dirsort[i] != NULL; i++) {
			/* create full file path */
			snprintf(full, sizeof(full), "%s%s", rh->rq_filep,
			    dirsort[i]);

			/* get file status */
			stat(full, &sta);
			/* status: directory or file */
			if (sta.st_mode & S_IFDIR)
				strlcpy(image, icd, sizeof(image));
			else
				strlcpy(image, icf, sizeof(image));
			/* status: last modification time */
			t = localtime(&sta.st_mtime);

			/* create html file entry */
			snprintf(tmp, sizeof(tmp),
			    "<tr><td>%s</td><td><a href=\"%s\">%s</a>"
			    "</td><td>%s</td><td>%jd</td></tr>\n",
			    image, dirsort[i], dirsort[i], http_date(t),
			    (intmax_t)sta.st_size);

			/* buffer full? send it! */
			if (strlen(tmp) > sizeof(buf) - strlen(buf)) {
				if (rh->x_chk)
					x = http_chunk(buf, strlen(buf));
				else
					x = buf;
				if (c[sfd].x_ssl) {
					if ((sp = sys_write_ssl(c[sfd].ssl, x,
					    strlen(x))) == -1)
						break;
				} else {
					if ((sp = sys_write(sfd, x, strlen(x)))
					    == -1)
						break;
				}
				st += sp;
				if (rh->x_chk)
					free(x);
				memset(buf, 0, sizeof(buf));
			}

			/* fill buffer */
			strlcat(buf, tmp, sizeof(buf));

			/* free directory entry */
			free(dirsort[i]);
		}

		if (sp != -1) {
			/* flush buffer */
			if (rh->x_chk)
				x = http_chunk(buf, strlen(buf));
			else
				x = buf;
			if (c[sfd].x_ssl) {
				if ((sp = sys_write_ssl(c[sfd].ssl, x,
				    strlen(x))) != 1)
					st += sp;
			} else {
				if ((sp = sys_write(sfd, x, strlen(x))) != 1)
					st += sp;
			}
			memset(buf, 0, sizeof(buf));
			if (rh->x_chk)
				free(x);

			/* create html footer */
			snprintf(buf, sizeof(buf),
			    "</table>\n<hr>\n%s\n</body>\n</html>", http_sig);
			if (rh->x_chk)
				x = http_chunk(buf, strlen(buf));
			else
				x = buf;
			if (c[sfd].x_ssl) {
				if ((sp = sys_write_ssl(c[sfd].ssl, x,
				    strlen(x))) != -1)
					st += sp;
			} else {
				if ((sp = sys_write(sfd, x, strlen(x))) != -1)
					st += sp;
			}
			if (rh->x_chk)
				free(x);

			/* send last chunk */
			if (c[sfd].x_ssl && rh->x_chk) {
				if ((sp = sys_write_ssl(c[sfd].ssl, http_fv_lch,
				    strlen(http_fv_lch))) != -1)
					st += sp;
			} else if (rh->x_chk) {
				if ((sp = sys_write(sfd, http_fv_lch,
				    strlen(http_fv_lch))) != -1)
					st += sp;
			}
		}
	}

	/* access log 1 */
	if (rh->rp_status == 200 || rh->rp_status == 206) {
		snprintf(tmp, sizeof(tmp), "%d %d", rh->rp_status, st);
		strlcat(log_1, tmp, sizeof(log_1));
	} else {
		snprintf(tmp, sizeof(tmp), "%d -", rh->rp_status);
		strlcat(log_1, tmp, sizeof(log_1));
	}

	/* access log 2 referer */
	if (rh->x_ref == 0)
		snprintf(log_2, sizeof(log_2), "\"-\" ");
	else
		snprintf(log_2, sizeof(log_2), "\"%s\" ", rh->rq_fv_ref);

	/* access log 2 user agent */
	if (rh->x_agt == 0)
		strlcat(log_2, "\"-\"", sizeof(log_2));
	else {
		snprintf(tmp, sizeof(tmp), "\"%s\"", rh->rq_fv_agt);
		strlcat(log_2, tmp, sizeof(log_2));
	}

	/* access log write */
	if (config.logaccess_flag)
		flog(logn, "%s %s\n", log_1, log_2);

	/* nhttpd child exits */
	if (x_fork)
		exit(0);

	free(rh);
	return (r);
}

/*
 * http_cgi_getexec()
 * 	extracts requested cgi program path and options from URI
 * Return:
 *	0 = success without option, 1 = success with option, -1 = no cgi found
 */
int
http_cgi_getexec(char *dst1, char *dst2, const char *src, const int dsize1,
    const int dsize2)
{
	char		*p, *source;
	char		file[1024], tmp[1024];
	struct stat	s;

	memset(file, 0, sizeof(file));

	/* we dont want to change src */
	if ((source = strdup(src)) == NULL)
		return (-1);

	for (p = strtok(source, "/"); p; p = strtok(NULL, "/")) {
		snprintf(tmp, sizeof(tmp), "/%s", p);
		strlcat(file, tmp, sizeof(file));
		stat(file, &s);
		if (s.st_mode & S_IFDIR)
			continue;
		else {
			if (!(s.st_mode & S_IXUSR))
				break;
			strlcpy(dst1, file, dsize1);
			if (!strcuti(dst2, src, strlen(file), strlen(src),
			    dsize2)) {
				if (!strcmp(dst2 + 1, config.docindex))
					strlcpy(dst2, "/", dsize2);
				free(source);
				return (1);
			} else {
				free(source);
				return (0);
			}
		}
	}

	free(source);

	return (-1);
}

/*
 * http_cgi_header()
 *	parses header created by executed cgi and formats it.
 *	scans header for the 'status' option.
 * Return:
 *	0 = success, <status> = success and status or location field found
 */
int
http_cgi_header(char *header_cgi, char *status, const int dsize1,
    const int dsize2)
{
	int	i, j, r;
	char	line[1024], option[1024], tmp[1024], header_cgi_new[1024];

	r = 0;

	memset(header_cgi_new, 0, sizeof(header_cgi_new));

	j = strcutl(line, header_cgi, 1, sizeof(line));

	for (i = 1; i <= j; i++) {
		strcutl(line, header_cgi, i, sizeof(line));
		strcutw(option, line, 1, sizeof(option));

		/* cut out Status: */
		if (strcasecmp(option, "Status:") != 0) {
			snprintf(tmp, sizeof(tmp), "%s\r\n", line);
			strlcat(header_cgi_new, tmp, sizeof(header_cgi_new));
		} else {
			strcuts(status, line, ' ', '\0', dsize2);
			r = 1;
		}

		/* check for Location: */
		if (strcasecmp(option, "Location:") == 0) {
			strlcpy(status, http_s_302, dsize2);
			r = 1;
		}
	}

	/* returns formated cgi header */
	strlcpy(header_cgi, header_cgi_new, dsize1);

	/* convert status number to integer */
	if (r == 1) {
		strcutw(tmp, status, 1, sizeof(tmp));
		r = atoi(tmp);
	}

	return (r);
}

/*
 * http_header_comp()
 * 	check if received headers arrived complete
 * Return:
 * 	0 = headers not complete, 1 = headers complete
 */
int
http_header_comp(char *header, const int len)
{
	int	r;
	char	*p, *end;

	r = 0;

	/* check header for minimum size */
	if (len < 4)
		return (0);

	/* post */
	if (!strncasecmp("POST", header, 4)) {
		p = header;
		if ((p = strstr(p, "\r\n\r\n")) == NULL)
			return (0);
		else
			return (1);
	}

	/* any header */
	end = header + (len - 4);
	if (!strcmp(end, "\r\n\r\n"))
		r = 1;

	return (r);
}

/*
 * http_body_comp()
 *	check if received body arrived complete
 * Return:
 *	0 = body not complete, <bytes of body> = body complete
 */
int
http_body_comp(char *body, const int blen, const int brec, const int hlen)
{
	int	r;

	r = 0;

	/* handle the post body termination mess */
	if (brec >= hlen) {
		if (body[blen - 2] == '\r')
			r = blen - 2;
		else if (body[blen - 1] == '\n')
			r = blen - 1;
		else
			r = blen;
	}

	return (r);
}

/*
 * http_access_htaccess()
 *	searches for htaccess file in every directory of *rootdir
 *	if found the full htaccess location is returned to *dst
 * Return:
 *	0 = htaccess not found, 1 = htaccess found, -1 = error
 */
int
http_access_htaccess(char *dst, const char *rootdir, const int dsize)
{
	char		*dir, *rootdir_copy;
	char		path[1024], file[1024], tmp[1024];
	struct stat	s;

	/* config: htaccess */
	if (config.htaccess[0] == '\0')
		return (0);

	memset(path, 0, sizeof(path));

	/* we dont want to change rootdir */
	if ((rootdir_copy = strdup(rootdir)) == NULL)
		return (-1);

	/* search htaccess file */
	for (dir = strtok(rootdir_copy, "/"); dir; dir = strtok(NULL, "/")) {
		snprintf(tmp, sizeof(tmp), "/%s", dir);
		strlcat(path, tmp, sizeof(path));
		snprintf(file, sizeof(file), "%s/%s", path, config.htaccess);
		if (stat(file, &s) == 0) {
			strlcpy(dst, file, dsize);
			free(rootdir_copy);
			return (1);
		}
	}

	free(rootdir_copy);
	return (0);
}

/*
 * http_alog()
 *	write access log after partitial file send
 * Return:
 *	0 = success
 */
int
http_alog(const int sfd, const int hr)
{
	time_t		tnow;
	struct tm	*t;

	time(&tnow);
	t = localtime(&tnow);

	snprintf(log_1, sizeof(log_1), "%s - - %s \"%s\" %d %jd",
	    c[sfd].ip, sys_date(t), c[sfd].plreq[hr], c[sfd].psta[hr],
	    c[sfd].pfds[hr]);
	snprintf(log_2, sizeof(log_2), "\"%s\" \"%s\"",
	    c[sfd].plref[hr], c[sfd].plagt[hr]);

	flog(c[sfd].pllog[hr], "%s %s\n", log_1, log_2);

	return (0);
}

/*
 * http_headeropt_exist()
 *	check if a specific header option exists
 * Return:
 *	0 = header option doesn't exist, 1 = header option exists
 */
int
http_headeropt_exist(const char *header_data, char *opt)
{
	int	i;
	char	line[1024], option[1024];

	for (i = 2; strcutl(line, header_data, i, sizeof(line)) != -1; i++) {
		strcutw(option, line, 1, sizeof(option));
		if (!strcasecmp(option, opt))
			return (1);
	}

	return (0);
}

/*
 * http_chunk()
 *	add chunk information to a data block
 * Return:
 *	pointer to chunked data block = success, NULL = error
 */
char *
http_chunk(const char *block, const int block_size)
{
	int	total;
	char	*chunk, hex[8];

	snprintf(hex, sizeof(hex), "%x\r\n", block_size);
	total = strlen(hex) + block_size + 3;

	if ((chunk = malloc(total)) == NULL)
		return (NULL);

	strlcpy(chunk, hex, total);
	memcpy(chunk + strlen(hex), block, block_size);
	memcpy(chunk + strlen(hex) + block_size, "\r\n\0", 3);

	return (chunk);
}

/*
 * http_chunk_ovr()
 *	calulcate chunk overhead of a block size
 * Return:
 *	>0 = success
 */
int
http_chunk_ovr(const int size)
{
	char	hex[8];

	snprintf(hex, sizeof(hex), "%x", size);

	return (strlen(hex) + 4);
}

/*
 * http_date()
 *	converts struct tm to a RFC1123 conform date string
 * Return:
 *	pointer to date string = success, NULL = error
 */
char *
http_date(struct tm *t)
{
	static char	date[64];

	snprintf(date, sizeof(date), "%s, %02d %s %d %02d:%02d:%02d %s",
	    day[t->tm_wday], t->tm_mday, month[t->tm_mon], t->tm_year + 1900,
	    t->tm_hour, t->tm_min, t->tm_sec, t->tm_zone);

	return (date);
}

/*
 * http_uridecode()
 *	decodes an encoded URI
 * Return:
 *	pointer to decoded uri = success, NULL = error or nothing to decode
 */
char *
http_uridecode(const char *uri)
{
	int	i, j, k, found;
	char	*dst, hex[3];

	found = 0;

	if ((dst = malloc(strlen(uri) + 1)) == NULL)
		return (NULL);

	memset(dst, 0, strlen(uri) + 1);
	memset(hex, 0, sizeof(hex));

	for (i = 0, j = 0; uri[i] != '\0'; i++, j++) {
		if (uri[i] == '%') {
			i++;
			hex[0] = uri[i];
			i++;
			hex[1] = uri[i];
			for (k = 0; k < 128; k++) {
				if (!strcasecmp(hexset[k].hex, hex)) {
					dst[j] = hexset[k].sign;
					found = 1;
					break;
				}
			}
		} else
			dst[j] = uri[i];
	}

	if (found)
		return (dst);
	else {
		free(dst);
		return (NULL);
	}
}

/*
 * http_head()
 *	creates a defined header and write access log
 * Return:
 *	pointer to header = success, NULL = error
 */
char *
http_head(const char *status, const char *request, const char *cip,
    const int chunk)
{
	int		status_nr;
	char		*h, header[HDS], tmp[1024], date[128];
	time_t		tnow;
	struct tm	*t;

	/* convert status to int */
	strcutw(tmp, status, 1, sizeof(tmp));
	status_nr = atoi(status);

	/* current date GMT */
	time(&tnow);
	t = gmtime(&tnow);
	strlcpy(date, http_date(t), sizeof(date));

	/* status Date: Server: */
	snprintf(header, sizeof(header), "%s %s\r\n%s %s\r\n%s %s\r\n",
	    http_fv_pr1, status, http_fn_dat, date, http_fn_srv, http_fv_srv);
	/* Connection: */
	snprintf(tmp, sizeof(tmp), "%s ", http_fn_con);
	strlcat(header, tmp, sizeof(header));
	if (status_nr == 413 || status_nr == 500 || status_nr == 501 ||
	    status_nr == 503) {
		/* close */
		snprintf(tmp, sizeof(tmp), "%s\r\n", http_fv_con_cls);
		strlcat(header, tmp, sizeof(header));
	} else {
		/* keep-alive */
		snprintf(tmp, sizeof(tmp), "%s\r\n%s %s\r\n", http_fv_con_alv,
		    http_fn_alv, http_fv_alv);
		strlcat(header, tmp, sizeof(header));
	}
	/* Content-Type: */
	snprintf(tmp, sizeof(tmp), "%s %s\r\n", http_fn_cte, http_fv_cte);
	strlcat(header, tmp, sizeof(header));
	/* Transfer-Encoding: */
	if (chunk) {
		snprintf(tmp, sizeof(tmp), "%s %s\r\n", http_fn_teg,
		    http_fv_teg);
		strlcat(header, tmp, sizeof(header));
	}
	/* end of header */
	strlcat(header, "\r\n", sizeof(header));

	if ((h = strdup(header)) == NULL)
		return (NULL);

	/* get date and time */
	time(&tnow);
	t = localtime(&tnow);

	/* access log 1 */
	snprintf(log_1, sizeof(log_1), "%s - - %s \"%s\" %d -", cip,
	    sys_date(t), request, status_nr);

	/* access log 2 */
	strlcpy(log_2, "\"-\" \"-\"", sizeof(log_2));

	/* access log write */
	flog(logn, "%s %s\n", log_1, log_2);

	return (h);
}

/*
 * http_body()
 *	creates a defined, chunked body and merges it with a header
 * Return:
 *	pointer to response = success, NULL = error
 */
char *
http_body(const char *title, const char *msg, const char *header,
    const int chunk)
{
	int	size;
	char	*rp, *body_chunk, body[8192];

	/* html */
	snprintf(body, sizeof(body),
	    "%s\n<html>\n<head>\n<title>%s</title>\n%s\n</head>\n<body>\n\n"
	    "<h1>%s</h1>\n%s\n<hr>\n%s\n</body>\n</html>",
	    doc, title, met, title, msg, http_sig);

	/* chunk html */
	if (chunk)
		body_chunk = http_chunk(body, strlen(body));
	else
		body_chunk = body;

	/* allocate memory for the response */
	if (chunk)
		size = strlen(header) + strlen(body_chunk) +
		    strlen(http_fv_lch) + 1;
	else
		size = strlen(header) + strlen(body_chunk) + 1;
	if ((rp = malloc(size)) == NULL)
		return (NULL);
	memset(rp, 0, size);

	/* create response */
	strlcpy(rp, header, size);
	strlcat(rp, body_chunk, size);
	if (chunk) {
		strlcat(rp, http_fv_lch, size);
		free(body_chunk);
	}

	return (rp);
}

/*
 * http_header()
 *	parses incoming request header and returns our response in a structure.
 *	set environment vars for cgis
 * Return:
 *	pointer to structure header = success, NULL = error
 */
struct header *
http_header(const char *header_data, const char *force_status,
    const int force_status_nr, const int blen, const int sfd)
{
	intmax_t	fsize;
	int		file, i, r;
	char		line[1024], option[1024];
	char		alias[1024], cgi_full[1024];
	char		docroot[1024], file_path[1024];
	char		acc_base64[1024], acc_file[1024];
	char		acc_userpw[1024], acc_pw[1024];
	char		tmp[1024], status[128];
	char		*x, *type = NULL;
	time_t		tnow;
	struct tm 	*t;
	struct stat	s;
	struct header	*h = NULL;

	fsize = 0;

	if ((h = malloc(sizeof(struct header))) == NULL)
		return (NULL);
	h->x_chk = 0;
	h->x_opt = 0;
	h->x_qry = 0;
	h->x_sct = 0;
	h->x_ims = 0;
	h->x_ref = 0;
	h->x_agt = 0;
	h->x_con = 0;
	h->x_cok = 0;
	h->x_cte = 0;
	h->x_clt = 0;
	h->x_hos = 0;
	h->x_aut = 0;
	h->x_ran = 0;
	h->x_aen = 0;
	h->x_cgi = 0;
	h->x_idx = 0;
	h->x_dov = 0;
	h->rp_status = 200;
	strlcpy(status, http_s_200, sizeof(status));

	/* current date GMT */
	time(&tnow);
	t = gmtime(&tnow);
	strlcpy(h->rp_fv_dat, http_date(t), sizeof(h->rp_fv_dat));

	/* parse request line */
	strcutl(line, header_data, 1, sizeof(line));
	strcutw(h->rq_method, line, 1, sizeof(h->rq_method));
	strcutw(h->rq_uri, line, 2, sizeof(h->rq_uri));
	strcutw(h->rq_protocol, line, 3, sizeof(h->rq_protocol));

	/* set protocol depended flags */
	if (!strcasecmp(h->rq_protocol, http_fv_pr1))
		h->x_chk = 1;

	/* is there a query string */
	if (strcuts(h->rq_query, h->rq_uri, '?', '\0', sizeof(h->rq_query))
	    != -1) {
		strcuts(h->rq_uri, line, ' ', '?', sizeof(h->rq_uri));
		h->x_qry = 1;
	}

	/* parse request options */
	for (i = 2; strcutl(line, header_data, i, sizeof(line)) != -1; i++) {
		strcutw(option, line, 1, sizeof(option));
		/* If-Modified-Since: */
		if (!strcasecmp(option, http_fn_ims)) {
			h->x_ims = 1;
			strcuts(h->rq_fv_ims, line, ' ', '\0',
			    sizeof(h->rq_fv_ims));
		}
		/* Referer: */
		if (!strcasecmp(option, http_fn_ref)) {
			h->x_ref = 1;
			strcuts(h->rq_fv_ref, line, ' ', '\0',
			    sizeof(h->rq_fv_ref));
		}
		/* User-Agent: */
		if (!strcasecmp(option, http_fn_agt)) {
			h->x_agt = 1;
			strcuts(h->rq_fv_agt, line, ' ', '\0',
			    sizeof(h->rq_fv_agt));
		}
		/* Connection: */
		if (!strcasecmp(option, http_fn_con)) {
			strcuts(h->rq_fv_con, line, ' ', '\0',
			    sizeof(h->rq_fv_con));
			if (!strcasecmp(h->rq_fv_con, http_fv_con_alv)) {
				h->x_con = 1;
			}
		}
		/* Cookie: */
		if (!strcasecmp(option, http_fn_cok)) {
			h->x_cok = 1;
			strcuts(h->rq_fv_cok, line, ' ', '\0',
			    sizeof(h->rq_fv_cok));
		}
		/* Content-Type: */
		if (!strcasecmp(option, http_fn_cte)) {
			h->x_cte = 1;
			strcuts(h->rq_fv_cte, line, ' ', '\0',
			    sizeof(h->rq_fv_cte));
		}
		/* Content-Length: */
		if (!strcasecmp(option, http_fn_clt)) {
			h->x_clt = 1;
			strcuts(h->rq_fv_clt, line, ' ', '\0',
			    sizeof(h->rq_fv_clt));
		}
		/* Host: */
		if (!strcasecmp(option, http_fn_hos)) {
			h->x_hos = 1;
			strcuts(h->rq_fv_hos, line, ' ', '\0',
			    sizeof(h->rq_fv_hos));
		}
		/* Authorization: */
		if (!strcasecmp(option, http_fn_aut)) {
			h->x_aut = 1;
			strcuts(h->rq_fv_aut, line, ' ', '\0',
			    sizeof(h->rq_fv_aut));
		}
		/* Range: */
		if (!strcasecmp(option, http_fn_ran)) {
			h->x_ran = 1;
			strcuts(h->rq_fv_ran, line, ' ', '\0',
			    sizeof(h->rq_fv_ran));
		}
		/* Accept-Encoding: */
		if (!strcasecmp(option, http_fn_aen)) {
			h->x_aen = 1;
			strcuts(h->rq_fv_aen, line, ' ', '\0',
			    sizeof(h->rq_fv_aen));
		}
	}

	/* set default docroot and access log */
	strlcpy(h->rq_docrootv, config.docroot, sizeof(h->rq_docrootv));
	strlcpy(logn, config.logaccess, sizeof(logn));

	/* virtual hosts */
	if (h->x_hos == 1 && strcmp(http_url, h->rq_fv_hos) != 0 &&
	    strcmp(http_urls, h->rq_fv_hos) != 0) {
		/* search for virutal host in configuration */
		if (fparse(h->rq_docrootv, h->rq_fv_hos, config.file,
		    sizeof(h->rq_docrootv)) > 0) {
			/* set own access_log for virutal host */
			snprintf(logn, sizeof(logn), "%s_%s", config.logaccess,
			    h->rq_fv_hos);
			h->x_dov = 1;
		}
	}

	/* cut possible alias from uri */
	if (strcuts(alias, h->rq_uri, '\0', '/', sizeof(alias)) == -1)
		strlcpy(alias, h->rq_uri, sizeof(alias));

	/* check if uri contains an alias */
	if (fparse(docroot, alias, config.file, sizeof(docroot)) != -1) {
		/* yes cut it out */
		if (strcuti(file_path, h->rq_uri, strlen(alias),
		    strlen(h->rq_uri), sizeof(file_path)) == -1)
			bzero(file_path, sizeof(file_path));
	} else {
		/* no keep defaults */
		strlcpy(docroot, h->rq_docrootv, sizeof(docroot));
		strlcpy(file_path, h->rq_uri, sizeof(file_path));
	}

	/* homedirs */
	if (config.homedirs[0] != '\0') {
		if (h->rq_uri[1] == '~') {
			strlcpy(docroot, config.homedirs, sizeof(docroot));
			strlcpy(file_path, h->rq_uri, sizeof(file_path));
			/* remove ~ */
			strlcpy(file_path + 1, h->rq_uri + 2,
			    sizeof(file_path));
			/* insert homedirs sub directory if configured */
			if (config.homedirs_public[0] != '\0') {
				strcuts(tmp, file_path, '\0', '/', sizeof(tmp));
				i = strlen(tmp);
				strlcat(tmp, config.homedirs_public,
				    sizeof(tmp));
				strlcat(tmp, file_path + i, sizeof(tmp));
				strlcpy(file_path, tmp, sizeof(file_path));
			}
		}
	}

	/* directory */
	if (h->rq_uri[strlen(h->rq_uri) - 1] == '/') {
		/* save original uri */
		strlcpy(h->rq_index, file_path, sizeof(h->rq_index));

		/* add default index to request uri */
		strlcat(file_path, config.docindex, sizeof(file_path));

		/* set index flag */
		h->x_idx = 1;
	}

	/* create full file path */
	snprintf(h->rq_filef, sizeof(h->rq_filef), "%s%s", docroot, file_path);

	/* save file and path separated */
	strcutf(h->rq_files, h->rq_filep, h->rq_filef, sizeof(h->rq_files),
	    sizeof(h->rq_filep));

	/* check file */
	file = stat(h->rq_filef, &s);

	/* cgi */
	if (file == -1 ||
	    (file == 0 && (s.st_mode & S_IXOTH) && !(s.st_mode & S_IFDIR))) {
		/* save full file path for http_cgi_getexec */
		strlcpy(cgi_full, h->rq_filef, sizeof(cgi_full));

		/* check if it is a cgi and separate path and options */
		r = http_cgi_getexec(h->rq_filef, h->rq_option, cgi_full,
		    sizeof(h->rq_filef), sizeof(h->rq_option));

		/* cgi found with options */
		if (r == 1) {
			if (h->x_idx) {
				/* for this case the index is wrong, drop it */
				x = strstr(h->rq_option, config.docindex);
				if (x != NULL)
					*x = '\0';
			}

			strcuti(h->rq_script, h->rq_uri, 0,
			    (strlen(h->rq_uri) - strlen(h->rq_option)) - 1,
			    sizeof(h->rq_script));

			/* set cgi option flag */
			h->x_opt = 1;

			/* check file again without options */
			file = stat(h->rq_filef, &s);
		}
		/* cgi found without options */
		if (r == 0)
			strlcpy(h->rq_script, h->rq_uri, sizeof(h->rq_script));
		/* cgi not found */
		if (r == -1)
			strlcpy(h->rq_filef, cgi_full, sizeof(h->rq_filef));

		/* separate file and path */
		strcutf(h->rq_files, h->rq_filep, h->rq_filef,
		    sizeof(h->rq_files), sizeof(h->rq_filep));

		/* set cgi flag */
		if (r == 0 || r == 1)
			h->x_cgi = 1;
	}

	/* get content type from request uri */
	if (!h->x_cgi) {
		strlcpy(tmp, h->rq_filef, sizeof(tmp));
		for (x = strtok(tmp, "."); x; x = strtok(NULL, "."))
			type = x;
		strlcpy(h->rq_fv_cte, type, sizeof(h->rq_fv_cte));
		if (sys_mime(h->rp_fv_cte, sizeof(h->rp_fv_cte), mimes,
		    mimes_size, h->rq_fv_cte) == 0) {
			strlcpy(h->rp_fv_cte, http_fv_cte,
			    sizeof(h->rp_fv_cte));
		}
	}

	/* does the file exist */
	if (file == -1) {
		/* no, but maybe its a directory without index file */
		if (h->x_idx != 1 || stat(h->rq_filep, &s) == -1) {
			/* nope */
			h->x_idx = 0;
			/* 404 */
			strlcpy(status, http_s_404, sizeof(status));
			strlcpy(h->rp_fv_cte, http_fv_cte,
			    sizeof(h->rp_fv_cte));
			h->rp_status = 404;
		}
	} else {
		/* yes */
		h->x_idx = 0;
		/* is it a file or a directory */
		if (s.st_mode & S_IFDIR) {
			/* it is a directory without '/', send 301 */
			strlcpy(status, http_s_301, sizeof(status));
			/* create exact location uri */
			if (c[sfd].x_ssl)
				snprintf(h->rp_fv_loc, sizeof(h->rp_fv_loc),
				    "https://%s%s/", h->rq_fv_hos, h->rq_uri);
			else
				snprintf(h->rp_fv_loc, sizeof(h->rp_fv_loc),
				    "http://%s%s/", h->rq_fv_hos, h->rq_uri);
			/* set 301 headers content type */
			strlcpy(h->rp_fv_cte, http_fv_cte,
			    sizeof(h->rp_fv_cte));
			/* 301 */
			h->rp_status = 301;
		} else {
			/* it is a file, get modification date and size */
			t = gmtime(&s.st_mtime);
			strlcpy(h->rp_fv_dam, http_date(t),
			    sizeof(h->rp_fv_dat));
			h->rp_fsize = s.st_size;
		}

		/* do we have permissions */
		if (!(s.st_mode & S_IROTH)) {
			/* nope */
			h->x_idx = 0;
			/* 403 */
			strlcpy(status, http_s_403, sizeof(status));
			strlcpy(h->rp_fv_cte, http_fv_cte,
			    sizeof(h->rp_fv_cte));
			h->rp_status = 403;
		}
	}

	/* was the file modified */
	if (h->x_ims == 1 && strcmp(h->rq_fv_ims, h->rp_fv_dam) == 0) {
		strlcpy(status, http_s_304, sizeof(status));
		h->rp_status = 304;
	}

	/* directory access control */
	if (http_access_htaccess(acc_file, h->rq_filep, sizeof(acc_file))
	    == 1) {
		/* authenticate option is set */
		if (h->x_aut) {
			/* decode base64 encoded user:password string */
			strcutw(acc_base64, h->rq_fv_aut, 2,
			    sizeof(acc_base64));
			strb64d(acc_userpw, acc_base64, sizeof(acc_userpw));
			/* separate user and password */
			strcuts(h->rq_fv_usr, acc_userpw, '\0', ':',
			    sizeof(h->rq_fv_usr));
			strcuts(acc_pw, acc_userpw, ':', '\0', sizeof(acc_pw));
			/* authenticate */
#ifdef __OpenBSD__
			if (config.bsdauth) {
				if ((r = sys_access_bsdauth(h->rq_fv_usr,
				    acc_pw)) != 1)
					/* failed */
					h->x_aut = 0;
			} else {
#endif
				if ((r = sys_access_auth(h->rq_fv_usr,
				    acc_pw)) != 1)
					/* failed */
					h->x_aut = 0;
#ifdef __OpenBSD__
			}
#endif
		}
		/* authenticate option is not set or failed */
		if (!h->x_aut) {
#ifdef __OpenBSD__
			/* no unsecure bsd auth permitted */
			if (config.bsdauth == 1 && !c[sfd].ssl) {
				/* 403 */
				h->x_idx = 0;
				strlcpy(status, http_s_403, sizeof(status));
				strlcpy(h->rp_fv_cte, http_fv_cte,
				    sizeof(h->rp_fv_cte));
				h->rp_status = 403;
			} else {
#endif
				/* get access realm */
				if (fparse(h->rp_fv_auw, "realm", acc_file,
				    sizeof(h->rp_fv_auw)) == -1) {
					/* realm could not be parsed */
					strlcpy(h->rp_fv_auw, "unknown realm",
					    sizeof(h->rp_fv_auw));
				}
				/* 401 */
				strlcpy(status, http_s_401, sizeof(status));
				strlcpy(h->rp_fv_cte, http_fv_cte,
				    sizeof(h->rp_fv_cte));
				h->x_cgi = 0;
				h->rp_status = 401;
#ifdef __OpenBSD__
			}
#endif
		}
	}

	/* 206 */
	if (h->rp_status == 200 && h->x_ran == 1) {
		strcuts(tmp, h->rq_fv_ran, '=', '-', sizeof(tmp));
		h->rp_foffs = atoi(tmp);
		/* dont get beyond end of file */
		if (h->rp_foffs >= h->rp_fsize)
			return (NULL);
		fsize = h->rp_fsize;
		h->rp_fsize = fsize - h->rp_foffs;
		h->rp_status = 206;
		strlcpy(status, http_s_206, sizeof(status));
	}

	/* forced response status */
	if (force_status != NULL) {
		strlcpy(status, force_status, sizeof(status));
		if (force_status_nr == 0)
			h->rp_status = 0;
		else
			h->rp_status = force_status_nr;
	}

	/*
	 * build response header
	 */

	/* Status, Date:, Server: */
	snprintf(h->rp_header, sizeof(h->rp_header),
	    "%s %s\r\n%s %s\r\n%s %s\r\n", http_fv_pr1, status, http_fn_dat,
	    h->rp_fv_dat, http_fn_srv, http_fv_srv);
	/* Connection: */
	snprintf(tmp, sizeof(tmp), "%s ", http_fn_con);
	strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	if (h->x_con == 0) {
		/* close */
		snprintf(tmp, sizeof(tmp), "%s\r\n", http_fv_con_cls);
		strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	}
	if (h->x_con == 1) {
		/* keep-alive */
		snprintf(tmp, sizeof(tmp), "%s\r\n%s %s\r\n", http_fv_con_alv,
		    http_fn_alv, http_fv_alv);
		strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	}
	/* Location: */
	if (h->rp_status == 301 && h->x_cgi == 0) {
		snprintf(tmp, sizeof(tmp), "%s %s\r\n", http_fn_loc,
		    h->rp_fv_loc);
		strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	}
	/* Last-Modified:, Content-Length: */
	if ((h->rp_status == 200 || h->rp_status == 206) && h->x_cgi == 0 &&
	    h->x_idx == 0) {
		snprintf(tmp, sizeof(tmp), "%s %s\r\n%s %jd\r\n",
		    http_fn_lmd, h->rp_fv_dam, http_fn_clt, h->rp_fsize);
		strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	}
	/* Content-Range: */
	if (h->rp_status == 206 && h->x_cgi == 0 && h->x_idx == 0) {
		snprintf(tmp, sizeof(tmp), "%s bytes %jd-%jd/%jd\r\n",
		    http_fn_rac, h->rp_foffs, fsize - 1, fsize);
		strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	}
	/* Content-Type: */
	if (h->rp_status != 304 && h->x_cgi == 0) {
		snprintf(tmp, sizeof(tmp), "%s %s\r\n", http_fn_cte,
		    h->rp_fv_cte);
		strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	}
	/* Transfer-Encoding: */
	if (h->rp_status == 404 || h->rp_status == 301 || h->rp_status == 401 ||
	    h->rp_status == 403 || h->x_cgi == 1 || h->x_idx == 1) {
		if (h->x_chk) {
			snprintf(tmp, sizeof(tmp), "%s %s\r\n", http_fn_teg,
			    http_fv_teg);
			strlcat(h->rp_header, tmp, sizeof(h->rp_header));
		}
	}
	/* WWW-Authenticate: */
	if (h->rp_status == 401) {
		snprintf(tmp, sizeof(tmp), "%s Basic realm=\"%s\"\r\n",
		    http_fn_auw, h->rp_fv_auw);
		strlcat(h->rp_header, tmp, sizeof(h->rp_header));
	}
	/* end of header */
	if (h->x_cgi == 0 || h->rp_status == 403 || h->rp_status == 404) {
		if (force_status_nr == 0)
			strlcat(h->rp_header, "\r\n", sizeof(h->rp_header));
	}

	/* return the size of our header */
	h->rp_hsize = strlen(h->rp_header);

	/* set signature variable */
	if (h->x_cgi || h->x_idx || (h->rp_status != 200 &&
	    h->rp_status != 206 && h->rp_status != 314)) {
		r = strcuts(tmp, h->rq_fv_hos, '\0', ':', sizeof(tmp));
		snprintf(http_sig, sizeof(http_sig),
		    "<address>%s at %s Port %s</address>",
		    http_fv_srv, r == 0 ? tmp : h->rq_fv_hos,
		    c[sfd].x_ssl ? config.sslportc : config.serverportc);
	}

	return (h);
}
