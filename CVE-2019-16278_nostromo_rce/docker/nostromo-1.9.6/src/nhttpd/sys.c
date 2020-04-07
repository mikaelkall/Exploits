/*	$nostromo: sys.c,v 1.73 2016/04/12 19:02:06 hacki Exp $ */

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
#include <sys/time.h>
#include <sys/resource.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#ifdef __OpenBSD__
#include <bsd_auth.h>
#include <login_cap.h>
#endif

#include "../libmy/str.h"
#include "../libmy/file.h"
#ifdef __linux__
#include <crypt.h>
#include "../libbsd/strlcpy.h"
#endif
#include "proto.h"
#include "extern.h"

/*
 * sys_mime()
 * 	searches mime type in our memory mapped mime list
 * Return:
 *	0 = mime not found, 1 = mime found
 */
int
sys_mime(char *dst, const int dsize, const char *mimes, const int msize,
    const char *type)
{
	int	i, j, k, field, comment;
	char	*x, l[2][1024];

	field = 1;
	comment = 0;

	for (i = 0, j = 0, k = 0; i < msize && k < sizeof(l[0]); i++) {
		if (mimes[i] == '#')
			comment = 1;
		if (comment) {
			if (mimes[i] == '\n')
				comment = 0;
			continue;
		}

		switch (field) {
		case 1:
			if (mimes[i] == '\n') {
				j = 0; k = 0; field = 1;
				break;
			}

			if (mimes[i] != ' ' && mimes[i] != '\t') {
				l[j][k] = mimes[i];
				k++;
			} else {
				l[j][k] = '\0';
				field = 2;
			}
			break;
		case 2:
			if (mimes[i] == '\n') {
				j = 0; k = 0; field = 1;
				break;
			}

			if (mimes[i] != ' ' && mimes[i] != '\t') {
				j = 1; k = 0; field = 3;
				l[j][k] = mimes[i];
				k++;
			}
			break;
		case 3:
			if (mimes[i] != '\n') {
				l[j][k] = mimes[i];
				k++;
				break;
			}

			l[j][k] = '\0';
			for (x = strtok(l[1], " "); x; x = strtok(NULL, " ")) {
				if (strcasecmp(x, type) == 0) {
					strlcpy(dst, l[0], dsize);
					return (1);
				}
			}
			j = 0; k = 0; field = 1;
			break;
		}
	}

	return (0);
}

/*
 * sys_bac_init()
 *	initialize memory for basic authentication cache
 * Return:
 *	0 = success, -1 = error
 */
int
sys_bac_init(void)
{
	int	i;

	bac = malloc(BAC_ENTRIES * sizeof(*bac));
	if (bac == NULL)
		return (-1);

	for (i = 0; i < BAC_ENTRIES; i++) {
		bac[i] = malloc(sizeof(struct ba_cache));
		if (bac[i] == NULL) {
			sys_bac_free();
			return (-1);
		}
		bac[i]->timestamp = 0;
		memset(bac[i]->username, 0, sizeof(bac[i]->username));
		memset(bac[i]->password, 0, sizeof(bac[i]->password));
	}

	return (0);
}

/*
 * sys_bac_free()
 *	free basic authentication cache memory
 */
void
sys_bac_free(void)
{
	int 	i;

	for (i = 0; i < BAC_ENTRIES; i++) {
		if (bac[i] != NULL)
			free(bac[i]);
	}

	if (bac != NULL)
		free(bac);
}

/*
 * sys_bac_add()
 *	add new basic authentication credentials to our cache
 */
void
sys_bac_add(const char *username, const char *password)
{
	int	i, i_oldest, already_cached;
	time_t	t_oldest;

	i = i_oldest = t_oldest = already_cached = 0;

	/* check if user is already cached */
	for (i = 0; i < BAC_ENTRIES; i++) {
		if (bac[i]->timestamp == 0)
			continue;
		if (strcmp(username, bac[i]->username) == 0) {
			/* cached entry will be overwritten */
			already_cached = 1;
			break;
		}
	}

	/* user isn't cached yet */
	if (already_cached == 0) {
		/* find empty slot */
		for (i = 0; i < BAC_ENTRIES; i++) {
			if (bac[i]->timestamp == 0)
				break;
		}

		/* if cache was full rotate by overwriting oldest entry */
		if (i == BAC_ENTRIES) {
			time(&t_oldest);
			for (i = 0; i < BAC_ENTRIES; i++) {
				if (bac[i]->timestamp < t_oldest) {
					i_oldest = i;
					t_oldest = bac[i]->timestamp;
				}
			}
			i = i_oldest;
		}
	}

	/* add or update entry */
	time(&bac[i]->timestamp);
	strlcpy(bac[i]->username, username, sizeof(bac[i]->username));
	strlcpy(bac[i]->password, password, sizeof(bac[i]->password));
}

/*
 * sys_bac_match()
 * 	check if basic authentication credentials are cached and if the
 *	provided password matches with the cached entry
 * Return:
 *	0 = credentials don't exist, 1 = credentials exist and password matches
 */
int
sys_bac_match(const char *username, const char *password)
{
	int	i;

	for (i = 0; i < BAC_ENTRIES; i++) {
		if (bac[i]->timestamp == 0)
			continue;
		if (strcmp(username, bac[i]->username) == 0 &&
		    strcmp(password, bac[i]->password) == 0) {
			/* username and password matches */
			return (1);
		}
	}

	return (0);
}

/*
 * sys_access_auth()
 *	basic user authentication
 * Return:
 *	0 = authentication failed, 1 = authentication successfull, -1 = error
 */
int
sys_access_auth(const char *clientuser, const char *clientpw)
{
	int		i, r, fd, found;
	char		ch[1], *password;
	char		serveruserpw[1024], serveruser[1024], serverpw[1024];

	i = r = found = 0;

	/* check if credentials are already cached */
	if (sys_bac_match(clientuser, clientpw))
		return (1);

	memset(serveruserpw, 0, sizeof(serveruserpw));

	/* open htpasswd */
	if ((fd = open(config.htpasswd, O_RDONLY)) == -1)
		return (-1);

	/* search user in htpasswd */
	while (read(fd, ch, 1)) {
		if (ch[0] != '\n') {
			serveruserpw[i] = ch[0];
			i++;
		} else {
			strcuts(serveruser, serveruserpw, '\0', ':',
			    sizeof(serveruser));
			strcuts(serverpw, serveruserpw, ':', '\0',
			    sizeof(serverpw));
			if (strcmp(serveruser, clientuser) == 0) {
				found = 1;
				break;
			}
			memset(serveruserpw, 0, sizeof(serveruserpw));
			i = 0;
		}
	}

	/* user not found in htpasswd */
	if (found == 0) {
		close(fd);
		return (r);
	}

	/* generate encrypted password */
	password = crypt(clientpw, serverpw);
	if (password == NULL) {
		syslog(LOG_ERR, "sys_access_auth: crypt() returned NULL");
		return (-1);
	}

	/* compare encrypted passwords */
	if (strcmp(password, serverpw) == 0) {
		/* add credentials to our cache */
		sys_bac_add(clientuser, clientpw);
		r = 1;
	}

	/* close htpasswd */
	close(fd);

	return (r);
}
#ifdef __OpenBSD__
/*
 * sys_access_bsdauth()
 *	basic authentication over the bsd authentication framework
 * Return:
 *	0 = authentication failed, 1 = authentication successfull
 */
int
sys_access_bsdauth(const char *clientuser, const char *clientpw)
{
	int	clientuserlen, clientpwlen;
	char	answer[4], msg[1024];

	/* check if credentials are already cached */
	if (sys_bac_match(clientuser, clientpw))
		return (1);

	clientuserlen = strlen(clientuser);
	clientpwlen = strlen(clientpw);
	if (clientuserlen == 0 || clientpwlen == 0)
		return (0);

	snprintf(msg, sizeof(msg), "%s %s", clientuser, clientpw);
	sys_write(fdbsdauth[0], msg, strlen(msg));
	memset(answer, 0, sizeof(answer));
	sys_read(fdbsdauth[0], answer, sizeof(answer));
	if (strcmp(answer, "ok") == 0) {
		/* add credentials to our cache */
		sys_bac_add(clientuser, clientpw);
		return (1);
	}

	return (0);
}

/*
 * sys_daemon_bsdauth()
 *	this function gets forked to a own process and handles
 *	basic authentication requests via the bsd authentication
 *	framework
 * Return:
 *	none
 */
void
sys_daemon_bsdauth(void)
{
	char	clientuser[128], clientpw[128], msg[1024];

	/* nhttpd child processes follow default signal handling */
	sys_sighandler(0);

	/* main loop */
	while (!quit) {
		if (sys_read(fdbsdauth[1], msg, sizeof(msg)) < 1)
			continue;

		strcutw(clientuser, msg, 1, sizeof(clientuser));
		strcutw(clientpw, msg, 2, sizeof(clientpw));

		if (auth_userokay(clientuser, NULL, NULL, clientpw))
			sys_write(fdbsdauth[1], "ok", 2);
		else
			sys_write(fdbsdauth[1], "nok", 3);
	}
}
#endif
/*
 * sys_read()
 *	synchronous read
 *	used for blocking descriptors
 * Return:
 *	>0 = bytes read, 0 = descriptor closed, -1 = error
 */
int
sys_read(const int sfd, char *buf, const int len)
{
	int	r;

	for (;;) {
		r = read(sfd, buf, len);

		/* handle errors */
		if (r == -1) {
			if (errno == EINTR) {
				sys_log(debug, "sys_read: EINTR");
				usleep(1);
				continue;
			}
			syslog(LOG_ERR, "sys_read: %s", strerror(errno));
			break;
		}

		/* descriptor closed by remote */
		if (r == 0) {
			sys_log(debug,
			    "sys_read: descriptor closed by remote: %d", r);
			break;
		}

		/* got data */
		if (r > 0)
			break;
	}

	return (r);
}

/*
 * sys_read_a()
 *	asynchronous read
 *	used for non-blocking sockets
 * Return:
 *	>0 = bytes read, 0 = socket closed, -1 = error
 */
int
sys_read_a(const int sfd, char *buf, const int len)
{
	int	r, got;

	got = 0;

	for (;;) {
		r = read(sfd, buf + got, len - got);

		/* handle errors */
		if (r == -1) {
			if (errno == EINTR) {
				sys_log(debug, "sys_read_a: EINTR");
				usleep(1);
				continue;
			}
			if (errno == EAGAIN) {
				sys_log(debug, "sys_read_a: EAGAIN: %d", got);
				return (got);
			}
			if (errno != ECONNRESET)
				syslog(LOG_ERR, "sys_read_a: %s",
				    strerror(errno));
			return (r);
		}

		/* socket closed by remote */
		if (r == 0) {
			sys_log(debug,
			    "sys_read_a: socket closed by remote: %d", got);
			return (got);
		}

		/* got data */
		if (r > 0)
			got += r;

		/* buffer full */
		if (got == len)
			break;
	}

	return (got);
}

/*
 * sys_read_ssl()
 *	handle SSL_read
 * Return:
 *	>0 = bytes read, 0 = socket closed, -1 = error
 */
int
sys_read_ssl(SSL *ssl, char *buf, const int len)
{
	int	r, erro, got;

	got = 0;

	for (;;) {
		r = SSL_read(ssl, buf + got, len - got);

		if (r == -1) {
			erro = SSL_get_error(ssl, r);

			if (erro == SSL_ERROR_WANT_WRITE) {
				sys_log(debug, "sys_read_ssl: WANT_WRITE: %d",
				    got);
				return (got);
			}
			if (erro == SSL_ERROR_WANT_READ) {
				sys_log(debug, "sys_read_ssl: WANT_READ: %d",
				    got);
				return (got);
			}
			syslog(LOG_ERR, "sys_read_ssl");
			return (r);
		}

		/* socket closed by remote */
		if (r == 0)
			return (got);

		/* got data */
		if (r > 0)
			got += r;

		/* buffer full */
		if (got == len)
			break;
	}

	return (got);
}

/*
 * sys_write()
 *	synchronous write
 *	used for non-blocking and blocking sockets
 * Return:
 *	>0 = bytes written, -1 = error
 */
int
sys_write(const int sfd, const char *buf, const int len)
{
	int	r, sent;

	sent = 0;

	for (;;) {
		r = write(sfd, buf + sent, len - sent);

		/* handle errors */
		if (r == -1) {
			if (errno == EINTR) {
				sys_log(debug, "sys_write: EINTR");
				usleep(1);
				continue;
			}
			if (errno == EAGAIN) {
				sys_log(debug, "sys_write: EAGAIN: %d", sent);
				usleep(1);
				continue;
			}
			syslog(LOG_ERR, "sys_write: %s", strerror(errno));
			return (r);
		}

		/* sent data */
		if (r > 0)
			sent += r;

		/* sent all */
		if (sent == len)
			break;
	}

	return (sent);
}

/*
 * sys_write_a()
 *	asynchronous write
 *	used for non-blocking sockets
 * Return:
 *	>0 = bytes written, 0 = nothing written, -1 = error
 */
int
sys_write_a(const int sfd, const char *buf, const int len)
{
	int	r, sent;

	sent = 0;

	for (;;) {
		r = write(sfd, buf + sent, len - sent);

		/* handle errors */
		if (r == -1) {
			if (errno == EINTR) {
				sys_log(debug, "sys_write_a: EINTR");
				usleep(1);
				continue;
			}
			if (errno == EAGAIN) {
				sys_log(debug, "sys_write_a: EAGAIN: %d", sent);
				return (sent > 0 ? sent : r);
			}
			if (errno != EPIPE)
				syslog(LOG_ERR, "sys_write_a: %s",
				    strerror(errno));
			return (r);
		}

		/* sent data */
		if (r > 0)
			sent += r;

		/* sent all */
		if (sent == len)
			break;
	}

	return (sent);
}

/*
 * sys_write_ssl()
 *	handle SSL_write
 * Return:
 *	>0 = bytes written, 0 = nothing written, -1 = error
 */
int
sys_write_ssl(SSL *ssl, const char *buf, const int len)
{
	int	r, erro, sent;

	sent = 0;

	for (;;) {
		r = SSL_write(ssl, buf + sent, len - sent);

		if (r == -1) {
			erro = SSL_get_error(ssl, r);

			if (erro == SSL_ERROR_WANT_WRITE) {
				sys_log(debug, "sys_write_ssl: WANT_WRITE: %d",
				    sent);
				return (sent);
			}
			if (erro == SSL_ERROR_WANT_READ) {
				sys_log(debug, "sys_write_ssl: WANT_READ: %d",
				    sent);
				return (sent);
			}
			syslog(LOG_ERR, "sys_write_ssl");
			return (r);
		}

		/* sent data */
		if (r > 0)
			sent += r;

		/* sent all */
		if (sent == len)
			break;
	}

	return (sent);
}

/*
 * sys_resetnonblock()
 *	set a socket back to blocking if it was non-blocking
 * Return:
 *	1 = set to blocking, 0 = was not non-blocking, -1 = error
 */
int
sys_resetnonblock(const int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
		return (-1);

	if (!(flags & O_NONBLOCK))
		return (0);

	flags &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return (-1);

	return (1);
}

/*
 * sys_close_except()
 *	close all file descriptors except fd and stdin, stdout, stderr
 * Return:
 *	0 = success, -1 = error
 */
int
sys_close_except(const int fd)
{
	int		i;
	struct rlimit	rlp;

	/* get maximal file limit */
	if (getrlimit(RLIMIT_NOFILE, &rlp) == -1)
		return (-1);

	/* close all fds higher than me */
	for (i = fd + 1; i < rlp.rlim_cur; i++)
		close(i);

	/* close all fds lower than me, except stdin, stdout, stderr */
	for (i = fd - 1; i > 2; i--)
		close(i);

	return (0);
}

/* sys_log()
 *	debug logging
 */
void
sys_log(const int debug, const char *string, ...)
{
	va_list ap;

	if (!debug)
		return;

	va_start(ap, string);
	vsyslog(LOG_INFO, string, ap);
	va_end(ap);
}

/*
 * sys_compar()
 *	compare function for qsort
 * Return:
 *	>-1 = success
 */
int
sys_compar(const void *p, const void *q)
{
	return (strcmp(*(char **)p, *(char **)q));
}

/*
 * sys_date()
 *	converts struct tm to a CLF conform date string
 * Return:
 *	pointer to date string = sucessfull, NULL = error
 */
char *
sys_date(struct tm *t)
{
	int		diff;
	char		*d, sign;
	static char	date[64];

	diff = t->tm_gmtoff / 3600;

	if (diff < 0) {
		diff = -diff;
		sign = '-';
	} else
		sign = '+';

	snprintf(date, sizeof(date), "[%02d/%s/%d:%02d:%02d:%02d %c%02d00]",
	    t->tm_mday, month[t->tm_mon], t->tm_year + 1900, t->tm_hour,
	    t->tm_min, t->tm_sec, sign, diff);

	d = date;

	return (d);
}

/*
 * sys_benv()
 *	build an environment string and return its address so we can pass it
 *	to an environment pointer array
 * Return:
 *	pointer to environment string = successfull, NULL = error
 */
char *
sys_benv(const char *str, ...)
{
	char	buf[1024];
	char	*p;
	va_list	ap;

	va_start(ap, str);
	vsnprintf(buf, sizeof(buf), str, ap);
	va_end(ap);

	p = strdup(buf);

	return (p);
}

/*
 * sys_sighandler()
 *	setup signal handler for parent or child process
 */
void
sys_sighandler(int parent)
{
	if (parent) {
		/* parent process uses signal handler */
		signal(SIGCHLD, sig_handler);
		signal(SIGINT, sig_handler);
		signal(SIGTERM, sig_handler);
		signal(SIGHUP, sig_handler);
		signal(SIGPIPE, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGALRM, SIG_IGN);
	} else {
		/* child process does default behaviour */
		signal(SIGCHLD, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGALRM, SIG_DFL);
	}
}
