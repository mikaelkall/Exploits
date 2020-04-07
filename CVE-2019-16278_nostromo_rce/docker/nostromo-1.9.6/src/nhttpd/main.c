/*	$nostromo: main.c,v 1.219 2016/04/12 19:02:06 hacki Exp $ */

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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <pwd.h>
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

/* count in additional fds like the listener sockets */
#define CON_MAX		CON + 16

/*
 * global vars local
 */
static int		ppid;
static const char	*configfile = "/var/nostromo/conf/nhttpd.conf";

/*
 * global vars extern
 */
volatile sig_atomic_t	quit = 0;
int			debug = 0;
int			mimes_size;
#ifdef __OpenBSD__
int			fdbsdauth[2];
#endif
char			*mimes;
char			logn[1024];
struct ba_cache		**bac;

const char *month[12] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
	"Nov", "Dec"
};

const char *day[7] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

const char *http_s_200		= "200 OK";
const char *http_s_206		= "206 Partial Content";
const char *http_s_301		= "301 Moved Permanently";
const char *http_s_302		= "302 Found";
const char *http_s_304		= "304 Not Modified";
const char *http_s_400		= "400 Bad Request";
const char *http_s_401		= "401 Unauthorized";
const char *http_s_403		= "403 Forbidden";
const char *http_s_404		= "404 Not Found";
const char *http_s_413		= "413 Request Entity Too Large";
const char *http_s_500		= "500 Internal Server Error";
const char *http_s_501		= "501 Not Implemented";
const char *http_s_503		= "503 Service Unavailable";
const char *http_fn_dat		= "Date:";
const char *http_fn_srv		= "Server:";
const char *http_fn_lmd		= "Last-Modified:";
const char *http_fn_clt		= "Content-Length:";
const char *http_fn_ims		= "If-Modified-Since:";
const char *http_fn_ref		= "Referer:";
const char *http_fn_agt		= "User-Agent:";
const char *http_fn_con		= "Connection:";
const char *http_fn_alv		= "Keep-Alive:";
const char *http_fn_cok		= "Cookie:";
const char *http_fn_teg		= "Transfer-Encoding:";
const char *http_fn_cte		= "Content-Type:";
const char *http_fn_loc		= "Location:";
const char *http_fn_hos		= "Host:";
const char *http_fn_aut		= "Authorization:";
const char *http_fn_auw		= "WWW-Authenticate:";
const char *http_fn_ran		= "Range:";
const char *http_fn_rac		= "Content-Range:";
const char *http_fn_aen		= "Accept-Encoding:";
const char *http_fv_srv		= "nostromo 1.9.6";
const char *http_fv_pr0	=	 "HTTP/1.0";
const char *http_fv_pr1	=	 "HTTP/1.1";
const char *http_fv_cgi		= "CGI/1.1";
const char *http_fv_teg		= "chunked";
const char *http_fv_lch		= "0\r\n\r\n";
const char *http_fv_con_alv	= "Keep-Alive";
const char *http_fv_con_cls	= "close";

char	http_fv_alv[128];
char	http_fv_cte[128];
char	http_url[128];
char	http_urls[128];
char	http_sig[128];
char	http_path[128];

struct cfg		config;
struct connection	c[CON_MAX];
struct listener		l[LST + 1];

/*
 * usage()
 *	print usage message
 * Return:
 *	none
 */
void
usage(int mode)
{
	extern char	*__progname;

	if (mode != 2) {
		fprintf(stderr, "usage: %s ", __progname);
		fprintf(stderr, "[-dhrv46] [-c configfile]\n");
	}

	if (mode == 1) {
		fprintf(stderr, "\noptions:\n");
		fprintf(stderr, "  -d\t\t: Debug mode.\n");
		fprintf(stderr, "  -h\t\t: This help.\n");
		fprintf(stderr,
		    "  -r\t\t: nhttpd will chroot to serverroot.\n");
		fprintf(stderr, "  -v\t\t: Shows version.\n");
		fprintf(stderr, "  -4\t\t: Enable IPv4 and IPv6.\n");
		fprintf(stderr, "  -6\t\t: Enable IPv6 only.\n");
		fprintf(stderr,
		    "  -c configfile\t: Use an alternate configfile.\n");
	}

	if (mode == 2)
		fprintf(stderr, "%s\n", http_fv_srv);

	exit(1);
}

/*
 * sig_handler()
 *	signal handler
 * Return:
 *	none
 */
void
sig_handler(const int sig)
{
	switch (sig) {
	case SIGCHLD: {
		int	status;
		int	save_errno = errno;

		while (waitpid(-1, &status, WNOHANG) > 0);

		errno = save_errno;

		break;
	}
	case SIGINT:
	case SIGTERM:
		quit = 1;
		break;
	case SIGHUP:
		load_config(1);
		break;
	default:
		syslog(LOG_INFO, "unhandled signal %i, ignored", sig);
		break;
	}
}

/*
 * send_full()
 *	send a fully generated header/body block
 * Return:
 *	none
 */
void
send_full(const int sfd, const int hr)
{
	int	s, len;
	char	*offset;

	s = 0;

	len = strlen(c[sfd].pfdh[hr]) - c[sfd].wsnd;

	if (len > 0) {
		offset = c[sfd].pfdh[hr] + c[sfd].wsnd;

		if (c[sfd].x_ssl)
			s = sys_write_ssl(c[sfd].ssl, offset, len);
		else
			s = sys_write_a(sfd, offset, len);
		if (s != -1)
			c[sfd].wsnd += s;
	}

	if (len == 0 || s < 0) {
		c[sfd].pfdo--;
		c[sfd].wred = 0;
 		c[sfd].wsnd = 0;
		c[sfd].pfdn[hr] = 0;
		c[sfd].x_chk[hr] = 0;
		c[sfd].x_ful[hr] = 0;
		free(c[sfd].pfdh[hr]);
	}
}

/*
 * send_chunk()
 *	send a file in chunks
 * Return:
 *	none
 */
void
send_chunk(const int sfd, const int hr)
{
	int	k, h, s, len;
	char	*offset;

	k = h = s = 0;

	len = c[sfd].wred - c[sfd].wsnd;

	/* read block from file */
	if (len == 0) {
		if (c[sfd].pfds[hr] == 0)
			h = strlen(c[sfd].pfdh[hr]);

		k = http_chunk_ovr(BS);

		c[sfd].wred = sys_read(c[sfd].pfdn[hr], c[sfd].wbuf,
		    (BS - h) - k);

		/* chunk block */
		if (c[sfd].wred > 0) {
			offset = http_chunk(c[sfd].wbuf, c[sfd].wred);
			c[sfd].wred += http_chunk_ovr(c[sfd].wred);

			if (c[sfd].pfds[hr] == 0) {
				/* attach http header */
				h = strlcpy(c[sfd].wbuf, c[sfd].pfdh[hr], BS);
				c[sfd].pfds[hr] = 1;
			}

			memcpy(c[sfd].wbuf + h, offset, c[sfd].wred);
			free(offset);
			c[sfd].wred += h;
		}

		c[sfd].wsnd = 0;
		len = c[sfd].wred;
	}

	offset = c[sfd].wbuf + c[sfd].wsnd;

	/* send a chunk */
	if (c[sfd].wred > 0) {
		if (c[sfd].x_ssl)
			s = sys_write_ssl(c[sfd].ssl, offset, len);
		else
			s = sys_write_a(sfd, offset, len);
		if (s != 1)
			c[sfd].wsnd += s;
	}

	/* send last chunk, cleanup */
	if (c[sfd].wred < 1 || s < 0) {
		if (c[sfd].x_ssl)
			s = sys_write_ssl(c[sfd].ssl, http_fv_lch,
			    strlen(http_fv_lch));
		else
			s = sys_write_a(sfd, http_fv_lch,
			    strlen(http_fv_lch));

		close(c[sfd].pfdn[hr]);
		c[sfd].pfdo--;
		c[sfd].wred = 0;
	 	c[sfd].wsnd = 0;
		c[sfd].pfdn[hr] = 0;
		c[sfd].pfds[hr] = 0;
		c[sfd].x_chk[hr] = 0;
		free(c[sfd].pfdh[hr]);
	}
}

/*
 * send_file()
 *	send a file in blocks, the size is delivered in the header
 * Return:
 *	none
 */
void
send_file(const int sfd, const int hr)
{
	int	h, s, len;
	char	*offset;

	h = s = 0;

	len = c[sfd].wred - c[sfd].wsnd;

	/* read block from file */
	if (len == 0) {
		if (c[sfd].pfds[hr] == 0) {
			/* attach http header */
			h = strlcpy(c[sfd].wbuf, c[sfd].pfdh[hr], BS);
			c[sfd].wred = sys_read(c[sfd].pfdn[hr],
			    c[sfd].wbuf + h, BS - h);
			c[sfd].wred += h;
		} else
			c[sfd].wred = sys_read(c[sfd].pfdn[hr],
			    c[sfd].wbuf, BS);

		c[sfd].wsnd = 0;
		len = c[sfd].wred;
	}

	offset = c[sfd].wbuf + c[sfd].wsnd;

	/* send a block */
	if (c[sfd].wred > 0) {
		if (c[sfd].x_ssl)
			s = sys_write_ssl(c[sfd].ssl, offset, len);
		else
			s = sys_write_a(sfd, offset, len);
		if (s != -1) {
			c[sfd].pfds[hr] += h ? s - h : s;
			c[sfd].wsnd += s;
		}
	}

	/* file sent, write access log, cleanup */
	if (c[sfd].wred < 1 || s < 0 || c[sfd].pfds[hr] == 0) {
		if (config.logaccess_flag)
			http_alog(sfd, hr);
		close(c[sfd].pfdn[hr]);
		c[sfd].pfdo--;
		c[sfd].wred = 0;
		c[sfd].wsnd = 0;
		c[sfd].pfdn[hr] = 0;
		c[sfd].pfds[hr] = 0;
		free(c[sfd].pfdh[hr]);
		free(c[sfd].plreq[hr]);
		free(c[sfd].plref[hr]);
		free(c[sfd].plagt[hr]);
		free(c[sfd].pllog[hr]);
	}
}

/*
 * sdlisten()
 *	checks all listener sockets for ``sd'' and ``sdtype''
 * Return:
 *	0 = no listener socket has matched, 1 = a listener socket has matched
 */
int
sdlisten(int sd, int sdtype)
{
	int i;

	for (i = 0; l[i].sd; i++) {
		if (sd == l[i].sd)
			break;
	}

	if (l[i].sd == 0)
		/* not a listener socket */
		return (0);

	if ((l[i].sdtype & sdtype) == 0) 
		/* not the listener type we want */
		return (0);

	return (1);
}

/*
 * load_config()
 *	load or reload configuration file
 * Return:
 *	0 = success, -1 = failed
 */
int
load_config(int reload)
{
	int r = 0;
	char tmp[1024];

	/* optional: 'logaccess' - reloadable */
	if (fparse(config.logaccess, "logaccess", config.file,
	    sizeof(config.logaccess)) == -1) {
		config.logaccess_flag = 0;
	} else {
		config.logaccess_flag = 1;
		strlcpy(logn, config.logaccess, sizeof(logn));
	}

	/* optional: 'htaccess' - reloadable */
	if (fparse(config.htaccess, "htaccess", config.file,
	    sizeof(config.htaccess)) == -1)
		config.htaccess[0] = '\0';

	/* optional: 'custom_401' - reloadable */
	if (fparse(config.c401, "custom_401", config.file,
	    sizeof(config.user)) == -1)
		config.c401[0] = '\0';

	/* optional: 'custom_403' - reloadable */
	if (fparse(config.c403, "custom_403", config.file,
	    sizeof(config.user)) == -1)
		config.c403[0] = '\0';

	/* optional: 'custom_403' - reloadable */
	if (fparse(config.c404, "custom_404", config.file,
	    sizeof(config.user)) == -1)
		config.c404[0] = '\0';

	/* optional: 'homedirs' - reloadable */
	if (fparse(config.homedirs, "homedirs", config.file,
	    sizeof(config.homedirs)) == -1)
		config.homedirs[0] = '\0';

	/* optional: 'homedirs_public' - reloadable */	
	if (fparse(config.homedirs_public, "homedirs_public", config.file,
	    sizeof(config.homedirs_public)) == -1) {
		config.homedirs_public[0] = '\0';
	} else {
		if (config.homedirs_public[0] != '/') {
			strlcpy(tmp, config.homedirs_public, sizeof(tmp));
			snprintf(config.homedirs_public,
			    sizeof(config.homedirs_public), "/%s", tmp);
		}
	}

	/* if we are in reload mode we leave here because the following
	 * parameters are not reloadable */
	if (reload) {
		/* clear Basic Authentication Cache as well */
		sys_bac_init();
		syslog(LOG_INFO, "configuration has been reloaded");
		return (r);
	}

	/* mandatory: 'servername' */
	if (fparse(config.servername, "servername", config.file,
	    sizeof(config.servername)) == -1) {
		fprintf(stderr, "Missing <servername> in config file.\n");
		r = -1;
	} else {
		/* get servers port */
		if (strcuts(config.serverportc, config.servername, ':', '\0',
		    sizeof(config.serverportc)) == -1) {
			/* default port */
			config.serverport = PRT;
			snprintf(config.serverportc,
			    sizeof(config.serverportc), "%d", PRT);
		} else {
			/* custom port */
			config.serverport = atoi(config.serverportc);
		}

		/* remove port from servername */
		strcuts(config.servername, config.servername, '\0', ':',
		    sizeof(config.servername));
	}

	/* mandatory: 'serverlisten' */
	if (fparse(config.serverlisten, "serverlisten", config.file,
	    sizeof(config.serverlisten)) == -1) {
		fprintf(stderr, "Missing <serverlisten> in config file.\n");
		r = -1;
	}

	/* mandatory: 'serveradmin' */
	if (fparse(config.serveradmin, "serveradmin", config.file,
	    sizeof(config.serveradmin)) == -1) {
		fprintf(stderr, "Missing <serveradmin> in config file.\n");
		r = -1;
	}

	/* mandatory: 'serverroot' */
	if (fparse(config.serverroot, "serverroot", config.file,
	    sizeof(config.serverroot)) == -1) {
		fprintf(stderr, "Missing <serverroot> in config file.\n");
		r = -1;
	}

	/* mandatory: 'servermimes' */
	if (fparse(config.servermimes, "servermimes", config.file,
	    sizeof(config.servermimes)) == -1) {
		fprintf(stderr, "Missing <servermimes> in config file.\n");
		r = -1;
	}

	/* mandatory: 'docroot' */
	if (fparse(config.docroot, "docroot", config.file,
	    sizeof(config.docroot)) == -1) {
		fprintf(stderr, "Missing <docroot> in config file.\n");
		r = -1;
	}

	/* mandatory: 'docindex' */
	if (fparse(config.docindex, "docindex", config.file,
	    sizeof(config.docindex)) == -1) {
		fprintf(stderr, "Missing <docindex> in config file.\n");
		r = -1;
	}

	/* optional: 'logpid' */
	if (fparse(config.logpid, "logpid", config.file,
	    sizeof(config.logpid)) == -1) {
		config.logpid_flag = 0;
	} else {
		config.logpid_flag = 1;
	}

	/* optional: 'user' */
	if (fparse(config.user, "user", config.file,
	    sizeof(config.user)) == -1)
		config.user[0] = '\0';

	/* optional: 'htpasswd' */
	if (fparse(config.htpasswd, "htpasswd", config.file,
	    sizeof(config.htpasswd)) == -1)
		config.htpasswd[0] = '\0';
#ifdef __OpenBSD__
	else {
		if (strcmp(config.htpasswd, "+bsdauth") == 0) {
			config.bsdauth = 1;
		} else if (strcmp(config.htpasswd, "+bsdauthnossl") == 0) {
			config.bsdauth = 2;
		} else {
			config.bsdauth = 0;
		}
	}
#endif
	/* optional: 'sslport' */
	if (fparse(config.sslportc, "sslport", config.file,
	    sizeof(config.sslportc)) == -1) {
		config.ssl = 0;
	} else {
		config.ssl = 1;
		config.sslport = atoi(config.sslportc);

		if (fparse(config.sslcert, "sslcert", config.file,
		    sizeof(config.sslcert))  == -1) {
			fprintf(stderr,
			    "Missing <sslcert> in config file.\n");
			r = -1;
		}

		if (fparse(config.sslcertkey, "sslcertkey", config.file,
		    sizeof(config.sslcertkey)) == -1) {
			fprintf(stderr,
			    "Missing <sslcertkey> in config file.\n");
			r = -1;
		}
	}

	return (r);
}

/*
 * main()
 *	nostromo webserver
 * Return:
 *	0 = terminated successfull, 1 = terminated with error
 */
int
main(int argc, char *argv[])
{
	int			sdmax, sdnew, sdnow, sdlim;
	int			i, j, k, r, s, ch, rd, rt, wr, post, size;
	int			fd, erro, opt_c, opt_r, opt_4, opt_6;
#ifdef __OpenBSD__
	int			pid;
#endif
	char			in[HDN * HDS + 1], tmp[HDS + 1];
	char			header[HDN][HDS + 1];
	char			*b, *h, *offset, *body = NULL;
	extern char		**environ;
	struct passwd		*pwd = NULL;
#ifdef __OpenBSD__
	struct group		*grp = NULL;
#endif
	struct stat		st;
	struct hostent		*host;
	struct sockaddr_in	sa, ca;
	struct sockaddr_in6	sa6, ca6;
	struct in6_addr		in6addr_any = IN6ADDR_ANY_INIT;
	struct in_addr		ina;
	struct in6_addr		ina6;
	struct timeval		tv;
	struct rlimit		rlp;
	socklen_t		ssize;
	fd_set			*master_r, *master_w, *set_r, *set_w;
	time_t			tnow;
	SSL_CTX			*ssl_ctx = NULL;
	FILE			*file;

	i = r = s = rd = sdmax = sdnow = 0;

	/*
	 * command line arguments
	 */
	opt_4 = 1;
	opt_6 = opt_c = opt_r = 0;
	while ((ch = getopt(argc, argv, "dhrv46c:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'h':
			usage(1);
			break;
		case 'r':
			opt_r = 1;
			break;
		case 'v':
			usage(2);
			break;
		case '4':
			opt_6 = 1;
			break;
		case '6':
			opt_4 = 0;
			opt_6 = 1;
			break;
		case 'c':
			strlcpy(config.file, optarg, sizeof(config.file));
			opt_c = 1;
			break;
		default:
			usage(0);
			/* NOTREACHED */
		}
	}

	/*
	 * process configuration file.
	 */

	/* if no custom configuration file is given take the default */
	if (!opt_c)
		strlcpy(config.file, configfile, sizeof(config.file));

	/* check if configuration file exists */
	fd = open(config.file, O_RDONLY);
	if (fd == -1)
		err(1, "%s", config.file);
	else
		close(fd);

	/* parse and load configuration file */
	if (load_config(0) == -1)
		exit(1);

	/*
	 * initialize memory for basic authentication cache
	 */
	r = sys_bac_init();
	if (r == -1)
		errx(1, "couldn't setup basic authentication cache");

	/*
	 * change to serverroot directory
	 */
	if (chdir(config.serverroot) == -1)
		err(1, "chdir");

	/*
	 * get UID and GID
	 */
	if (config.user[0] != '\0') {
		if ((pwd = getpwnam(config.user)) == NULL)
			errx(1, "%s: no such user.", config.user);
	}

	/*
	 * map mime types file
	 */
	stat(config.servermimes, &st);
	mimes_size = st.st_size;
	if ((fd = open(config.servermimes, O_RDONLY, 0)) == -1)
		err(1, "%s", config.servermimes);
	else {
		if ((mimes = mmap(NULL, mimes_size, PROT_READ,
		    MAP_FILE|MAP_SHARED, fd, 0)) == MAP_FAILED)
			err(1, "mmap");
		close(fd);
	}

	/*
	 * assemble some strings
	 */

	/* servers full url */
	if (config.serverport == PRT)
		snprintf(http_url, sizeof(http_url), "%s", config.servername);
	else
		snprintf(http_url, sizeof(http_url), "%s:%d",
		    config.servername, config.serverport);
	if (config.ssl && config.sslport == PRTS)
		snprintf(http_urls, sizeof(http_url), "%s", config.servername);
	if (config.ssl && config.sslport != PRTS)
		snprintf(http_urls, sizeof(http_url), "%s:%d",
		    config.servername, config.sslport);
	/* servers connection timeout */
	snprintf(http_fv_alv, sizeof(http_fv_alv), "timeout=%d, max=%d", TON,
	    TON);
	/* servers default content type */
	sys_mime(http_fv_cte, sizeof(http_fv_cte), mimes, mimes_size, "html");

	/*
	 * clear all environment variables and save PATH
	 */
	strlcpy(http_path, getenv("PATH"), sizeof(http_path));
	*environ = NULL;

	/*
	 * get servers IP adress(es)
	 */
	if (opt_4) {
		if ((host = gethostbyname2(config.servername, AF_INET)) ==
		    NULL) {
			herror(config.servername);
			exit(1);
		}
		inet_ntop(AF_INET, host->h_addr, config.serverip4,
		    sizeof(config.serverip4));
	}
	if (opt_6) {
		if ((host = gethostbyname2(config.servername, AF_INET6)) ==
		    NULL) {
			herror(config.servername);
			exit(1);
		}
		inet_ntop(AF_INET6, host->h_addr, config.serverip6,
		    sizeof(config.serverip6));
	}

	/*
	 * SSL
	 */
	if (config.ssl) {
		/* initialize SSL library */
		SSL_load_error_strings();
		SSL_library_init();

		/* create SSL context */
		if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
			err(1, "SSL_CTX_new");

		/* load certificate and private key and check them */
		if (SSL_CTX_use_certificate_file(ssl_ctx, config.sslcert,
		    SSL_FILETYPE_PEM) != 1)
			err(1, "SSL_CTX_use_certificate_file");
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config.sslcertkey,
		    SSL_FILETYPE_PEM) != 1)
			err(1, "SSL_CTX_use_PrivateKey_file");
		if (SSL_CTX_check_private_key(ssl_ctx) != 1)
			err(1, "SSL_CTX_check_private_key");
	}

	/*
	 * calculate maximal concurrent connections
	 */
	sdlim = CON_MAX;

	rlp.rlim_cur = sdlim;
	rlp.rlim_max = sdlim;
	r = setrlimit(RLIMIT_NOFILE, &rlp);
	if (r == -1)
		err(1, "setrlimit");

	/*
	 * initialize select sets
	 */
	master_r = (fd_set *)calloc(howmany(sdlim + 1, NFDBITS),
	    sizeof(fd_mask));
	if (master_r == NULL)
		err(1, "calloc");
	master_w = (fd_set *)calloc(howmany(sdlim + 1, NFDBITS),
	    sizeof(fd_mask));
	if (master_w == NULL)
		err(1, "calloc");
	set_r = (fd_set *)calloc(howmany(sdlim + 1, NFDBITS),
	    sizeof(fd_mask));
	if (set_r == NULL)
		err(1, "calloc");
	set_w = (fd_set *)calloc(howmany(sdlim + 1, NFDBITS),
	    sizeof(fd_mask));
	if (set_w == NULL)
		err(1, "calloc");

	i = 0;
	/*
	 * IPv4
	 */
	if (opt_4) {
		if ((b = strdup(config.serverlisten)) == NULL)
			err(1, "strdup");

		r = 0;
		for (h = strtok(b, " "); h; h = strtok(NULL, " ")) {
			/* check for free space in listener socket array */
			if (i == LST)
				break;

			/* if no IPv4 address nor wildcard, skip it */
			if (strchr(h, '.') == NULL && *h != '*')
				continue;

			/* socket */
			if ((l[i].sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
				err(1, "socket");

			/* set socket non-blocking */
			if (fcntl(l[i].sd, F_SETFL,
			    fcntl(l[i].sd, F_GETFL) | O_NONBLOCK) == -1)
				err(1, "fcntl");
			/* allow rapid reuse of the address */
			size = 1;
			if (setsockopt(l[i].sd, SOL_SOCKET, SO_REUSEADDR,
			    (char *)&size, sizeof(size)) == -1)
				err(1, "setsockopt");

			/* bind */
			sa.sin_family = AF_INET;
			sa.sin_port = htons(config.serverport);
			if (*h == '*') {
				sa.sin_addr.s_addr = INADDR_ANY;
				r = 1;
			} else {
				bzero(&ina, sizeof(struct in_addr));
				if (inet_pton(AF_INET, h, &ina) != 1)
					err(1, "inet_pton");
				sa.sin_addr.s_addr = ina.s_addr;
			}
			memset(&sa.sin_zero, 0, sizeof(sa.sin_zero));
			if (bind(l[i].sd, (struct sockaddr *)&sa,
			    sizeof(sa)) == -1)
				err(1, "bind");

			/* listen */
			if (listen(l[i].sd, CON) == -1)
				err(1, "listen");

			/* add listener socket to master set */
			FD_SET(l[i].sd, master_r);

			/* keep track of the biggest socket descriptor */
			sdmax = l[i].sd;

			l[i].sdtype = IPALL | IP4;
			i++;

			/* we use INADDR_ANY, done */
			if (r)
				break;
		}

		free(b);
	}

	/*
	 * IPv4 SSL
	 */
	if (opt_4 && config.ssl) {
		if ((b = strdup(config.serverlisten)) == NULL)
			err(1, "strdup");

		r = 0;
		for (h = strtok(b, " "); h; h = strtok(NULL, " ")) {
			/* check for free space in listener socket array */
			if (i == LST)
				break;

			/* if no IPv4 address nor wildcard, skip it */
			if (strchr(h, '.') == NULL && *h != '*')
				continue;

			/* socket */
			if ((l[i].sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
				err(1, "socket");

			/* set socket non-blocking */
			if (fcntl(l[i].sd, F_SETFL,
			    fcntl(l[i].sd, F_GETFL) | O_NONBLOCK) == -1)
				err(1, "fcntl");
			/* allow rapid reuse of the address */
			size = 1;
			if (setsockopt(l[i].sd, SOL_SOCKET, SO_REUSEADDR,
			    (char *)&size, sizeof(size)) == -1)
				err(1, "setsockopt");

			/* bind */
			sa.sin_family = AF_INET;
			sa.sin_port = htons(config.sslport);
			if (*h == '*') {
				sa.sin_addr.s_addr = INADDR_ANY;
				r = 1;
			} else {
				bzero(&ina, sizeof(struct in_addr));
				if (inet_pton(AF_INET, h, &ina) != 1)
					err(1, "inet_pton");
				sa.sin_addr.s_addr = ina.s_addr;
			}
			memset(sa.sin_zero, 0, sizeof(sa.sin_zero));
			if (bind(l[i].sd, (struct sockaddr *)&sa,
			    sizeof(sa)) == -1)
				err(1, "bind");

			/* listen */
			if (listen(l[i].sd, CON) == -1)
				err(1, "listen");

			/* add ssl listener socket to master set */
			FD_SET(l[i].sd, master_r);

			/* keep track of the biggest socket descriptor */
			sdmax = l[i].sd;

			l[i].sdtype = IPALL | IP4SSL;
			i++;

			/* we use INADDR_ANY, done */
			if (r)
				break;
		}

		free(b);
	}

	/*
	 * IPv6
	 */
	if (opt_6) {
		if ((b = strdup(config.serverlisten)) == NULL)
			err(1, "strdup");

		r = 0;
		for (h = strtok(b, " "); h; h = strtok(NULL, " ")) {
			/* check for free space in listener socket array */
			if (i == LST)
				break;

			/* if no IPv4 address nor wildcard, skip it */
			if (strchr(h, ':') == NULL && *h != '*')
				continue;

			/* socket */
			if ((l[i].sd = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
				err(1, "socket");

			/* set socket non-blocking */
			if (fcntl(l[i].sd, F_SETFL,
			    fcntl(l[i].sd, F_GETFL) | O_NONBLOCK) == -1)
				err(1, "fcntl");
			/* allow rapid reuse of the address */
			size = 1;
			if (setsockopt(l[i].sd, SOL_SOCKET, SO_REUSEADDR,
			    (char *)&size, sizeof(size)) == -1)
				err(1, "setsockopt");

			/* bind */
			#ifndef __linux__
			sa6.sin6_len = sizeof(sa6);
			#endif
			sa6.sin6_family = AF_INET6;
			sa6.sin6_port = htons(config.serverport);
			sa6.sin6_flowinfo = 0;
			sa6.sin6_scope_id = 0;
			if (*h == '*') {
				memcpy(sa6.sin6_addr.s6_addr, &in6addr_any,
				    sizeof(in6addr_any));
				r = 1;
			} else {
				//bzero(&ina6, sizeof(struct in6_addr));
				if (inet_pton(AF_INET6, h, &ina6.s6_addr) != 1)
					err(1, "inet_pton");
				memcpy(sa6.sin6_addr.s6_addr, &ina6.s6_addr,
				    sizeof(struct in6_addr));
			}
			if (bind(l[i].sd, (struct sockaddr *)&sa6,
			    sizeof(sa6)) == -1)
				err(1, "bind");

			/* listen */
			if (listen(l[i].sd, CON) == -1)
				err(1, "listen");

			/* add ipv6 listener to master set */
			FD_SET(l[i].sd, master_r);

			/* keep track of the biggest socket descriptor */
			sdmax = l[i].sd;

			l[i].sdtype = IPALL | IP6;
			i++;

			/* we use INADDR_ANY, done */
			if (r)
				break;
		}

		free(b);
	}

	/*
	 * IPv6 SSL
	 */
	if (opt_6 && config.ssl) {
		if ((b = strdup(config.serverlisten)) == NULL)
			err(1, "strdup");

		r = 0;
		for (h = strtok(b, " "); h; h = strtok(NULL, " ")) {
			/* check for free space in listener socket array */
			if (i == LST)
				break;

			/* if no IPv4 address nor wildcard, skip it */
			if (strchr(h, ':') == NULL && *h != '*')
				continue;

			/* socket */
			if ((l[i].sd = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
				err(1, "socket");

			/* set socket non-blocking */
			if (fcntl(l[i].sd, F_SETFL,
			    fcntl(l[i].sd, F_GETFL) | O_NONBLOCK) == -1)
				err(1, "fcntl");
			/* allow rapid reuse of the address */
			size = 1;
			if (setsockopt(l[i].sd, SOL_SOCKET, SO_REUSEADDR,
			    (char *)&size, sizeof(size)) == -1)
				err(1, "setsockopt");

			/* bind */
			#ifndef __linux__
			sa6.sin6_len = sizeof(sa6);
			#endif
			sa6.sin6_family = AF_INET6;
			sa6.sin6_port = htons(config.sslport);
			sa6.sin6_flowinfo = 0;
			sa6.sin6_scope_id = 0;
			if (*h == '*') {
				memcpy(sa6.sin6_addr.s6_addr, &in6addr_any,
				    sizeof(in6addr_any));
			} else {
				//bzero(&ina6, sizeof(struct in6_addr));
				if (inet_pton(AF_INET6, h, &ina6.s6_addr) != 1)
					err(1, "inet_pton");
				memcpy(sa6.sin6_addr.s6_addr, &ina6.s6_addr,
				    sizeof(struct in6_addr));
			}
			if (bind(l[i].sd, (struct sockaddr *)&sa6,
			    sizeof(sa6)) == -1)
				err(1, "bind");

			/* listen */
			if (listen(l[i].sd, CON) == -1)
				err(1, "listen");

			/* add ipv6 listener to master set */
			FD_SET(l[i].sd, master_r);

			/* keep track of the biggest socket descriptor */
			sdmax = l[i].sd;

			l[i].sdtype = IPALL | IP6SSL;
			i++;

			/* we use INADDR_ANY, done */
			if (r)
				break;
		}

		free(b);
	}

	/*
	 * check if we could bind at least to one interface
	 */
	if (i == 0) {
		fprintf(stderr, "Couldn't bind to any interfaces, aborting.\n");
		exit(1);
	}

	/*
	 * setup own signal handler for the parent process
	 */
	sys_sighandler(1);

	/*
	 * open syslog
	 */
	openlog("nhttpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * daemonize
	 */
	ppid = fork();
	if (ppid == -1)
		err(1, "fork");
	if (ppid > 0)
		exit(0);
	setsid();
	ppid = fork();
	if (ppid == -1)
		err(1, "fork");
	if (ppid > 0)
		exit(0);
	ppid = getpid();
	umask(022);
	close(0);
	close(1);
	close(2);
	if (open("/dev/null", O_RDWR) == -1) {
		syslog(LOG_ERR, "open: %s", strerror(errno));
		exit(1);
	}
	if (dup(0) == -1) {
		syslog(LOG_ERR, "dup: %s", strerror(errno));
		exit(1);
	}
	if (dup(0) == -1) {
		syslog(LOG_ERR, "dup: %s", strerror(errno));
		exit(1);
	}
#ifdef __OpenBSD__
	/*
	 * basic authentication via bsd authentication framework
	 */
	if (config.bsdauth) {
		pipe(fdbsdauth);
		pid = fork();
		if (pid == -1)
			err(1, "fork");
		/* bsd auth daemon */
		if (pid == 0) {
			/* child closes all fds except pipe to parent */
			sys_close_except(fdbsdauth[1]);
			grp = getgrnam("auth");
			setgid(grp->gr_gid);
			if (config.user[0] != '\0')
				setuid(pwd->pw_uid);
			sys_daemon_bsdauth();
			exit(0);
		}
		close(fdbsdauth[1]);
	}
#endif
	/*
	 * chroot to serverroot directory
	 */
	if (opt_r) {
		if (chroot(config.serverroot) == -1) {
			syslog(LOG_ERR, "chroot: %s", strerror(errno));
			exit(1);
		}
		strcuti(config.file, config.file, strlen(config.serverroot),
		    strlen(config.file), sizeof(config.file));
	}

	/*
	 * set UID and GID
	 */
	if (config.user[0] != '\0') {
		if (setgid(pwd->pw_gid) == -1) {
			syslog(LOG_ERR, "setgid: %s", strerror(errno));
			exit(1);
		}
		if (setuid(pwd->pw_uid) == -1) {
			syslog(LOG_ERR, "setuid: %s", strerror(errno));
			exit(1);
		}
	}
	/* don't run as root */
	if (getuid() == 0) {
		syslog(LOG_ERR,
		    "we don't run as root, choose another user");
		exit(1);
	}

	/*
	 * PID file creation
	 */
	if (config.logpid_flag) {
		if ((file = fopen(config.logpid, "w")) != NULL) {
			fclose(file);
			flog(config.logpid, "%d\n", ppid);
		} else {
			syslog(LOG_ERR, "fopen: %s: %s",
			    config.logpid, strerror(errno));
			exit(1);
		}
	}

	/*
	 * recheck our fd limits
	 */
	r = getrlimit(RLIMIT_NOFILE, &rlp);
	if (r == -1) {
		syslog(LOG_ERR, "getrlimit: %s", strerror(errno));
		exit(1);
	}

	/*
	 * nostromo ready
	 */
	syslog(LOG_INFO, "started");
	syslog(LOG_INFO, "max. file descriptors = %d (cur) / %d (max)",
	    (int)rlp.rlim_cur, (int)rlp.rlim_max);
	if (config.ssl)
		syslog(LOG_INFO, "SSL enabled on port %d", config.sslport);
	if (opt_r)
		syslog(LOG_INFO, "chroot to %s", config.serverroot);
	if (opt_4 && opt_6)
		syslog(LOG_INFO, "IPv4 and IPv6 enabled");
	if (!opt_4 && opt_6)
		syslog(LOG_INFO, "IPv6 only enabled");
	if (debug)
		syslog(LOG_INFO, "debug mode enabled");

	/*
	 * main loop
	 */
	while (!quit) {
		/* copy master set */
		memcpy(set_r, master_r, howmany(sdlim + 1, NFDBITS));
		memcpy(set_w, master_w, howmany(sdlim + 1, NFDBITS));

		/* select is waiting for some action */
		tv.tv_sec = TON;
		tv.tv_usec = 0;
		if (select(sdmax + 1, set_r, set_w, NULL, &tv) == -1) {
			if (errno == EINTR) {
				usleep(1);
				continue;
			}
			/* EFAULT, EBADF, and EINVAL are not acceptable */
			syslog(LOG_ERR, "select: %s", strerror(errno));
			break;
		}

		/* check all existing connections */
		for (sdnow = 3; sdnow <= sdmax; sdnow++) {
			/*
			 * Unused connection
			 */
			if (c[sdnow].to == 0 && sdlisten(sdnow, IPALL) == 0)
				continue;

			/* check connection read and write state */
			rd = FD_ISSET(sdnow, set_r);
			wr = FD_ISSET(sdnow, set_w);

			/*
			 * existing connection idles, check for timeout
			 */
			if (rd == 0 && wr == 0) {
				if (sdlisten(sdnow, IPALL) == 0 &&
				    c[sdnow].pfdo == 0 &&
				    (time(&tnow) - c[sdnow].to) > TON) {
					sys_log(debug,
					"main: socket closed by us: timeout");
					goto quit;
				}
				continue;
			}

			/*
			 * new connection
			 */
			if (rd > 0 && sdlisten(sdnow, IPALL)) {
				/* accept */
				if (sdlisten(sdnow, IP6 | IP6SSL)) {
					ssize = sizeof(ca6);
					if ((sdnew = accept(sdnow,
					    (struct sockaddr *)&ca6, &ssize)) ==
					    -1)
						continue;
				} else {
					ssize = sizeof(ca);
					if ((sdnew = accept(sdnow,
					    (struct sockaddr *)&ca, &ssize)) ==
					    -1)
						continue;
				}

				/* set socket options */
				if (fcntl(sdnew, F_SETFL,
				    fcntl(sdnew, F_GETFL) | O_NONBLOCK) == -1)
					continue;
				if (SBS > 0) {
					size = SBS;
					if (setsockopt(sdnew, SOL_SOCKET,
					    SO_SNDBUF, &size, sizeof(size)) ==
					    -1)
						continue;
				}

				/* initialize connection structure */
				c[sdnew].to = time(&tnow);
				c[sdnew].rbuf = malloc((HDN * HDS) + 1);
				c[sdnew].wbuf = malloc(BS);
				c[sdnew].roff = 0;
				c[sdnew].wred = 0;
				c[sdnew].wsnd = 0;
				c[sdnew].pfdo = 0;
				c[sdnew].x_ssl = 0;
				c[sdnew].x_ip6 = 0;
				c[sdnew].x_sta = 0;

				/* SSL ready */
				if (sdlisten(sdnow, IP4SSL | IP6SSL)) {
					c[sdnew].ssl = SSL_new(ssl_ctx);
					SSL_set_fd(c[sdnew].ssl, sdnew);
					c[sdnew].x_ssl = 1;
				}

				/* save ip and port */
				if (sdlisten(sdnow, IP6 | IP6SSL)) {
					inet_ntop(AF_INET6, &ca6.sin6_addr,
					    c[sdnew].ip, sizeof(c[sdnew].ip));
					snprintf(c[sdnew].pt,
					    sizeof(c[sdnew].pt), "%d",
					    ca6.sin6_port);
					c[sdnew].x_ip6 = 1;
				} else {
					strlcpy(c[sdnew].ip,
					    inet_ntoa(ca.sin_addr),
					    sizeof(c[sdnew].ip));
					snprintf(c[sdnew].pt,
					    sizeof(c[sdnew].pt), "%d",
					    ca.sin_port);
				}

				/* check connection limit */
				if (sdnew == (sdlim - 1)) {
					h = http_head(http_s_503, "-",
					    c[sdnew].ip, 0);
					b = http_body(http_s_503, "", h, 0);
					c[sdnew].pfdo++;
					c[sdnew].pfdn[i] = 1;
					c[sdnew].pfdh[i] = strdup(b);
					c[sdnew].x_ful[i] = 1;
					c[sdnew].x_chk[i] = 0;
					c[sdnew].x_sta = 0;
					free(h);
					free(b);
					FD_SET(sdnew, master_w);
				}

				/* add new connection to read fdset */
				FD_SET(sdnew, master_r);

				/* set highest socket */
				if (sdnew > sdmax)
					sdmax = sdnew;

				continue;
			}

			/*
			 * SSL handshake
			 */
			if (c[sdnow].x_ssl == 1) {
				r = SSL_accept(c[sdnow].ssl);
				if (r == 1) {
					c[sdnow].x_ssl = 2;
					continue;
				}
				erro = SSL_get_error(c[sdnow].ssl, r);
				if (erro == SSL_ERROR_WANT_READ)
					continue;
				if (erro == SSL_ERROR_WANT_WRITE)
					continue;
				/* SSL handshake error */
				goto quit;
			}

			/*
			 * active connection wants partial file send
			 */
			if (c[sdnow].pfdo > 0) {
				for (i = 0; i < HDN; i++) {
					if (c[sdnow].pfdn[i] == 0)
						continue;

					/* send plain block */
				 	if (c[sdnow].x_chk[i] == 0 &&
					    c[sdnow].x_ful[i] == 0)
						send_file(sdnow, i);
					/* send chunked block */
					if (c[sdnow].x_chk[i] == 1 &&
					    c[sdnow].x_ful[i] == 0)
						send_chunk(sdnow, i);
					/* send full response block */
					if (c[sdnow].x_ful[i] == 1 &&
					    c[sdnow].x_chk[i] == 0)
						send_full(sdnow, i);

					break;
				}
				/* all partial files sent */
				if (c[sdnow].pfdo == 0) {
					FD_CLR(sdnow, master_w);
					if (c[sdnow].x_sta == 0)
						goto quit;
				}
				continue;
			}

			/*
			 * active connection sends request
			 */
			memset(tmp, 0, sizeof(tmp));

			/* size check for data */
 			if (c[sdnow].roff > (sizeof(in) - 1) - BS) {
				h = http_head(http_s_413, "-", c[sdnow].ip, 0);
				b = http_body(http_s_413, "", h, 0);
				c[sdnow].pfdo++;
				c[sdnow].pfdn[i] = 1;
				c[sdnow].pfdh[i] = strdup(b);
				c[sdnow].x_ful[i] = 1;
				c[sdnow].x_chk[i] = 0;
				c[sdnow].x_sta = 0;
				free(h);
				free(b);
				continue;
			}

			/* receive data */
			offset = c[sdnow].rbuf + c[sdnow].roff;

			if (c[sdnow].x_ssl)
				r = sys_read_ssl(c[sdnow].ssl, offset, BS);
			else
				r = sys_read_a(sdnow, offset, BS);
			if (r < 1)
				goto quit;

			c[sdnow].roff += r;
			offset = c[sdnow].rbuf + c[sdnow].roff;
			*offset = '\0';

			/* set timestamp for connection timeout */
			c[sdnow].to = time(&tnow);

			/* we need a full header sequence */
			size = http_header_comp(c[sdnow].rbuf, c[sdnow].roff);
			if (!size)
				continue;

			/* we got a full header sequence */
			memcpy(in, c[sdnow].rbuf, c[sdnow].roff);
			rt = c[sdnow].roff;
			c[sdnow].roff = 0;

			/* size check for header count */
			if (size > HDN) {
				h = http_head(http_s_413, "-", c[sdnow].ip, 0);
				b = http_body(http_s_413, "", h, 0);
				c[sdnow].pfdo++;
				c[sdnow].pfdn[i] = 1;
				c[sdnow].pfdh[i] = strdup(b);
				c[sdnow].x_ful[i] = 1;
				c[sdnow].x_chk[i] = 0;
				c[sdnow].x_sta = 0;
				free(h);
				free(b);
				continue;
			}

			/* post */
			if (!strncasecmp("POST ", in, 5))
				post = 1;
			else
				post = 0;

			/* separate every header */
			for (i = 0, j = 0, k = 0; i < rt; i++) {
				/* size check for header */
				if (j == sizeof(header[k]) - 1) {
					h = http_head(http_s_413, "-",
					    c[sdnow].ip, 0);
					b = http_body(http_s_413, "", h, 0);
					c[sdnow].pfdo++;
					c[sdnow].pfdn[i] = 1;
					c[sdnow].pfdh[i] = strdup(b);
					c[sdnow].x_ful[i] = 1;
					c[sdnow].x_chk[i] = 0;
					c[sdnow].x_sta = 0;
					free(h);
					free(b);
					continue;
				}
				if (in[i] == '\n' && in[i + 2] == '\n') {
					tmp[j] = in[i];
					i = i + 2;
					strlcpy(header[k], tmp,
					    sizeof(header[k]));
					k++;
					j = 0;
					memset(tmp, 0, sizeof(tmp));
				} else {
					tmp[j] = in[i];
					j++;
				}
				/* we got the post header */
				if (post == 1 && k == 1)
					break;
			}

			/* for post get initial body content */
			if (post) {
				body = in + (strlen(header[0]) + 2);
				size = rt - (strlen(header[0]) + 2);
			}

			/* and process every single header */
			for (i = 0; i < k; i++) {
				s = 0;
				r = 1;
				s = http_verify(header[i], sizeof(header[i]),
				    c[sdnow].ip, sdnow, i);
				if (s == 1)
					r = http_proc(header[i], body, i, size,
					    sdnow);
				if (r == 0)
					goto quit;
				/* on error abort processing */
				if (r == -1) {
					strcutl(tmp, header[i], 1, sizeof(tmp));
					h = http_head(http_s_500, tmp,
					    c[sdnow].ip, 0);
					b = http_body(http_s_500, "", h, 0);
					c[sdnow].pfdo++;
					c[sdnow].pfdn[i] = 1;
					c[sdnow].pfdh[i] = strdup(b);
					c[sdnow].x_ful[i] = 1;
					c[sdnow].x_chk[i] = 0;
					c[sdnow].x_sta = 0;
					free(h);
					free(b);
				}
			}

			/* connection has open files, add to write fdset */
			if (c[sdnow].pfdo > 0)
				FD_SET(sdnow, master_w);

			/* check keep-alive */
			if (r != 1) {
				quit:
				if (c[sdnow].x_ssl)
					SSL_free(c[sdnow].ssl);
				c[sdnow].to = 0;
				c[sdnow].x_ip6 = 0;
				c[sdnow].x_ssl = 0;
				free(c[sdnow].rbuf);
				free(c[sdnow].wbuf);
				close(sdnow);
				FD_CLR(sdnow, master_r);
				FD_CLR(sdnow, master_w);
			}
		}
	}

	/*
	 * nostromo shutdown
	 */
	munmap(mimes, mimes_size);
	syslog(LOG_INFO, "stopped");
	kill(0, SIGTERM);	/* terminate all childs */

	return (0);
}
