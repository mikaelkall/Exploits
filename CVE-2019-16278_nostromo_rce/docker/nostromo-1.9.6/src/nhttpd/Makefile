#	$nostromo: Makefile,v 1.5 2016/04/12 19:02:06 hacki Exp $

PROG= nhttpd
SRCS= main.c http.c sys.c

CFLAGS+= -Wall -Wstrict-prototypes
LDADD+=	-L../libmy -lmy

PIPE= -pipe

MAN= nhttpd.8

BINOWN=	root
BINMOD=	0555
BINDIR=	/usr/local/sbin

OS!= uname -s

LDADD+= -lssl -lcrypto
.if ${OS} == "FreeBSD"
LDADD+= -lcrypt
.endif
.if ${OS} == "NetBSD"
LDADD+= -lcrypt
.endif

.include <bsd.prog.mk>
