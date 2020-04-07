#	$nostromo: Makefile,v 1.4 2016/04/12 19:02:58 hacki Exp $

PROG= crypt
SRCS= crypt.c

CFLAGS+= -Wall -Werror -Wstrict-prototypes

PIPE= -pipe

MAN=

BINOWN=	root
BINMOD=	0555
BINDIR=	/usr/local/sbin

OS!= uname -s

.if ${OS} == "FreeBSD"
LDADD+=	-lcrypt
.endif
.if ${OS} == "NetBSD"
LDADD+=	-lcrypt
.endif

.include <bsd.prog.mk>
