LIB= my
SRCS= strcutl.c strcutw.c strcuts.c strcuti.c strcutf.c flog.c flogd.c fparse.c strlower.c strb64d.c

CFLAGS+= -Wall -Werror -Wstrict-prototypes
MAN=
NOPIC= 1
NOPROFILE= 1

PIPE= -pipe

OS!= uname -s

.if ${OS} == "NetBSD"
MKLINKLIB= no
.endif

install:
	@echo -n

.include <bsd.lib.mk>
