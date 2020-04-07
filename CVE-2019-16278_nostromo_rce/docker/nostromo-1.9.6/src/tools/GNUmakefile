#	$nostromo: GNUmakefile,v 1.3 2016/04/12 19:02:58 hacki Exp $

CCFLAGS = -O2 -pipe -Wall -Werror -Wstrict-prototypes -c

crypt:		crypt.o
		cc -L../libbsd -o crypt crypt.o -lcrypt -lbsd
		strip crypt

crypt.o:	crypt.c
		cc ${CCFLAGS} crypt.c

clean:
		rm -f crypt *.o
