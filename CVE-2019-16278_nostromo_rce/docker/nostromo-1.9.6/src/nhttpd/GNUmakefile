#	$nostromo: GNUmakefile,v 1.6 2016/04/12 19:02:06 hacki Exp $

CCFLAGS = -O2 -pipe -Wall -Wstrict-prototypes -c

nhttpd:	main.o http.o sys.o
	cc -L../libmy -L../libbsd -o nhttpd main.o http.o sys.o -lmy -lbsd -lssl -lcrypt
	strip nhttpd
	nroff -Tascii -c -mandoc nhttpd.8 > nhttpd.cat8

main.o:	main.c
	cc ${CCFLAGS} main.c

http.o:	http.c
	cc ${CCFLAGS} http.c

sys.o:	sys.c
	cc ${CCFLAGS} sys.c

clean:
	rm -f nhttpd nhttpd.cat8 *.o
