CCFLAGS = -O2 -Wall -Werror -Wstrict-prototypes -c

libmy.a:	strcutl.o strcutw.o strcuts.o strcuti.o strcutf.o flog.o flogd.o fparse.o strlower.o strb64d.o
		ar -r libmy.a strcutl.o strcutw.o strcuts.o strcuti.o strcutf.o flog.o flogd.o fparse.o strlower.o strb64d.o
		ranlib libmy.a

strcutl.o:	strcutl.c
		cc ${CCFLAGS} strcutl.c
strcutw.o:	strcutw.c
		cc ${CCFLAGS} strcutw.c
strcuts.o:	strcuts.c
		cc ${CCFLAGS} strcuts.c
strcuti.o:	strcuti.c
		cc ${CCFLAGS} strcuti.c
strcutf.o:	strcutf.c
		cc ${CCFLAGS} strcutf.c
strlower.o:	strlower.c
		cc ${CCFLAGS} strlower.c
strb64d.o:	strb64d.c
		cc ${CCFLAGS} strb64d.c

flog.o:		flog.c
		cc ${CCFLAGS} flog.c
flogd.o:	flogd.c
		cc ${CCFLAGS} flogd.c
fparse.o:	fparse.c
		cc ${CCFLAGS} fparse.c

clean:
		rm -f libmy.a *.o
