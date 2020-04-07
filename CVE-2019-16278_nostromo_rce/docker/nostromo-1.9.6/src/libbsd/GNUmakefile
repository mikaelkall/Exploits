CCFLAGS = -O2 -pipe -Wall -Werror -Wstrict-prototypes -c

libbsd.a:	strlcpy.o strlcat.o
		ar -r libbsd.a strlcpy.o strlcat.o
		ranlib libbsd.a

strlcpy.o:	strlcpy.c
		cc ${CCFLAGS} strlcpy.c
strlcat.o:	strlcat.c
		cc ${CCFLAGS} strlcat.c
clean:
		rm -f libbsd.a *.o
