#	$nostromo: Makefile,v 1.3 2016/04/12 18:52:41 hacki Exp $

SUBDIR+= src

afterinstall:
	install -d -o root -g daemon -m 755 /var/nostromo/conf
	install -d -o root -g daemon -m 755 /var/nostromo/htdocs
	install -d -o root -g daemon -m 755 /var/nostromo/htdocs/cgi-bin
	install -d -o root -g daemon -m 755 /var/nostromo/icons
	install -d -o root -g daemon -m 755 /var/nostromo/logs
	install -c -o root -g bin -m 555 htdocs/cgi-bin/printenv \
		/var/nostromo/htdocs/cgi-bin/printenv
	install -c -o root -g bin -m 644 conf/mimes \
		/var/nostromo/conf/mimes
	install -c -o root -g bin -m 644 conf/nhttpd.conf-dist \
		/var/nostromo/conf/nhttpd.conf-dist
	install -c -o root -g bin -m 644 htdocs/index.html \
		/var/nostromo/htdocs/index.html
	install -c -o root -g bin -m 644 htdocs/nostromo.gif \
		/var/nostromo/htdocs/nostromo.gif
	install -c -o root -g bin -m 644 icons/dir.gif \
		/var/nostromo/icons/dir.gif
	install -c -o root -g bin -m 644 icons/file.gif \
		/var/nostromo/icons/file.gif

.include <bsd.subdir.mk>
