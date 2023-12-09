docdir = $(datadir)/doc/rblcheck

EXTRA_DIST = rblcheck.sgml
DISTCLEANFILES = rblcheck.ps rblcheck.rtf rblcheck.tex html/*.html
MAINTAINERCLEANFILES = Makefile.in

html/index.html: rblcheck.sgml
	srcdir=`cd $(srcdir) && pwd`; \
	db2html $$srcdir/rblcheck.sgml
	mv rblcheck html

rblcheck.ps: rblcheck.sgml
	srcdir=`cd $(srcdir) && pwd`; \
	dockbook2ps $$srcdir/rblcheck.sgml

rblcheck.rtf: rblcheck.sgml
	srcdir=`cd $(srcdir) && pwd`; \
	dockbook2rtf $$srcdir/rblcheck.sgml

rblcheck.txt: rblcheck.sgml
	srcdir=`cd $(srcdir) && pwd`; \
	docbook2txt $$srcdir/rblcheck.sgml

dist-hook: html/index.html rblcheck.ps rblcheck.rtf
	$(mkinstalldirs) $(distdir)/html
	cp $(srcdir)/html/*.html $(distdir)/html
	cp $(srcdir)/rblcheck.ps $(distdir)/rblcheck.ps
	cp $(srcdir)/rblcheck.rtf $(distdir)/rblcheck.rtf

distclean-local:
	-rmdir html

install-data-local: html/index.html rblcheck.ps rblcheck.rtf
	$(mkinstalldirs) $(DESTDIR)$(docdir)/html
	for file in $(srcdir)/html/*.html; do \
		basefile=`echo $$file | sed -e 's,^.*/,,'`; \
		$(INSTALL_DATA) $$file $(DESTDIR)$(docdir)/html/$$basefile; \
	done
	$(INSTALL_DATA) $(srcdir)/rblcheck.ps $(DESTDIR)$(docdir)/rblcheck.ps
	$(INSTALL_DATA) $(srcdir)/rblcheck.rtf $(DESTDIR)$(docdir)/rblcheck.rtf

