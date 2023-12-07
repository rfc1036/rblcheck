## Process this file with automake to produce Makefile.in

auxdir = @ac_aux_dir@
AUX_DIST = $(auxdir)/install-sh $(auxdir)/missing $(auxdir)/mkinstalldirs

noinst_HEADERS = sites.h

bin_PROGRAMS = rblcheck
rblcheck_SOURCES = rblcheck.c

XFAIL_TESTS =
TESTS = tests/clearlist tests/addlisting tests/removelisting $(XFAIL_TESTS)

# We don't include README.ALPHA or bootstrap here, so we don't include them
# in a "make distcheck". Since all tests are shell scripts, we're including
# the full list verbatim.
EXTRA_DIST = \
	config/install-sh		\
	config/missing			\
	config/mkinstalldirs		\
	config/rblcheck.spec		\
	config/rblcheck.spec.in		\
	$(TESTS)

SUBDIRS = docs .

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 configure config.h.in stamp-h.in \
	$(AUX_DIST)

DISTCLEANFILES = config/rblcheck.spec

ACLOCAL = aclocal -I $(auxdir)

