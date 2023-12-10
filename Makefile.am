## Process this file with automake to produce Makefile.in

noinst_HEADERS = sites.h

bin_PROGRAMS = rblcheck
rblcheck_SOURCES = rblcheck.c utils.c

if WITH_HASHED_DNSBLS
rblcheck_SOURCES += base32.c
rblcheck_CPPFLAGS = $(CRYPTO_CFLAGS)
rblcheck_LDADD = $(CRYPTO_LIBS)
endif

TESTS = tests/clearlist tests/addlisting tests/removelisting

# We don't include README.ALPHA or bootstrap here, so we don't include them
# in a "make distcheck". Since all tests are shell scripts, we're including
# the full list verbatim.
EXTRA_DIST = \
	$(TESTS)

SUBDIRS = docs .

maintainer-clean-local:
	-rm -rf build-aux/

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 configure config.h.in

ACLOCAL_AMFLAGS = -I build-aux

