dnl Process this file with autoconf to produce a configure script.
AC_INIT(rblcheck, 20230811, , rblcheck, https://github.com/rfc1036/rblcheck)
AC_CONFIG_SRCDIR(rblcheck.c)
AC_CONFIG_AUX_DIR(build-aux)
AM_INIT_AUTOMAKE(foreign -Wall)

AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

dnl Checks for header files.
AC_CHECK_HEADERS(getopt.h)

dnl Figure out where to get res_query from. First, see if it's in the
dnl C library (Linux, and probably a few others). Then, check libbind
dnl (generally, if you've installed bind 8, you're going to want to use
dnl the new library). Finally, check for libresolv (which should exist
dnl on most systems).
AC_CHECK_FUNC([res_query], [], [
	AC_CHECK_LIB([resolv],[res_query], [], [
		AC_CHECK_LIB([resolv],[__res_query], [], [
			AC_CHECK_LIB([bind],[res_query], [],
				AC_MSG_ERROR(cannot locate res_query function))])])])

AC_CHECK_FUNCS(getaddrinfo)

AC_DEFUN([CONFIGURE_OPENSSL], [
	PKG_CHECK_MODULES(crypto, libcrypto,,
		AC_MSG_ERROR([You need the OpenSSL library.]))
	CRYPTO_CFLAGS="$crypto_CFLAGS"
	CRYPTO_LIBS="$crypto_LIBS"

	AC_CHECK_LIB(crypto, EVP_MD_CTX_new, [has_openssl_evp=1], [])
	AH_TEMPLATE([HAVE_OPENSSL_EVP], [The OpenSSL EVP API is available])
	AS_IF([test "$has_openssl_evp" = 1], [AC_DEFINE([HAVE_OPENSSL_EVP], 1)])
	AC_DEFINE([HAVE_LIBCRYPTO], 1, [libcrypto is available])
])

AC_DEFUN([CONFIGURE_NETTLE], [
	PKG_CHECK_MODULES(nettle, nettle,,
		AC_MSG_ERROR([You need the Nettle cryptographic library.]))
	CRYPTO_CFLAGS="$nettle_CFLAGS"
	CRYPTO_LIBS="$nettle_LIBS"
	AC_DEFINE([HAVE_LIBNETTLE], 1, [libnettle is available])
])

dnl Crypto library configuration.
AC_ARG_WITH([crypto-library],
	AS_HELP_STRING([--with-crypto-library=LIBRARY], [crypto library (openssl, nettle, none) [openssl]]),
	[], [with_crypto_library=openssl])

case "$with_crypto_library" in
	openssl) CONFIGURE_OPENSSL([]) ;;
	nettle)	CONFIGURE_NETTLE([]) ;;
	none)	AC_MSG_NOTICE([Support for hashed DNSBLs is disabled]) ;;
	*)	AC_MSG_ERROR([Unknown crypto library '$with_crypto_library'.]) ;;
esac

AM_CONDITIONAL(HAVE_LIBCRYPTO, test "$with_crypto_library" = "openssl")
AM_CONDITIONAL(HAVE_LIBNETTLE, test "$with_crypto_library" = "nettle")

AM_CONDITIONAL(WITH_HASHED_DNSBLS, test "$with_crypto_library" != "none")
AM_COND_IF([WITH_HASHED_DNSBLS],
	AC_DEFINE([WITH_HASHED_DNSBLS], 1, [Support for hashed DNSBLs is enabled]))

AC_CONFIG_HEADERS(config.h)

AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(CRYPTO_LIBS)

dnl All done.
AC_CONFIG_FILES(
	Makefile
	docs/Makefile
)
AC_OUTPUT
