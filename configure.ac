dnl Process this file with autoconf to produce a configure script.
AC_INIT(rblcheck, 20190999, , rblcheck, https://github.com/rfc1036/rblcheck)
AC_CONFIG_SRCDIR(rblcheck.c)
AC_CONFIG_AUX_DIR(build-aux)
AM_INIT_AUTOMAKE(foreign -Wall)

AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

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

AC_CONFIG_HEADERS(config.h)

dnl All done.
AC_CONFIG_FILES(
	Makefile
	docs/Makefile
	config/rblcheck.spec
	config/pkginfo
)
AC_OUTPUT
