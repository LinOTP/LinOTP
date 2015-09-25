# Require autoconf 2.52
AC_PREREQ(2.52)

# Process this file with autoconf to produce a configure script.
AC_INIT(pam_linotp,[2.2],[linotp-community@lsexperts.de])
AC_CONFIG_SRCDIR([src/pam_linotp.c])
AC_CANONICAL_TARGET([])
AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S

LT_INIT([shared])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h syslog.h fcntl.h unistd.h security/pam_ext.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset strdup strerror])

# Check for curl
AC_PATH_PROGS(CURL_CONFIG, curl-config, no)
if test "x$CURL_CONFIG" = "xno"; then
    AC_MSG_ERROR(could not locate curl libraries)
fi
CURL_LDADD=$($CURL_CONFIG --libs)
AC_SUBST(CURL_LDADD)
CURL_CFLAGS=$($CURL_CONFIG --cflags)
AC_SUBST(CURL_CFLAGS)

# Checks for libraries.
AC_CHECK_LIB(pam, pam_get_item, , AC_MSG_ERROR(could not locate pam libraries))

# Check and set OpenSSL paths
PKG_CHECK_MODULES(OPENSSL, openssl, [], [ AC_MSG_ERROR(openssl not found) ])

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT
