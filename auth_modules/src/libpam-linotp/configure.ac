#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
#
#    This file is part of LinOTP authentication modules.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#     E-mail: linotp@keyidentity.com
#     Contact: www.linotp.org
#     Support: www.keyidentity.com
#
# Require autoconf 2.52
AC_PREREQ(2.52)

# Process this file with autoconf to produce a configure script.
AC_INIT(pam_linotp,[2.2],[linotp@keyidentity.com])
AC_CONFIG_SRCDIR([src/pam_linotp.c])
AC_CONFIG_MACRO_DIR([m4])
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
AC_CHECK_HEADERS([errno.h string.h syslog.h fcntl.h unistd.h security/pam_ext.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset strdup strerror])
AC_CHECK_FUNCS([memset_s explicit_bzero])

### AX_GCC_FUNC_ATTRIBUTE([optimize]) ###

# <Debug note="Provide more infos about local OS cappabilities...">
# This test is optional; it is used only to provide extra information about memset_s function...
AC_CHECK_DECLS([memset_s], [], [], [[
#include <errno.h>
#include <string.h>]])
# This test is optional; it is used only to provide extra information about explicit_bzero function...
AC_CHECK_DECLS([explicit_bzero], [], [], [[
#include <errno.h>
#include <string.h>]])
# </Debug>

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
