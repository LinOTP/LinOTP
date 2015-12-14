#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
#     E-mail: linotp@lsexperts.de
#     Contact: www.linotp.org
#     Support: www.lsexperts.de
#
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
AC_CHECK_HEADERS([curl.h string.h syslog.h fcntl.h unistd.h security/pam_ext.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset strdup strerror])

# Checks for libraries.
AC_CHECK_LIB(pam, pam_get_item, , AC_MSG_ERROR(could not locate pam libraries))
AC_CHECK_LIB(curl,curl_easy_setopt,  , AC_MSG_ERROR(could not locate curl libraries))
AC_CHECK_LIB(curl,curl_easy_escape,  , AC_MSG_ERROR(could not locate curl libraries))
AC_CHECK_LIB(curl,curl_easy_perform,  , AC_MSG_ERROR(could not locate curl libraries))
AC_CHECK_LIB(curl,curl_global_init,  , AC_MSG_ERROR(could not locate curl libraries))
AC_CHECK_LIB(curl,curl_easy_init,  , AC_MSG_ERROR(could not locate curl libraries))
AC_CHECK_LIB(curl,curl_global_cleanup,  , AC_MSG_ERROR(could not locate curl libraries))


# Check and set OpenSSL paths
PKG_CHECK_MODULES(OPENSSL, openssl, [], [ AC_MSG_ERROR(openssl not found) ])

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT

