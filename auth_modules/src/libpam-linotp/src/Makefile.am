#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

AM_CFLAGS = -Wall -fPIC -std=c99
AM_LDFLAGS = -module -avoid-version

lib_LTLIBRARIES = pam_linotp.la

CURL_LIBS = -lcurl

pam_linotp_la_SOURCES =  pam_linotp.c
pam_linotp_la_LIBADD = $(OPENSSL_LIBS) $(CURL_LIBS)


install:       
	$(mkinstalldirs) $(DESTDIR)/$(libdir)/security
	$(INSTALL) $(top_builddir)/src/.libs/pam_linotp.so $(DESTDIR)/$(libdir)/security

uninstall:       
	$(RM) $(DESTDIR)/$(libdir)/security/pam_linotp.so 
	@ rmdir $(DESTDIR)/$(libdir)/security

