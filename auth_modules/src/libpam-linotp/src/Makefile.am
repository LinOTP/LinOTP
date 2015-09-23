# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in

AM_CFLAGS = -Wall -fPIC
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

