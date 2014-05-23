PYTHON=`which python`

SOURCE_DIRS	= libpam-linotp freeradius pam_py_linotp
PACK_DIRS	= libpam-linotp freeradius pam_py_linotp freeradius_perl simplesamlphp-module wordpress-php

ECHO	= echo

all:
	@$(ECHO) .......
	@$(ECHO) "make create" will create a tar.gz. of all auth modules
	@$(ECHO)               prior to doing this you may do a "make clean" to remove all compiled stuff.
	@$(ECHO) "make builddeb - Generate a deb package of pam_linotp"
	@$(ECHO) "make clean    - clean up"
	@$(ECHO) "make ppa-dev  - upload to ppa unstable"
	@$(ECHO) "make ppa      - upload to ppa stable"
	@$(ECHO) .......

create: clean
	tar -zcf LinOTPAuth.tar.gz $(PACK_DIRS)

source: 
	-for d in $(SOURCE_DIRS); do (cd $$d; $(MAKE) source ); done
	(cd pam_py_linotp ;$(PYTHON) setup.py sdist $(COMPILE))


builddeb:
	mkdir -p ../build
	(cd libpam-linotp; libtoolize; aclocal; autoconf; autoheader; automake --add-missing; dpkg-buildpackage -i -I -rfakeroot)
	(cd freeradius_perl; dpkg-buildpackage)
	mv libpam-linotp_* ../build/
	mv linotp-freeradius-perl_* ../build/

clean:
	rm -rf ../build
	rm -f *.tar.gz
	(cd libpam-linotp; rm -f config.guess config.sub COPYING depcomp INSTALL install-sh missing)
	(cd libpam-linotp; rm -fr aclocal.m4 autom4te.cache config.log config.status configure libtool ltmain.sh Makefile Makefile.in compile)
	(cd libpam-linotp/src && rm -rf Makefile Makefile.in *.la *.lo *.a *.o .libs/)
	(cd libpam-linotp/debian && rm -rf libpam-linotp* files autoreconf.* )
	rm -f libpam-linotp_*
	rm -f linotp-freeradius*
	(cd pam_py_linotp; $(PYTHON) setup.py clean; rm -rf dist pam_py_linotp.egg-info* )
	(cd freeradius && make clean)
	(cd freeradius_perl && cd debian && rm -rf linotp-freeradius-perl* files)

ppa-preprocess:
	rm -f *.dsc
	rm -f *.changes
	rm -f *.upload
	(cd libpam-linotp; DEBEMAIL="LSE LinOTP2 Packaging <linotp2@lsexperts.de>" dch -i; rm -f ../libpam-linotp_*_source.changes; debuild -S)
	(cd freeradius_perl; DEBEMAIL="LSE LinOTP2 Packaging <linotp2@lsexperts.de>" dch -i; rm -f ../linotp-freeradius-perl_*.changes; debuild -S)

ppa-dev:
	make ppa-preprocess
	(cd libpam-linotp; dput ppa:linotp/unstable ../libpam-linotp_*_source.changes)
	(cd freeradius_perl; dput ppa:linotp/unstable ../linotp-freeradius-perl_*.changes)

ppa:
	make ppa-preprocess
	(cd libpam-linotp; dput ppa:linotp/stable ../libpam-linotp_*_source.changes)
	(cd freeradius_perl; dput ppa:linotp/stable ../linotp-freeradius-perl_*.changes)


