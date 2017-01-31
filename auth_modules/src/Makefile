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
#
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
	(cd libpam-linotp; rm -f ../libpam-linotp_*_source.changes; debuild -S)
	(cd freeradius_perl; rm -f ../linotp-freeradius-perl_*.changes; debuild -S)

