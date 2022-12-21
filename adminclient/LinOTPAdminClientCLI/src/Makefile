#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
#
#    This file is part of LinOTP admin clients.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

ECHO    = echo
PYTHON=`which python`
DESTDIR=/
BUILDIR=$(CURDIR)/debian/linotp
PROJECT=LinOTPAdminClientCLI

all:
	@echo "make source   - Create source package"
	@echo "make create - Create the source packages (command client)"
	@echo "make install  - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean    - Get rid of scratch and byte files"

source:
	$(PYTHON) setup.py sdist $(COMPILE)

create:
	mkdir -p ../build
	make source
	mv dist/LinOTPAdminClientCLI*.tar.gz ../build/

install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE)

buildrpm:
#	$(PYTHON) setup.py bdist_rpm --post-install=rpm/postinstall --pre-uninstall=rpm/preuninstall
	$(PYTHON) setup.py bdist_rpm

builddeb:
	# build the source package in the parent directory
	# then rename it to project_version.orig.tar.gz
	mkdir -p ../build
	$(PYTHON) setup.py sdist $(COMPILE) --dist-dir=../
	rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	# build the package
	dpkg-buildpackage -i -I -rfakeroot $(DPKG_BUILDPACKAGE_ARGS)
	mv ../linotp-adminclient-cli*.deb ../build/
	rm -f ../build/LinOTPAdminClientCLI*.tar.gz

clean:
	$(PYTHON) setup.py clean
	rm -rf build/ MANIFEST dist/
	find . -name '*.pyc' -delete
	rm -f ../linotp*adminclient*cli_*.deb
	rm -f ../linotp*adminclient*cli_*.dsc
	rm -f ../linotp*adminclient*cli_*.changes
	rm -f ../linotp*adminclient*cli_*.tar.gz
	rm -f ../LinOTP*AdminClient*CLI_*.tar.gz
	rm -rf ../build/linotp-adminclient-cli*.deb
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean


ppa-preprocess:
	rm -f ../*.dsc
	rm -f ../*.changes
	rm -f ../*.upload
	rm -f ../linotp-adminclient-cli_*_source.changes
	debuild -S

wine:
	mkdir -p ../build
	wine c:\\python26\\python setup.py bdist --format=wininst
	mv dist/LinOTPAdminClientCLI*.win32.exe ../build/
