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
	@echo "make ppa      - PRODUCTIVE: upload package to ppa launchpad"
	@echo "make ppa-dev  - upload package to ppa launchpad unstable"

source:
	$(PYTHON) setup.py sdist $(COMPILE)

create:
	make source
	cp dist/*.tar* ..

install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE)

buildrpm:
#	$(PYTHON) setup.py bdist_rpm --post-install=rpm/postinstall --pre-uninstall=rpm/preuninstall
	$(PYTHON) setup.py bdist_rpm

builddeb:
	# build the source package in the parent directory
	# then rename it to project_version.orig.tar.gz
	$(PYTHON) setup.py sdist $(COMPILE) --dist-dir=../ 
	rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	# build the package
	dpkg-buildpackage -i -I -rfakeroot 

clean:
	$(PYTHON) setup.py clean
	rm -rf build/ MANIFEST dist/
	find . -name '*.pyc' -delete
	rm -f ../linotp*adminclient*cli_*.deb
	rm -f ../linotp*adminclient*cli_*.dsc
	rm -f ../linotp*adminclient*cli_*.changes
	rm -f ../linotp*adminclient*cli_*.tar.gz
	rm -f ../LinOTP*AdminClient*CLI_*.tar.gz
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean


ppa-preprocess:
	rm -f ../*.dsc
	rm -f ../*.changes
	rm -f ../*.upload
	DEBEMAIL="LSE LinOTP2 Packaging <linotp2@lsexperts.de>"	dch -i
	rm -f ../linotp-adminclient-cli_*_source.changes
	debuild -S

ppa-dev:
	make ppa-preprocess
	dput ppa:linotp/unstable ../linotp-adminclient-cli*_source.changes

