ECHO    = echo
PYTHON=`which python`
DESTDIR=/
BUILDIR=$(CURDIR)/debian/linotp
PROJECT=LinOTPAdminClientGUI
BUILDVERSION = `date +%y%m%d%H%M`

all:
	@echo "make source     - Create source package"
	@echo "make create     - Create the source packages"
	@echo "make install    - Install on local system"
	@echo "make buildrpm   - Generate a rpm package"
	@echo "make builddeb   - Generate a deb package"
	@echo "make clean      - Get rid of scratch and byte files"
	@echo "make translate  - Translate texts in the program"

buildversion:
#	@echo "Setting buildversion $(BUILDVERSION)"
#	@sed -e s/BUILD_VERSION\ =\ .*/BUILD_VERSION\ =\ \'$(BUILDVERSION)\'/ glinotpadm.py > glinotpadm.py.neu
#	@mv glinotpadm.py.neu glinotpadm.py
#	@echo done.

translate:
	(cd locale && make translate)

source:
	make buildversion
	$(PYTHON) setup.py sdist $(COMPILE)

create:
	mkdir -p ../build
	make buildversion
	make source

install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE)

buildrpm:
	make buildversion
#	$(PYTHON) setup.py bdist_rpm --post-install=rpm/postinstall --pre-uninstall=rpm/preuninstall
	$(PYTHON) setup.py bdist_rpm 

builddeb:
	mkdir -p ../build
	make buildversion
	# build the source package in the parent directory
	# then rename it to project_version.orig.tar.gz
	$(PYTHON) setup.py sdist $(COMPILE) --dist-dir=../ 
	rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	# build the package
	dpkg-buildpackage -i -I -rfakeroot
	mv ../linotp-adminclient-gui*.deb ../build/

clean:
	$(PYTHON) setup.py clean
	rm -rf build/ MANIFEST dist/
	rm -f glinotpadm.glade.h
	rm -f *.log
	find . -name '*.pyc' -delete
	#rm -r dist/
	#if [ -d dist ]; then rm -r dist/; fi
	rm -f ../linotp*adminclient*gui_*.deb
	rm -f ../linotp*adminclient*gui_*.dsc
	rm -f ../linotp*adminclient*gui_*.changes
	rm -f ../linotp*adminclient*gui*.tar.gz
	rm -f ../LinOTP*AdminClient*GUI*.tar.gz
	rm -rf LinOTPAdminClientGUI.egg-info/
	rm -rf ../build/linotp-adminclient-gui*.deb
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean
	rm -rf debian/linotp-adminclient-*

ppa-preprocess:
	rm -f ../*.dsc
	rm -f ../*.changes
	rm -f ../*.upload
	DEBEMAIL="LSE LinOTP2 Packaging <linotp2@lsexperts.de>" dch -i
	rm -f ../linotp-adminclient-gui_*_source.changes
	debuild -S

ppa-dev:
	make ppa-preprocess
	dput ppa:linotp/unstable ../linotp-adminclient-gui*_source.changes

