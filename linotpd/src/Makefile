ECHO    = echo
PYTHON=`which python`
DESTDIR=/
BUILDIR=$(CURDIR)/debian/linotp
PROJECT=LinOTP
VERSION = 2.7
COPYSTUFF = tools setup.* linotp config debian Makefile DESCRIPTION MANIFEST.in README.txt

all:
	@echo "make source - Create source package"
	@echo "make create - Create the source packages"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"
	@echo "make translate"
	@echo "make ppa-dev - Publish in ppa repository linotp-dev"
	@echo "make ppa     - Publish in PRODUCTIVE repository linotp"


translate:
	mkdir -p linotp/i18n/
	python setup.py extract_messages
	#	python setup.py init_catalog -l de
	msgmerge -U linotp/i18n/de/LC_MESSAGES/linotp.po linotp/i18n/linotp.pot
	gtranslator linotp/i18n/de/LC_MESSAGES/linotp.po
	python setup.py compile_catalog

buildtranslation:
	mkdir -p linotp/i18n/
	python setup.py extract_messages
	msgmerge -U linotp/i18n/de/LC_MESSAGES/linotp.po linotp/i18n/linotp.pot
	python setup.py compile_catalog

source:
	make buildtranslation
	$(PYTHON) setup.py sdist $(COMPILE)

create:
	mkdir -p ../build
	make buildtranslation
	make source
	cp dist/*.tar* ../build/

install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE)

buildrpm:
	make buildtranslation
	$(PYTHON) setup.py bdist_rpm --post-install=rpm/postinstall --pre-uninstall=rpm/preuninstall

ppa-preprocess:
	rm -f *.dsc
	rm -f *.changes
	rm -f *.upload
	DEBEMAIL="LSE LinOTP2 Packaging <linotp2@lsexperts.de>" dch -i
	make buildtranslation
	rm -fr linotp-$(VERSION)
	mkdir -p linotp-$(VERSION)
	cp -r $(COPYSTUFF) linotp-$(VERSION)
	rm -f linotp_*_source.changes
	(cd linotp-$(VERSION); touch LINOTP_DEBIAN_PACKAGE;  debuild -S)

ppa-dev:
	make ppa-preprocess
	dput ppa:linotp/unstable linotp_*_source.changes

# We need to have a builddepLOCAL, as we need to build the debian file inside a linotp-VERSION
#  directory. Otherwise the packagname of linotp in the debconf database will be unknown.
#
builddeblocal:
	# build the source package in the parent directory
	# then rename it to project_version.orig.tar.gz
	# We need to touch this file, so that the setup.py knows, that we are building a debian package!
	touch LINOTP_DEBIAN_PACKAGE
	$(PYTHON) setup.py sdist $(COMPILE) --dist-dir=../
	rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	# build the package
	mkdir -p debian/linotp/var/log/linotp/
	dpkg-buildpackage -i -I -rfakeroot

builddeb:
	mkdir -p ../build
	make buildtranslation
	mkdir -p linotp-$(VERSION)
	cp -r $(COPYSTUFF)  linotp-$(VERSION)
	(cd linotp-$(VERSION) ; make builddeblocal )
	rm -fr linotp-$(VERSION)
	mv linotp*.deb ../build

clean:
	$(PYTHON) setup.py clean
	rm -rf build/ MANIFEST dist/
	find . -name '*.pyc' -delete
	#rm -r dist/
	rm -f ./linotp*.deb
	rm -f ./linotp*.dsc
	rm -f ./linotp*.changes
	rm -f ./*.build
	rm -f ./*.upload
	rm -f ./*.tar.gz
	rm -fr ./LinOTP.egg-info/
	rm -f linotp/i18n/linotp.pot
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean
	rm -rf ../build/


test:
	./test.sh
