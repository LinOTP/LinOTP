ECHO    = echo
PYTHON=`which python`
DESTDIR=/
BUILDIR=$(CURDIR)/debian/linotp
VERSION = 2.7.1.2
PROJECT=LinOTP
COPYSTUFF = tools setup.* linotp config debian Makefile DESCRIPTION MANIFEST.in README.txt

I18N_LANGUAGES = de
I18N_SRC := $(CURDIR)/linotp/i18n
I18N_JSON_DEST := $(CURDIR)/linotp/public/i18n
I18N_PO_FILES := $(foreach lang,$(I18N_LANGUAGES),$(I18N_SRC)/$(lang)/LC_MESSAGES/linotp.po)
I18N_JSON_FILES := $(foreach lang,$(I18N_LANGUAGES),$(I18N_JSON_DEST)/$(lang).json)


all:
	@echo "make source - Create source package"
	@echo "make create - Create the source packages"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"
	@echo "make translate"
	@echo "make ppa-dev - Publish in ppa repository linotp-dev"


extract:
	python setup.py extract_messages
	msgmerge -U linotp/i18n/de/LC_MESSAGES/linotp.po linotp/i18n/linotp.pot

# Compile a .po file to a .json file using the `pojson` tool.
$(I18N_JSON_DEST)/%.json: $(I18N_SRC)/%/LC_MESSAGES/linotp.po
	mkdir -p $(I18N_JSON_DEST)
	pojson -e utf-8 $< > $@

# Compile all .po files to .mo files using babel. As a dependency,
# the .po files are compiled to .json files. The order doesn't matter.
compile_catalog: $(I18N_JSON_FILES)
	python setup.py compile_catalog

translate: extract
	gtranslator linotp/i18n/de/LC_MESSAGES/linotp.po
	make compile_catalog

buildtranslation: extract
	make compile_catalog

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
	rm -f $(I18N_JSON_FILES)
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean
	rm -rf ../build/


test:
	./test.sh
