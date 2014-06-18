ECHO    = echo
PYTHON=`which python`
DESTDIR=/
BUILDIR=$(CURDIR)/debian/python-yubico
PROJECT=python-yubico

all:
	@echo "make source - Create source package"
	@echo "make create - Create the source packages"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"

source:
	$(PYTHON) setup.py sdist $(COMPILE)

create:
	mkdir -p ../build
	make source
	mv dist/python-yubico*.tar.gz ../build

install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE)

buildrpm:
#	$(PYTHON) setup.py bdist_rpm --post-install=rpm/postinstall --pre-uninstall=rpm/preuninstall
	$(PYTHON) setup.py bdist_rpm

builddeb:
	# build the source package in the parent directory
	# then rename it to project_version.orig.tar.gz
	mkdir -p ../build
	rm -f dist/*
	$(PYTHON) setup.py sdist $(COMPILE) --dist-dir=../ 
	rename -f 's/$(PROJECT)-(.*)\.tar\.gz/$(PROJECT)_$$1\.orig\.tar\.gz/' ../*
	# build the package
	dpkg-buildpackage -i -I -rfakeroot
	mv ../python-yubico*.deb ../build/

clean:
	$(PYTHON) setup.py clean
	rm -rf build/ MANIFEST dist/
	find . -name '*.pyc' -delete
	#rm -r dist/
	rm -f ../$(PROJECT)_*.deb
	rm -f ../$(PROJECT)_*.dsc
	rm -f ../$(PROJECT)_*.changes
	rm -f ../$(PROJECT)_*.tar.gz
	rm -f ../$(PROJECT)-*.tar.gz
	rm -f ../build/python-yubico*.tar.gz
	rm -f ../build/python-yubico*.deb
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean

