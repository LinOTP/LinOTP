ECHO    = echo
PYTHON=`which python`
DESTDIR=/
BUILDIR=$(CURDIR)/debian/linotp
PROJECT=LinotpUserIdResolver

all:
	@echo "make source - Create source package"
	@echo "make create - Create the source packages"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"
	@echo "make test_resolver - Test the passwd resolver"

source:
	$(PYTHON) setup.py sdist $(COMPILE)

create:
	mkdir -p ../build
	make source
	cp dist/*.tar* ../build/

install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE)


ppa-preprocess:
	rm -f ../*.dsc
	rm -f ../*.changes
	rm -f ../*.upload
	rm -f ../linotp*useridresolver_*_source.changes
	debuild -S

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
	dpkg-buildpackage -i -I -rfakeroot
	mv ../linotp-useridresolver*.deb ../build

clean:
	$(PYTHON) setup.py clean
	rm -rf build/ MANIFEST dist/
	find . -name '*.pyc' -delete
	#rm -rf dist/
	#if [ -d dist ]; then rm -r dist/; fi
	rm -f ../linotp*useridresolver_*.deb
	rm -f ../linotp*useridresolver_*.dsc
	rm -f ../linotp*useridresolver_*.build
	rm -f ../linotp*useridresolver_*.changes
	rm -f ../LinOtp*UserIdResolver-*.tar.gz
	rm -f ../linotp*useridresolver_*.tar.gz
	rm -rf LinOtpUserIdResolver.egg-info/
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean
	rm -rf ../build/

test_resolver:
	nosetests -x -v test/test_resolve.py
