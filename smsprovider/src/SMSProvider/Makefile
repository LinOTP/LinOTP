ECHO    = echo
PYTHON=`which python`
DESTDIR=/
BUILDIR=$(CURDIR)/debian/linotp
PROJECT=SMSProvider

all:
	@echo "make source - Create source package"
	@echo "make create - Create the source packages"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"
	@echo "make test_sms - test the SMS provider"

source:
	$(PYTHON) setup.py sdist $(COMPILE)

create:
	make source

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
	#rm -r dist/
	#if [ -d dist ]; then rm -r dist/; fi
	rm -f ../linotp-smsprovider_*.deb
	rm -f ../linotp-smsprovider_*.dsc
	rm -f ../linotp-smsprovider_*.changes
	rm -f ../SMSProvider_*.tar.gz
	rm -f ../linotp-smsprovider_*.tar.gz
	fakeroot $(MAKE) -f $(CURDIR)/debian/rules clean

test_sms:
	(nosetests -v -x test/test_sms.py)

