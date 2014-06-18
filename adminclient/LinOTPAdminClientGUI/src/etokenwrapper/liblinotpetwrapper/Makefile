default: all

FILES = liblinotpetwrapper.so.0.1 liblinotpetwrapper.o test.o mytestprogramm 
LINKS = liblinotpetwrapper.so.0 liblinotpetwrapper.so  
VERSION = 0.1

clean:
	-for i in $(FILES); do if [ -f $$i ]; then rm $$i; fi; done
	-for i in $(LINKS); do if [ -h $$i ]; then rm $$i; fi; done
	rm -fr liblinotpetwrapper-$(VERSION)
all:
	gcc -fPIC -g -c -Wall -I/usr/include/PCSC -I.. liblinotpetwrapper.c
	gcc -shared -Wl,-soname,liblinotpetwrapper.so.0  -leTSapi -leTPkcs11 -I/usr/include/PCSC -I.. -o liblinotpetwrapper.so.0.1 liblinotpetwrapper.o 
	ln -s liblinotpetwrapper.so.0.1 liblinotpetwrapper.so.0
	ln -s liblinotpetwrapper.so.0.1 liblinotpetwrapper.so
	gcc -L. -I. -I/usr/include/PCSC -I.. -g -c -Wall test.c
	gcc -llinotpetwrapper -L. test.o -o mytestprogramm

test:
	LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH ./mytestprogramm

install:
	install liblinotpetwrapper.so.0.1 /usr/local/lib/
	ldconfig

rpm:
	mkdir -p  liblinotpetwrapper-$(VERSION)
	cp  *.h *.c Makefile liblinotpetwrapper-$(VERSION)
	cp -r Aladdin-includes/ liblinotpetwrapper-$(VERSION)
	tar -zcf ~/rpmbuild/SOURCES/liblinotpetwrapper-0.1.tgz liblinotpetwrapper-0.1
	rpmbuild -ba liblinotpetwrapper.spec
	@echo ++++++++++++++++++++++++++++++++++++++++++++++
	@echo
	@echo You RPM should now reside in ~/rpmbuild/RPMS/i386
	@echo
	@echo ++++++++++++++++++++++++++++++++++++++++++++++
	cp ~/rpmbuild/RPMS/i386/liblinotpetwrapper*.rpm  ../../../../../
