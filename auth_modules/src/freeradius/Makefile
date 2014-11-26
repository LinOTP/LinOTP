FREERADDIR=`find sandbox -name freeradius\* -type d`
LINOTP_VERSION=2.7.1rc0

COMMENT="added LinOTP2 module rlm_linotp"
info:
	@echo "make clean     -- this will delete the sandbox, needed to build the deb packages"
	@echo "make deb       -- this will build debian packages containig linotp module"
deb:
	make clean
	mkdir -p sandbox
	( cd sandbox &&  apt-get source freeradius )
	cp -r src/rlm_linotp2 $(FREERADDIR)/src/modules/
	cp -r src/rlm_linotp2/linotp2.conf $(FREERADDIR)/raddb/modules/linotp
	cp -r src/rlm_linotp2/linotp $(FREERADDIR)/raddb/sites-available/
	echo "rlm_linotp2" >> $(FREERADDIR)/src/modules/stable
	# remove iodbc, so that it will compile on ubuntu
	sed /libiodbc/d $(FREERADDIR)/debian/control > control.new; mv control.new $(FREERADDIR)/debian/control	
	sed /odbc/d $(FREERADDIR)/src/modules/rlm_sql/stable > stable.new; mv stable.new $(FREERADDIR)/src/modules/rlm_sql/stable
	# patch the postinstall
	cp freeradius.postinst.diff $(FREERADDIR)/debian/
	( cd $(FREERADDIR)/debian/; patch < freeradius.postinst.diff )
	#cat Changelog.linotp $(FREERADDIR)/debian/changelog >> $(FREERADDIR)/debian/changelog.new
	#mv $(FREERADDIR)/debian/changelog.new $(FREERADDIR)/debian/changelog
	head -n1 sandbox/freeradius-*/debian/changelog | cut -d' ' -f2 | sed  's/(\(.*\))/\1/' > freeradius-version.tmp
	( export DEBEMAIL="linotp2@lsexperts.de"; export DEBFULLNAME="LSE LinOTP2 Packaging"; cd $(FREERADDIR); dch -v 1:`cat ../../freeradius-version.tmp`-linotp$(LINOTP_VERSION) $(COMMENT) )
	( cd $(FREERADDIR) && dpkg-buildpackage -b )
clean:
	rm sandbox -fr
