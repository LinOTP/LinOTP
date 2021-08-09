# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP server.
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

PYTHON:=$(shell which python3)
DESTDIR=/
BUILDDIR=$(PWD)/../build
PROJECT=LinOTP
LINOTP_SRC_VERSION=$(shell python3 setup.py --version)
DEB_BUILDDIR:=$(BUILDDIR)/linotp

I18N_LANGUAGES = de
I18N_SRC := $(CURDIR)/linotp/i18n
I18N_JSON_DEST := $(CURDIR)/linotp/public/i18n
I18N_PO_FILES := $(foreach lang,$(I18N_LANGUAGES),$(I18N_SRC)/$(lang)/LC_MESSAGES/linotp.po)
I18N_JSON_FILES := $(foreach lang,$(I18N_LANGUAGES),$(I18N_JSON_DEST)/$(lang).json)


.PHONY: all
all:
	@echo "make source - Create source package"
	@echo "make create - Create the source packages"
	@echo "make install - Install on local system"
	@echo "make buildrpm - Generate a rpm package"
	@echo "make builddeb - Generate a deb package"
	@echo "make clean - Get rid of scratch and byte files"
	@echo "make translate"


.PHONY: extract
extract:
	python setup.py extract_messages
	$(foreach lang, \
		$(I18N_LANGUAGES), \
		msgmerge -U -s $(I18N_SRC)/$(lang)/LC_MESSAGES/linotp.po $(I18N_SRC)/linotp.pot \
		;\
	)

$(I18N_SRC)/%/LC_MESSAGES/linotp.po: extract

.PHONY: translate
translate:
	@echo "Execute translate-LANG (e.g. translate-de)"

translate-%: $(I18N_SRC)/%/LC_MESSAGES/linotp.po
	gtranslator $<
	$(MAKE) compile_catalog

# Compile a .po file to a .json file using the `pojson` tool.
$(I18N_JSON_DEST)/%.json: $(I18N_SRC)/%/LC_MESSAGES/linotp.po
	mkdir -p $(I18N_JSON_DEST)
	pojson -e utf-8 $< > $@

# Compile all .po files to .mo files using babel. As a dependency,
# the .po files are compiled to .json files. The order doesn't matter.
.PHONY: compile_catalog
compile_catalog: $(I18N_JSON_FILES)
	python setup.py compile_catalog

.PHONY: buildtranslation
buildtranslation: extract compile_catalog

.PHONY: source
source:
	mkdir -p $(BUILDDIR)
	$(PYTHON) setup.py sdist $(COMPILE) --dist-dir=$(BUILDDIR)

.PHONY: create
create: source

.PHONY: install
install:
	$(PYTHON) setup.py install --root $(DESTDIR) $(COMPILE)

.PHONY: buildrpm
buildrpm:
	$(PYTHON) setup.py bdist_rpm --post-install=rpm/postinstall --pre-uninstall=rpm/preuninstall

.PHONY: prepare-deb-source
prepare-deb-source: source
	mkdir -pv $(DEB_BUILDDIR)

	# Unpack clean sources to a staging directory for building from. This is to ensure
	# that we have built linotp from the same source tarball contents.

	# The debian packaging directory is not included in the source tarball.
	# See <https://wiki.debian.org/UpstreamGuide#Pristine_Upstream_Source> for rationale

	# Create tarball copy in the format expected by dpkg-source
	cd $(DEB_BUILDDIR) \
		&& upstream_version=$(shell dpkg-parsechangelog | grep "^Version:" |cut -d' ' -f2 | cut -d- -f1) ;\
		package_name=$(shell dpkg-parsechangelog | grep "^Source:" |cut -d' ' -f2 ) ;\
		orig_tar_name="../$${package_name}_$${upstream_version}.$(TAR_SUFFIX)" ;\
		cp $(BUILDDIR)/$(PROJECT)-*.tar.gz $${orig_tar_name} \
		&& tar --strip-components=1 -xf $${orig_tar_name}

	cp -r debian $(DEB_BUILDDIR)

# Ubuntu builds create source packages in linotpd/src
.PHONY: ppa-preprocess
ppa-preprocess: source
	$(MAKE) prepare-deb-source DEB_BUILDDIR=linotp-build TAR_SUFFIX=ubuntu-temp.tar.gz
	cd linotp-build && debuild -S


# Debian builds create binary packages in linotpd/build
.PHONY: builddeb
builddeb:
	../../ci/update-debian-changelog .
	$(MAKE) prepare-deb-source DEB_BUILDDIR=$(DEB_BUILDDIR) TAR_SUFFIX=orig.tar.gz
	cd $(DEB_BUILDDIR); dpkg-buildpackage -i -I -rfakeroot $(DPKG_BUILDPACKAGE_ARGS)

.PHONY: clean
clean:
	$(PYTHON) setup.py clean
	rm -rf MANIFEST
	find . -name '*.pyc' -delete
	rm -fr ./LinOTP.egg-info/
	rm -f $(I18N_JSON_FILES)
	rm -rf ../build/ \
		linotp-build

	rm -f linotp_*.dsc \
		linotp_*.build \
		linotp_*.tar.gz \
		linotp_*.diff.gz \
		linotp_*.changes \
		linotp_*.upload


test:
	$(MAKE) -C linotp/tests/unit $@
	$(MAKE) -C linotp/tests/functional $@

.PHONY: test
