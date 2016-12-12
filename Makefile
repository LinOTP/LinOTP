#!/usr/bin/make -f
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 KeyIdentity GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
#
# LinOTP toplevel makefile
#

PYTHON:=python2

# This directory is used as destination for the various parts of
# the build phase. The various install targets default to this directory
# but can be overriden by DESTDIR
BUILDDIR:=$(PWD)/build

# Targets to operate on LinOTPd and its dependent projects shipped
# in this repository
LINOTPD_PROJS := smsprovider useridresolver linotpd adminclient/LinOTPAdminClientCLI

###################
# Recursive targets
#
# These invoke make in the project subdirectories
#
# install
# clean
#
# Each target will be expanded into the subdirectory targets
#
# e.g. build -> build.subdirmake -> build.smsprovider + build.useridresolver + build.linotpd

# Targets that should recurse into linotp project directories
LINOTPD_TARGETS := install clean
.PHONY: $(LINOTPD_TARGETS)

INSTALL_TARGETS := $(addsuffix .install,$(LINOTPD_PROJS))
CLEAN_TARGETS := $(addsuffix .clean,$(LINOTPD_PROJS))
MAKEFILE_TARGETS := $(INSTALL_TARGETS) $(CLEAN_TARGETS)
.PHONY: $(MAKEFILE_TARGETS)

$(MAKEFILE_TARGETS):
	# Invoke makefile target in subdirectory/src
	$(MAKE) -C $(basename $@)/src $(subst $(basename $@).,,$@)

# Subdirectory make that should invoke target in all subproject directories
.PHONY: %.subdirmake
%.subdirmake : smsprovider.% useridresolver.% linotpd.% ;

# Add dependencies for main targets
# build -> build.subdirmake
# clean -> clean.subdirmake
# etc.
.SECONDEXPANSION:
$(LINOTPD_TARGETS): $$(basename $$@).subdirmake

clean:
	if [ -d $(BUILDDIR) ]; then rm -rf $(BUILDDIR) ;fi

# Run a command in a list of directories
# $(call run-in-directories,DIRS,COMMAND)
run-in-directories = \
	echo run-in-directories:$(1) ;\
	for P in $(1) ;\
		do \
		    cmd="cd $$P/src && $(2)" ;\
			echo \\n$$cmd ;\
			( eval $$cmd ) || exit $? ;\
	done

# Run a command in all linotpd directories
run-in-linotpd-projs = $(call run-in-directories,$(LINOTPD_PROJS),$(1))

#################
# Targets invoking setup.py
#

# Installation of packages in 'develop mode'.
.PHONY: develop
develop:
	$(call run-in-linotpd-projs,$(PYTHON) setup.py $@)


#####################
# Unit test targets
#
#
# These targets can be run directly from a development
# environment, within a container or an installed system
#
# unittests - just the unit tests
# integrationtests - selenium integration tests
# test - all tests

ifndef NOSETESTS_ARGS
NOSETESTS_ARGS?=-v
endif

test: unittests integrationtests

unittests:
	$(MAKE) -C linotpd/src/linotp/tests/unit $@
	nosetests $(NOSETESTS_ARGS) .

# integrationtests - selenium integration tests
# Use the SELENIUMTESTS_ARGS to supply test arguments
integrationtests:
	$(MAKE) -C linotpd/src/linotp/tests/integration $@

.PHONY: test unittests integrationtests


#####################
# Packaging targets
#

# These targets run the various commands needed
# to create packages of linotp

# builddeb: Generate .debs
# deb-install: Build .debs and install to DESTDIR

DEBPKG_PROJS := linotpd useridresolver smsprovider adminclient/LinOTPAdminClientCLI
BUILDARCH := $(shell dpkg-architecture -q DEB_BUILD_ARCH)
CHANGELOG = "$(shell cd linotpd/src ; dpkg-parsechangelog)"

# Output is placed in DESTDIR, but this
# can be overriden
ifndef DESTDIR
DESTDIR = $(BUILDDIR)
endif

.PHONY: builddeb
builddeb:
	# builddeb: Run debuild in each directory to generate .deb
	$(call run-in-directories,$(DEBPKG_PROJS),$(MAKE) builddeb)

.PHONY: deb-install
deb-install: builddeb
	# deb-install: move the built .deb files into an archive directory and
	# 			    generate Packages file
	mkdir -pv $(DESTDIR)
	cp $(foreach dir,$(DEBPKG_PROJS),$(dir)/build/*.deb) $(DESTDIR)
	find $(DESTDIR)
	cd $(DESTDIR) && dpkg-scanpackages -m . > Packages

