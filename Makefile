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
	if [ -d RELEASE ]; then rm -rf RELEASE; fi

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

#####################
# Docker container targets
#
# These targets are for building and running docker containers
# for integration and builds

# Container name | Dockerfile location | Purpose
# ---------------------------------------------------------------------------------------------------
# linotp-builder | Dockerfile.builder             | Container ready to build linotp packages
# linotpd        | linotpd/src                    | Runs linotpd in apache
# selenium-test  | linotpd/src/tests/integration  | Run LinOTP Selenium tests against selenium remote

# Extra arguments can be passed to docker build
DOCKER_BUILD_ARGS=

# Uncomment the following if using apt-cacher-ng to cache packages:
#DOCKER_BUILD_ARGS+=--build-arg=http_proxy=http://172.17.0.1:3142

# Default Docker run arguments.
# Extra run arguments can be given here. It can also be used to
# override runtime parameters. For example, to specify a port mapping:
#  make docker-run-linotp-sqlite DOCKER_RUN_ARGS='-p 1234:80'
DOCKER_RUN_ARGS=

DOCKER_BUILD = docker build $(DOCKER_BUILD_ARGS)
DOCKER_RUN = docker run $(DOCKER_RUN_ARGS)
SELENIUM_TESTS_COMPOSEFILE=linotpd/src/linotp/tests/integration/docker-compose.yml

## Toplevel targets
# Toplevel target to build all containers
docker-build-all: docker-build-debs  docker-build-linotpd docker-build-selenium

# Toplevel target to build linotpd container
docker-linotpd: docker-build-debs  docker-build-linotpd

# Build and run Selenium tests
docker-run-selenium: docker-build-linotpd
	docker-compose -f $(SELENIUM_TESTS_COMPOSEFILE) up selenium_tester

##
.PHONY: docker-build-all docker-linotpd docker-run-selenium

# The linotp builder container contains all build dependencies
# needed to build linotp, plus a copy of the linotp
# sources under /pkg/linotp
#
# To use this container as a playground to test build linotp:
#   docker run -it linotp-builder
.PHONY: docker-build-linotp-builder
docker-build-linotp-builder:
	$(DOCKER_BUILD) \
		-f Dockerfile.builder \
		-t linotp-builder \
		.

# A unique name to reference containers for this build
NAME_PREFIX := linotpbuilder-$(shell date +%H%M%S-%N)
DOCKER_CONTAINER_NAME = $(NAME_PREFIX)

.PHONY: docker-build-debs
docker-build-debs: docker-build-linotp-builder $(BUILDDIR)/apt/Packages

$(BUILDDIR)/apt/Packages:
	# Build the debs in a container, then extract them from the image
	$(DOCKER_RUN) \
		--workdir=/pkg/linotp \
		--name=$(DOCKER_CONTAINER_NAME)-apt \
		linotp-builder \
		make deb-install DESTDIR=/pkg/apt DEBUILD_OPTS="$(DEBUILD_OPTS)"
	mkdir -p $(DESTDIR)/incoming
	docker cp \
		$(DOCKER_CONTAINER_NAME)-apt:/pkg/apt $(DESTDIR)
	docker rm $(DOCKER_CONTAINER_NAME)-apt

.PHONY: docker-build-linotpd
docker-build-linotpd: $(BUILDDIR)/dockerfy $(BUILDDIR)/apt/Packages
	cp linotpd/src/Dockerfile \
		linotpd/src/config/*.tmpl \
		linotpd/src/tools/linotp-create-htdigest \
		$(BUILDDIR)

	# We show the files sent to Docker context here to aid in debugging
	find $(BUILDDIR) -ls

	$(DOCKER_BUILD) \
		-t linotpd \
		$(BUILDDIR)

.PHONY: docker-build-selenium
docker-build-selenium: docker-build-linotpd
	$(DOCKER_BUILD) \
		-t selenium_test \
		$(dir $(SELENIUM_TESTS_COMPOSEFILE))

	cd $(dir $(SELENIUM_TESTS_COMPOSEFILE)) \
	&& docker-compose build

.PHONY: docker-run-selenium
docker-run-selenium: docker-build-selenium

.PHONY: docker-run-linotp-sqlite
docker-run-linotp-sqlite: docker-build-linotpd
	# Run linotp in a standalone container
	cd linotpd/src \
		&& $(DOCKER_RUN) -it \
			 -e LINOTP_APACHE_SSL=false \
			 -e LINOTP_DB_TYPE=sqlite \
			 -e LINOTP_DB_NAME=//tmp/sqlite \
			 -e LINOTP_DB_HOST= \
			 -e LINOTP_DB_PORT= \
			 -e APACHE_PORT=80 \
			 -p 80 \
			linotpd

# Dockerfy tool
.PHONY: get-dockerfy
get-dockerfy: $(BUILDDIR)/dockerfy

# Obtain dockerfy binary
# TODO: Build from source
$(BUILDDIR)/dockerfy:
	mkdir -pv $(BUILDDIR)/dockerfy-tmp
	wget --no-verbose --directory-prefix=$(BUILDDIR)/dockerfy-tmp \
		https://github.com/SocialCodeInc/dockerfy/releases/download/1.1.0/dockerfy-linux-amd64-1.1.0.tar.gz
	tar -C $(BUILDDIR) -xvf $(BUILDDIR)/dockerfy-tmp/dockerfy-linux-amd64*.gz
	rm -r $(BUILDDIR)/dockerfy-tmp

