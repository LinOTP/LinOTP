#!/usr/bin/make -f
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 - 2019 KeyIdentity GmbH
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
#
# LinOTP toplevel makefile
#
#
# If you are running in a local development environment, you can
# set these environment variables to configure make behaviour:
# export http_proxy=http://proxy.hostname:port
# export no_proxy=localhost,127.0.0.1,.my.local.domain
# export DOCKER_REGISTRY_URL=registry.local.domain

PYTHON:=python3

# This directory is used as destination for the various parts of
# the build phase. The various install targets default to this directory
# but can be overriden by DESTDIR
BUILDDIR:=$(PWD)/build

# Targets to operate on LinOTPd and its dependent projects shipped
# in this repository
LINOTPD_PROJS := linotpd

# These variables let you set the amount of stuff LinOTP is logging.
#
# LINOTP_LOGLEVEL controls the amount of logging in general while
# LINOTP_CONSOLE_LOGLEVEL controls logging to the console (as opposed
# to logstash -- logstash always gets whatever LINOTP_LOGLEVEL lets
# through, so LINOTP_CONSOLE_LOGLEVEL can be used to have less stuff
# show up on the console than in logstash).
# SQLALCHEMY_LOGLEVEL controls the amount of logging done by SQLAlchemy
# (who would have guessed); DEBUG will log SQL queries and results,
# INFO will log just queries (no results) and WARN will log neither.
# APACHE_LOGLEVEL limits the amount of stuff Apache writes to its error
# output; normally anything that is written to the LinOTP console goes
# through here, too, so there isn't a lot of sense in setting this
# differently to LINOTP_CONSOLE_LOGLEVEL unless you're doing nonstandard
# trickery and/or use a different (and unsupported by us) web server
# than Apache to run LinOTP.

export LINOTP_LOGLEVEL=INFO
export LINOTP_CONSOLE_LOGLEVEL=DEBUG
export SQLALCHEMY_LOGLEVEL=ERROR
export APACHE_LOGLEVEL=DEBUG


#############################################################################################
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
#############################################################################################

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
%.subdirmake : linotpd.% ;

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


###############################################################################
# Unit test targets
#
#
# These targets can be run directly from a development
# environment, within a container or an installed system
#
# unittests - just the unit tests
# integrationtests - selenium integration tests
# test - all tests
###############################################################################

test: unittests integrationtests functionaltests

unittests:
	$(MAKE) -C linotpd/src/linotp/tests/unit $@

# Functional tests. Additional arguments can be
# supplied with FUNCTIONALTESTS_ARGS
functionaltests:
	$(MAKE) -C linotpd/src/linotp/tests/functional $@

# integrationtests - selenium integration tests
# Use the SELENIUMTESTS_ARGS to supply test arguments
integrationtests:
	$(MAKE) -C linotpd/src/linotp/tests/integration $@

.PHONY: test unittests functionaltests integrationtests



###############################################################################
# Packaging targets
#
#
# These targets run the various commands needed
# to create packages of linotp
#
# builddeb: Generate .debs
# deb-install: Build .debs and install to DESTDIR
###############################################################################

DEBPKG_PROJS := linotpd
BUILDARCH = $(shell dpkg-architecture -q DEB_BUILD_ARCH)
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
	# deb-install: move the built .deb, .changes and related files into an archive directory and
	# generate Packages file
	mkdir -pv $(DESTDIR)
	cp $(foreach dir,$(DEBPKG_PROJS),$(dir)/build/*.deb) $(DESTDIR)
	find $(foreach dir,$(DEBPKG_PROJS),$(dir)) -type f -regex '.+\.changes' -o -regex '.+\.dsc' -o -regex '.+\.tar\..+' -o -regex '.+\.buildinfo' | xargs -iXXX -n1 cp XXX $(DESTDIR)
	find $(DESTDIR)
	cd $(DESTDIR) && dpkg-scanpackages -m . > Packages



######################################################################################################
# Docker container targets
#
# These targets are for building and running docker containers
# for integration and builds
#
# Container name | Dockerfile location | Purpose
# ---------------------------------------------------------------------------------------------------
# linotp-builder | Dockerfile.builder             | Container ready to build linotp packages
# linotp         | linotpd/src                    | Runs linotp in apache
# selenium-test  | linotpd/src/tests/integration  | Run LinOTP Selenium tests against selenium remote
# linotp-unit    | linotpd/src/linotp/tests/unit  | Run LinOTP Unit tests
######################################################################################################


# Extra arguments can be passed to docker build
DOCKER_BUILD_ARGS=

# List of tags to add to built linotp images, using the '-t' flag to docker-build
DOCKER_TAGS=latest

# Override to change the mirror used for image building
DEBIAN_MIRROR=deb.debian.org

# Override to change the Debian release used to build with
DEBIAN_RELEASE_NAME=buster
BASE_IMAGE=debian:$(DEBIAN_RELEASE_NAME)

# Arguments passed to Docker build commands
# Pass proxy environment variables through to docker build by default
DOCKER_EXTRA_BUILD_ARGS= --build-arg=http_proxy \
					--build-arg=https_proxy \
					--build-arg=no_proxy \
					--build-arg BASE_IMAGE=$(BASE_IMAGE) \
					--build-arg DEBIAN_MIRROR=$(DEBIAN_MIRROR) \
					--build-arg DEPENDENCY_SOURCE=$(DEPENDENCY_SOURCE) \
					--build-arg DEPENDENCY_DISTRIBUTION=$(DEPENDENCY_DISTRIBUTION) \
					--build-arg DEPENDENCY_COMPONENT=$(DEPENDENCY_COMPONENT) \
					--build-arg DEPENDENCY_GPG_KEYID=$(DEPENDENCY_GPG_KEYID) \
					--build-arg DEPENDENCY_GPG_KEY_URL=$(DEPENDENCY_GPG_KEY_URL)

# Default Docker run arguments.
# Extra run arguments can be given here. It can also be used to
# override runtime parameters. For example, to specify a port mapping:
#  make docker-run-linotp-sqlite DOCKER_RUN_ARGS='-p 1234:80'
DOCKER_RUN_ARGS=

DOCKER_BUILD = docker build $(DOCKER_BUILD_ARGS) $(DOCKER_EXTRA_BUILD_ARGS)
DOCKER_RUN = docker run $(DOCKER_RUN_ARGS)

TESTS_DIR=linotpd/src/linotp/tests

SELENIUM_TESTS_DIR=$(TESTS_DIR)/integration
UNIT_TESTS_DIR=$(TESTS_DIR)/unit
FUNCTIONAL_TESTS_DIR=$(TESTS_DIR)/functional

## Toplevel targets
# Toplevel target to build all containers
docker-build-all: docker-build-debs docker-build-linotp docker-build-linotp-test-image docker-build-linotp-softhsm

# Toplevel target to build linotp container
docker-linotp: docker-build-debs  docker-build-linotp

# Build and run Selenium /integration tests
docker-selenium: docker-build-all docker-run-selenium

# Build and run Unit tests
docker-unit: docker-build-linotp docker-build-linotp-test-image docker-run-linotp-unit

docker-functional: docker-build-linotp docker-build-linotp-test-image docker-run-linotp-functional-test

docker-pylint: docker-run-linotp-pylint

.PHONY: docker-build-all docker-linotp docker-run-selenium docker-unit docker-pylint docker-functional

# This is expanded during build to add image tags
DOCKER_TAG_ARGS=$(foreach tag,$(DOCKER_TAGS),-t $(DOCKER_IMAGE):$(tag))

# The linotp builder container contains all build dependencies
# needed to build linotp, plus a copy of the linotp
# sources under /pkg/linotp
#
# To use this container as a playground to test build linotp:
#   docker run -it linotp-builder
.PHONY: docker-build-linotp-builder
docker-build-linotp-builder: DOCKER_IMAGE=linotp-builder
docker-build-linotp-builder:
	$(DOCKER_BUILD) \
		-f Dockerfile.builder \
		$(DOCKER_TAG_ARGS) \
		-t $(DOCKER_IMAGE) \
		.

# A unique name to reference containers for this build
DOCKER_CONTAINER_TIMESTAMP := $(shell date +%H%M%S-%N)
NAME_PREFIX := linotpbuilder-$(DOCKER_CONTAINER_TIMESTAMP)
DOCKER_CONTAINER_NAME = $(NAME_PREFIX)

.PHONY: docker-build-debs
docker-build-debs: docker-build-linotp-builder
	# Force rebuild of debs
	rm -f $(BUILDDIR)/apt/Packages
	$(MAKE) $(BUILDDIR)/apt/Packages

# Build the debian packages in a container, then extract them from the image
$(BUILDDIR)/apt/Packages:
	$(DOCKER_RUN) \
		--detach \
		--rm \
		--name $(DOCKER_CONTAINER_NAME)-apt \
		linotp-builder \
		sleep 3600
	docker cp . $(DOCKER_CONTAINER_NAME)-apt:/build
	docker exec \
		$(DOCKER_CONTAINER_NAME)-apt \
			make deb-install DESTDIR=/build/apt DEBUILD_OPTS=\"$(DEBUILD_OPTS)\"
	docker cp \
		$(DOCKER_CONTAINER_NAME)-apt:/build/apt $(DESTDIR)
	docker rm -f $(DOCKER_CONTAINER_NAME)-apt

# Build just the linotp image. The builder-linotp is required but will not be
# built by this target - use 'make docker-linotp' to build the dependencies first
.PHONY: docker-build-linotp
docker-build-linotp: DOCKER_IMAGE=linotp
docker-build-linotp: $(BUILDDIR)/dockerfy $(BUILDDIR)/apt/Packages
	cp linotpd/src/Dockerfile \
		linotpd/src/config/*.tmpl \
		linotpd/src/tools/linotp* \
		linotpd/src/linotp/tests/integration/testdata/se_mypasswd \
		$(BUILDDIR)
	cp -r linotpd/src/config/docker-initscripts.d $(BUILDDIR)

	# We show the files sent to Docker context here to aid in debugging
	find $(BUILDDIR)

	$(DOCKER_BUILD) \
		$(DOCKER_TAG_ARGS) \
		-t $(DOCKER_IMAGE) \
		$(BUILDDIR)

# Build testing Docker Container
# This container is based on the linotp image and includes additional
# dependencies for testing targets.
# It needs an existing linotp image available
# which can be built by make docker-build-linotp
.PHONY: docker-build-testenv
docker-build-linotp-test-image: DOCKER_IMAGE=linotp-testenv
docker-build-linotp-test-image:
	cd $(TESTS_DIR) \
	&& $(DOCKER_BUILD) \
		$(DOCKER_TAG_ARGS) \
		-t $(DOCKER_IMAGE) .

# Build Softhsm test container
.PHONY: docker-build-linotp-softhsm
docker-build-linotp-softhsm: DOCKER_IMAGE=linotp-softhsm
docker-build-linotp-softhsm: BASE_IMAGE=linotp:latest
docker-build-linotp-softhsm:
	cd $(SELENIUM_TESTS_DIR) \
	&& $(DOCKER_BUILD) \
		$(DOCKER_TAG_ARGS) \
		-f Dockerfile.softhsm \
		-t $(DOCKER_IMAGE) .

# Run Selenium based smoketest against LinOTP configured with
# softhsm security module
.PHONY: docker-run-softhsm-smoketest
docker-run-softhsm-smoketest:
	cd $(SELENIUM_TESTS_DIR) \
		&& docker-compose \
			-f docker-compose.yml -f docker-compose-softhsm.yml \
			run \
			--rm \
			-e PYTESTARGS="-m smoketest ${PYTESTARGS}" \
			selenium_tester
	cd $(SELENIUM_TESTS_DIR) \
		&& docker-compose down


# Pass PYTESTARGS=test_manage.py for picking a specific test file
#      PYTESTARGS="-k testname" for picking a specific test
#
# e.g.
#      make docker-run-selenium PYTESTARGS=test_manage.py
.PHONY: docker-run-selenium
docker-run-selenium:
	cd $(SELENIUM_TESTS_DIR) \
		&& docker-compose run \
			--rm \
			-e PYTESTARGS="${PYTESTARGS}" \
			selenium_tester
	cd $(SELENIUM_TESTS_DIR) \
		&& docker-compose down

# Remove all selenium test relevant containers/images
# We do not remove the LinOTP image:
#  - Maybe built an up-2-date image some pipeline steps before test execution.

.PHONY: docker-selenium-clean
docker-selenium-clean:
# This container triggers the python test scripts
	docker stop $$(docker ps -a -q --filter "name=integration_selenium_tester_run") 2>/dev/null || echo "Stop integration_selenium_tester_run_*"
# This container receives the selenium webdriver instructions
	docker stop $$(docker ps -a -q --filter "name=integration_selenium") 2>/dev/null || echo "Stop integration_selenium_*"
	docker stop $$(docker ps -a -q --filter "name=integration_linotp") 2>/dev/null || echo "Stop integration_linotp_*"
	docker stop $$(docker ps -a -q --filter "name=integration_db") 2>/dev/null || echo "Stop integration_db_*"

	docker rm -f $$(docker ps -a -q --filter "name=integration_selenium_tester_run") 2>/dev/null || echo "Remove container integration_selenium_tester_run_*"
	docker rm -f $$(docker ps -a -q --filter "name=integration_selenium") 2>/dev/null || echo "Remove container integration_selenium_*"
	docker rm -f $$(docker ps -a -q --filter "name=integration_linotp") 2>/dev/null || echo "Remove container integration_linotp_*"
	docker rm -f $$(docker ps -a -q --filter "name=integration_db") 2>/dev/null || echo "Remove container integration_db_*"

	docker rmi -f integration_selenium_tester 2>/dev/null || echo "Remove image integration_selenium_tester"
	docker rmi -f selenium_tester 2>/dev/null || echo "Remove image selenium_tester"
	docker rmi -f selenium/standalone-chrome-debug 2>/dev/null || echo "Remove image selenium/standalone-chrome-debug"
	docker rmi -f mysql 2>/dev/null || echo "Removed image mysql"
	docker images
	docker ps -a

.PHONY: docker-run-linotp-sqlite
docker-run-linotp-sqlite: docker-build-linotp
	# Run linotp in a standalone container
	cd linotpd/src \
		&& $(DOCKER_RUN) -it \
			 -e HEALTHCHECK_PORT=80 \
			 -e LINOTP_LOGLEVEL=$(LINOTP_LOGLEVEL) \
			 -e LINOTP_CONSOLE_LOGLEVEL=$(LINOTP_CONSOLE_LOGLEVEL) \
			 -e SQLALCHEMY_LOGLEVEL=$(SQLALCHEMY_LOGLEVEL) \
			 -e APACHE_LOGLEVEL=$(APACHE_LOGLEVEL) \
			linotp

# Dockerfy tool
.PHONY: get-dockerfy
get-dockerfy: $(BUILDDIR)/dockerfy

DOCKERFY_URL=https://github.com/SocialCodeInc/dockerfy/releases/download/1.1.0/dockerfy-linux-amd64-1.1.0.tar.gz
DOCKERFY_SHA256=813d47ebf2e63c966655dd5349a29600ba94deac7a57c132bf624c56ba210445

# Obtain dockerfy binary
# TODO: Build from source
$(BUILDDIR)/dockerfy:
	mkdir -pv $(BUILDDIR)/dockerfy-tmp
	wget --directory-prefix=$(BUILDDIR)/dockerfy-tmp $(DOCKERFY_URL)
	echo "${DOCKERFY_SHA256} " $(BUILDDIR)/dockerfy-tmp/dockerfy-linux-amd64*gz \
	| sha256sum -c -
	tar -C $(BUILDDIR) -xvf $(BUILDDIR)/dockerfy-tmp/dockerfy-linux-amd64*.gz
	rm -r $(BUILDDIR)/dockerfy-tmp


#
# # Unit tests
#

# Run Unit tests. Use $PYTESTARGS for additional pytest settings
.PHONY: docker-run-linotp-unit
docker-run-linotp-unit:
	cd $(UNIT_TESTS_DIR) \
		&& $(DOCKER_RUN) \
			--name=$(DOCKER_CONTAINER_NAME)-unit \
			--volume=$(PWD):/linotpsrc:ro \
			-t linotp-testenv \
			/usr/bin/make test PYTESTARGS="$(PYTESTARGS)"

#jenkins pipeline uses this make rule
.PHONY: docker-run-linotp-unit-pipeline
PYTESTARGS=-v -p no:cacheprovider --junitxml=/tmp/pytests.xml
docker-run-linotp-unit-pipeline: docker-run-linotp-unit
	docker cp $(DOCKER_CONTAINER_NAME)-unit:/tmp/pytests.xml $(PWD)
	docker rm $(DOCKER_CONTAINER_NAME)-unit

#
# # Pylint
#


# Run Pylint Code Analysis
.PHONY: docker-run-linotp-pylint
docker-run-linotp-pylint: docker-build-linotp-test-image
	$(DOCKER_RUN) \
		--name=$(DOCKER_CONTAINER_NAME)-pylint \
		--volume=$(PWD):/linotpsrc \
		-w="/linotpsrc" \
		--entrypoint="" \
		--env "LANG=C.UTF-8" \
		-t linotp-testenv \
	 	pylint --output-format=parseable --reports=y --rcfile=.pylintrc \
		--disable=E1101,maybe-no-member --ignore tests,functional,integration linotp > pylint.log; exit 0


#
# # Functional Tests
#


# NIGHTLY variable controls, if certain long-runnig tests are skipped
#
# NIGHTLY="no" or unset: long-running tests are skipped
# NIGHTLY="yes" all tests are executed
#
# Example:
# $ export NIGHTLY="yes"
# $ make docker-run-linotp-functional-test

FUNCTIONAL_DOCKER_CONTAINER_NAME=linotp-$(DOCKER_CONTAINER_TIMESTAMP)-functional
FUNCTIONAL_MYSQL_CONTAINER_NAME=mysql-$(DOCKER_CONTAINER_TIMESTAMP)-functional

.PHONY: docker-run-linotp-functional-test
docker-run-linotp-functional-test:
	cd $(FUNCTIONAL_TESTS_DIR) && \
		NIGHTLY=${NIGHTLY} \
		FUNCTIONAL_DOCKER_CONTAINER_NAME=$(FUNCTIONAL_DOCKER_CONTAINER_NAME) \
		FUNCTIONAL_MYSQL_CONTAINER_NAME=$(FUNCTIONAL_MYSQL_CONTAINER_NAME) \
		PYTESTARGS="$(PYTESTARGS)" \
			docker-compose --project-directory $(PWD) up \
				--abort-on-container-exit \
				--force-recreate
	docker rm $(FUNCTIONAL_DOCKER_CONTAINER_NAME) $(FUNCTIONAL_MYSQL_CONTAINER_NAME)
