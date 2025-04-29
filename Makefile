#!/usr/bin/make -f
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
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
# LINOTP_LOG_LEVEL controls the amount of logging in general while
# LINOTP_LOG_CONSOLE_LEVEL controls logging to the console (as opposed
# to logstash -- logstash always gets whatever LINOTP_LOG_LEVEL lets
# through, so LINOTP_LOG_CONSOLE_LEVEL can be used to have less stuff
# show up on the console than in logstash).
# LINOTP_LOG_LEVEL_DB_CLIENT controls the amount of logging done by SQLAlchemy
# (who would have guessed); DEBUG will log SQL queries and results,
# INFO will log just queries (no results) and WARN will log neither.
# APACHE_LOGLEVEL limits the amount of stuff Apache writes to its error
# output; normally anything that is written to the LinOTP console goes
# through here, too, so there isn't a lot of sense in setting this
# differently to LINOTP_LOG_CONSOLE_LEVEL unless you're doing nonstandard
# trickery and/or use a different (and unsupported by us) web server
# than Apache to run LinOTP.

export LINOTP_LOG_LEVEL=INFO
export LINOTP_LOG_CONSOLE_LEVEL=DEBUG
export LINOTP_LOG_LEVEL_DB_CLIENT=ERROR
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
LINOTPD_TARGETS := linotpd.install linotpd.clean
.PHONY: $(LINOTPD_TARGETS)

linotpd.install:
	$(MAKE) -f Makefile.linotp install

linotpd.clean:
	$(MAKE) -f Makefile.linotp clean

clean: linotpd.clean
	if [ -d $(BUILDDIR) ]; then rm -rf $(BUILDDIR) ;fi
	if [ -d RELEASE ]; then rm -rf RELEASE; fi


#################
# Targets invoking setup.py
#

# Installation of packages in 'develop mode'.
.PHONY: develop
develop:
	$(PYTHON) setup.py $@


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
	$(MAKE) -C linotp/tests/unit $@

# Functional tests. Additional arguments can be
# supplied with FUNCTIONALTESTS_ARGS
functionaltests:
	$(MAKE) -C linotp/tests/functional $@

# integrationtests - selenium integration tests
# Use the SELENIUMTESTS_ARGS to supply test arguments
integrationtests:
	$(MAKE) -C linotp/tests/integration $@

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
CHANGELOG = "$(shell dpkg-parsechangelog)"

# Output is placed in DESTDIR, but this
# can be overriden
ifndef DESTDIR
DESTDIR = $(BUILDDIR)
endif

.PHONY: builddeb
builddeb:
	# Target: builddeb: Run debuild in each directory to generate .deb
	$(MAKE) -f Makefile.linotp builddeb

.PHONY: deb-install
deb-install: builddeb
	# Target: deb-install - move the built .deb, .changes and related files into an archive directory and
	# generate Packages file
	mkdir -pv $(DESTDIR)
	cp $(BUILDDIR)/*.deb $(DESTDIR)
	find $(BUILDDIR) -type f -regex '.+\.changes' -o -regex '.+\.dsc' -o \
						 -regex '.+\.tar\..+' -o -regex '.+\.buildinfo' | \
						 xargs -iXXX -n1 cp XXX $(DESTDIR)
	find $(DESTDIR)
	cd $(DESTDIR) && dpkg-scanpackages -m . > Packages


######################################################################################################
# Docker container targets
#
# These targets are for building and running docker containers
# for integration and builds
#
# Container name | Dockerfile location           | Purpose
# --------------------------------------------------------------------------------------------------
# linotp-builder | docker/Dockerfile.builder-deb | Container ready to build linotp packages
# linotp         |                               | Runs (deb-based) linotp in apache
# selenium-test  | tests/integration             | Run LinOTP Selenium tests against selenium remote
# linotp-unit    | linotp/tests/unit             | Run LinOTP Unit tests
######################################################################################################


# Extra arguments can be passed to docker build
DOCKER_BUILD_ARGS=

# List of tags to add to built linotp images, using the '-t' flag to docker-build
DOCKER_TAGS=latest

# Override to change the mirror used for image building
DEBIAN_MIRROR=deb.debian.org

# Override to change the dependency repository used to install required packages
ifndef DEPENDENCY_DEB_REPO
DEPENDENCY_DEB_REPO=http://www.linotp.org/apt/debian buster linotp
DEPENDENCY_GPG_KEYID=913DFF12F86258E5
endif

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
					--build-arg DEPENDENCY_DEB_REPO="$(DEPENDENCY_DEB_REPO)" \
					--build-arg DEPENDENCY_GPG_KEYID=$(DEPENDENCY_GPG_KEYID) \
					--build-arg DEPENDENCY_GPG_KEY_URL=$(DEPENDENCY_GPG_KEY_URL)

# Default Docker run arguments.
# Extra run arguments can be given here. It can also be used to
# override runtime parameters. For example, to specify a port mapping:
#  make docker-run-linotp-sqlite DOCKER_RUN_ARGS='-p 1234:80'
DOCKER_RUN_ARGS=

DOCKER_BUILD = docker build $(DOCKER_BUILD_ARGS) $(DOCKER_EXTRA_BUILD_ARGS)
DOCKER_RUN = docker run $(DOCKER_RUN_ARGS)

TESTS_DIR=linotp/tests

SELENIUM_TESTS_DIR=$(TESTS_DIR)/integration
UNIT_TESTS_DIR=$(TESTS_DIR)/unit
FUNCTIONAL_TESTS_DIR=$(TESTS_DIR)/functional

## Toplevel targets
# Toplevel target to build all containers
docker-build-all: docker-build-debs docker-build-linotp
docker-build-all: docker-build-linotp-test-image docker-build-linotp-softhsm docker-build-packagetest

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
		-f docker/Dockerfile.builder-deb \
		$(DOCKER_TAG_ARGS) \
		-t $(DOCKER_IMAGE) \
		.

# A unique name to reference containers for this build
DOCKER_CONTAINER_TIMESTAMP := $(shell date +%H%M%S-%N)
NAME_PREFIX := linotpbuilder-$(DOCKER_CONTAINER_TIMESTAMP)
DOCKER_CONTAINER_NAME = $(NAME_PREFIX)
DOCKER_BUILDDIR=$(BUILDDIR)/linotpd.build

.PHONY: docker-build-debs
docker-build-debs: docker-build-linotp-builder
	# Force rebuild of debs
	rm -f $(BUILDDIR)/apt/Packages
	$(MAKE) $(BUILDDIR)/apt/Packages


# Build the debian packages in a container, then extract them from the image
$(BUILDDIR)/apt/Packages:
	# Target: $(BUILDDIR)/apt/Packages:
	$(DOCKER_RUN) \
		--detach \
		--rm \
		--name $(DOCKER_CONTAINER_NAME)-apt \
		linotp-builder \
		sleep 3600

	docker cp . $(DOCKER_CONTAINER_NAME)-apt:/build

	docker exec \
		$(DOCKER_CONTAINER_NAME)-apt \
			make deb-install BUILDDIR=/build/build DESTDIR=/build/apt \
				DEBUILD_OPTS=\"$(DEBUILD_OPTS)\" CI_COMMIT_TAG=$(CI_COMMIT_TAG)

	rm -rf $(BUILDDIR)/apt

	docker cp \
		$(DOCKER_CONTAINER_NAME)-apt:/build/apt $(BUILDDIR)/apt

	docker rm -f $(DOCKER_CONTAINER_NAME)-apt

# Build just the linotp image. The builder-linotp is required but will not be
# built by this target - use 'make docker-linotp' to build the dependencies first
.PHONY: docker-build-linotp
docker-build-linotp: DOCKER_IMAGE=linotp
docker-build-linotp: $(BUILDDIR)/dockerfy $(BUILDDIR)/apt/Packages
	# Target: docker-build-linotp
	mkdir -vp $(DOCKER_BUILDDIR)
	cp docker/Dockerfile.linotp-deb $(DOCKER_BUILDDIR)/Dockerfile
	cp config/*.tmpl \
		linotp/tests/integration/testdata/se_mypasswd \
		$(DOCKER_BUILDDIR)
	cp $(BUILDDIR)/dockerfy $(DOCKER_BUILDDIR)
	cp -r config/docker-initscripts.d $(DOCKER_BUILDDIR)
	cp -r $(BUILDDIR)/apt $(DOCKER_BUILDDIR)

	# We show the files sent to Docker context here to aid in debugging
	find $(DOCKER_BUILDDIR)

	$(DOCKER_BUILD) \
		$(DOCKER_TAG_ARGS) \
		-t $(DOCKER_IMAGE) \
		$(DOCKER_BUILDDIR)

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

# Build packaging test container
.PHONY: docker-build-packagetest
docker-build-packagetest: DOCKER_IMAGE=linotp-packagetest
docker-build-packagetest:
	cd $(TESTS_DIR)/packaging \
	&& $(DOCKER_BUILD) \
		$(DOCKER_TAG_ARGS) \
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

# Run Docker based packaging install/upgrade tests
.PHONY: docker-run-packagetest
docker-run-packagetest:
	cd $(TESTS_DIR)/packaging \
		&& docker-compose \
			run \
			--rm \
			packaging_tester
	cd $(TESTS_DIR)/packaging \
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
	$(DOCKER_RUN) -it \
		 -e HEALTHCHECK_PORT=80 \
		 -e LINOTP_LOG_LEVEL=$(LINOTP_LOG_LEVEL) \
		 -e LINOTP_LOG_CONSOLE_LEVEL=$(LINOTP_LOG_CONSOLE_LEVEL) \
		 -e LINOTP_LOG_LEVEL_DB_CLIENT=$(LINOTP_LOG_LEVEL_DB_CLIENT) \
		 -e APACHE_LOGLEVEL=$(APACHE_LOGLEVEL) \
		linotp

# Dockerfy tool
.PHONY: get-dockerfy
get-dockerfy: $(BUILDDIR)/dockerfy

DOCKERFY_URL=https://github.com/markriggins/dockerfy/releases/download/0.2.6/dockerfy-linux-amd64-0.2.6.tar.gz
DOCKERFY_SHA256=4903afb679e13437398bb89536eb674e741fc0463ee118d945038fe085a8ce4b

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


#
# # Requirements
#
del-reqs:
	rm -f requirements*.txt

reqs: del-reqs requirements.txt requirements-all.txt requirements-dev.txt requirements-prod.txt requirements-test.txt 

requirements.txt: setup.py
	pip-compile \
	--output-file requirements.txt

requirements-all.txt: setup.py
	pip-compile \
	--all-extras  \
	--output-file requirements-all.txt

requirements-dev.txt: setup.py
	pip-compile \
	--output-file requirements-dev.txt \
	--extra develop

requirements-prod.txt: setup.py
	pip-compile \
	--output-file requirements-prod.txt \
	--extra prod

requirements-test.txt: setup.py
	pip-compile \
	--output-file requirements-test.txt \
	--extra test
