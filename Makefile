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
	if [ -d RELEASE ]; then rm -rf RELEASE; fi


#################
# Targets invoking setup.py
#

# Installation of packages in 'develop mode'.
.PHONY: develop
develop:
	$(PYTHON) setup.py $@



###############################################################################
# Test targets
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


################
# Requirements #
################
del-reqs:
	rm requirements*.txt

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
