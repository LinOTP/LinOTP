#!/usr/bin/make -f
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

#####################
# Unit test configuration
#
# Overrides can be specified on the make command line
# For example:
#   make integrationtests TCFILE=my_cfg.ini LOGGINGFILTER=

LINOTPDIR := $(realpath $(PWD)/../../..)

# The test settings ini file to use. Override to use a different file.
TCFILE=$(LINOTPDIR)/functional_tc.ini

# Nosetests arguments
NOSETESTS_ARGS=-v --with-pylons=$(LINOTPDIR)/test.ini

# Additional test arguments can be specified in FUNCTIONALTESTS_ARGS
FUNCTIONALTESTS_ARGS=

# The default log filter does not show debug messages from urllib connections.
# Override this to include them.
LOGGINGFILTER=-requests.packages.urllib3.connectionpool

#####################
# Functional test targets
#

ifdef LOGGINGFILTER
LOGFILTER_ARGS=--logging-filter=${LOGGINGFILTER}
endif

test: functionaltests

functionaltests:
	# functionaltests
	cd $(LINOTPDIR) && nosetests $(NOSETESTS_ARGS) --tc-file=$(TCFILE) $(LOGFILTER_ARGS) $(FUNCTIONALTESTS_ARGS)

.PHONY: test functionaltests
