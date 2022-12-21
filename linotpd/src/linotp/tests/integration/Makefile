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

# The test settings ini file to use. Override to use a different file.
TCFILE=server_cfg.ini

# Nosetests arguments
NOSETESTS_ARGS=-v

ifdef TEST_DEBUG
DEBUG_ARGS=-s --pdb
endif

# Additional test arguments can be specified in SELENIUMTESTS_ARGS
SELENIUMTESTS_ARGS=

# The default log filter does not show debug messages from the Selenium connection and urllib connections.
# Override this to include them.
LOGGINGFILTER=-requests.packages.urllib3.connectionpool,-selenium.webdriver.remote.remote_connection

#####################
# Unit test targets
#

ifdef LOGGINGFILTER
LOGFILTER_ARGS=--logging-filter=${LOGGINGFILTER}
endif

test: integrationtests

integrationtests:
	# integrationtests - selenium integration tests
	nosetests $(NOSETESTS_ARGS) --with-flaky --tc-file=$(TCFILE) $(LOGFILTER_ARGS) $(SELENIUMTESTS_ARGS) $(DEBUG_ARGS) $(TEST_CASE)

integrationtests-bunch1:
	# integrationtests - selenium integration tests
	nosetests $(NOSETESTS_ARGS) --with-flaky --tc-file=$(TCFILE) $(LOGFILTER_ARGS) $(SELENIUMTESTS_ARGS) $(DEBUG_ARGS) test_create_useridresolvers.py test_selfservice.py test_token_view.py test_policies.py test_manage.py test_emailtoken.py

integrationtests-bunch2:
	# integrationtests - selenium integration tests
	nosetests $(NOSETESTS_ARGS) --with-flaky --tc-file=$(TCFILE) $(LOGFILTER_ARGS) $(SELENIUMTESTS_ARGS) $(DEBUG_ARGS) test_scenario01.py test_yubikey.py test_user_view.py test_system_config.py test_smstoken.py test_auth.py test_realm_dialog.py


.PHONY: test integrationtests
