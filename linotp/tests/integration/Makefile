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

# Definition of PYTEST and PYTESTARGS
include ../common-vars.mk

#####################
# Integration test configuration
#
# Overrides can be specified on the make command line
# For example:
#   make integrationtests TCFILE=my_cfg.ini

# The test settings ini file to use. Override to use a different file.
TCFILE=server_cfg.ini

#####################
# Integration test targets
#

test: integrationtests

integrationtests:
	# integrationtests - selenium integration tests
	$(PYTEST) $(PYTESTARGS) --tc-file=$(TCFILE) $(TEST_CASE)

integrationtests-bunch1:
	# integrationtests - selenium integration tests
	$(PYTEST) $(PYTESTARGS) --tc-file=$(TCFILE) test_create_useridresolvers.py test_selfservice.py test_token_view.py test_policies.py test_manage.py test_emailtoken.py

integrationtests-bunch2:
	# integrationtests - selenium integration tests
	$(PYTEST) $(PYTESTARGS) --tc-file=$(TCFILE) test_scenario01.py test_yubikey.py test_user_view.py test_system_config.py test_smstoken.py test_auth.py test_realm_dialog.py


.PHONY: test integrationtests
