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

# Common rules for test makefiles
#
# This file is to be included by subdirectory makefiles like this:
#  include ../common-vars.mk

# Executable to run tests against
# this is pytest-3 on plain Debian, but pytest in a pip virtual environment
# By default we autodetect this, but the user can provide an override
PYTEST=

ifndef PYTEST
    # Autodetect pytest binary name. If we are running in a virtual environment,
    # the executable 'pytest' will be on the path. If it is not available,
    # try pytest-3, which is the name of the system installed version
    PYTEST=$(shell which pytest)
    ifeq ($(PYTEST),)
        PYTEST=$(shell which pytest-3)
        ifeq ($(PYTEST),)
            $(error could not find a pytest executable)
        endif
    endif
endif

# Overrides can be specified on the make command line
# For example:
#   make functionaltests PYTESTARGS=-v
PYTESTARGS=

