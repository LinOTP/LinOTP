#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

"""
Tests the logging decorators
"""

import unittest
import linotp.lib.logs as logs

# ------------------------------------------------------------------------------


class FakeLogger(object):

    def __init__(self, log_level=10):
        self.clear()
        self.log_level = log_level

    def clear(self):
        self.messages = []
        self.extras = []

    def debug(self, message, extra):
        self.messages.append(message)
        self.extras.append(extra)

    def getEffectiveLevel(self):
        return self.log_level

# ------------------------------------------------------------------------------


def func(arg1, arg2):

    return {'list': [arg1, arg2], 'rev_list': [arg2, arg1]}

# ------------------------------------------------------------------------------


class TestLoggingDecorators(unittest.TestCase):

    """
    Unit tests for different logging decorators
    """

    # --------------------------------------------------------------------------

    def test_enter_exit_decorator(self):

        """
        Check if arguments decorated with @log_enter_exit are logged
        """

        fake_logger = FakeLogger()

        # ----------------------------------------------------------------------

        decorated = logs.log_enter_exit(fake_logger)(func)

        returnvalue = decorated(2, 1)

        asserted_returnvalue = {'list': [2, 1], 'rev_list': [1, 2]}
        self.assertEqual(returnvalue, asserted_returnvalue)

        # ----------------------------------------------------------------------

        enter_extras = {
            'type': 'function_enter',
            'function_name': 'func',
            'function_args': (2, 1),
            'function_kwargs': {}
        }

        self.assertEqual(fake_logger.extras[0], enter_extras)

        # ----------------------------------------------------------------------

        exit_extras = {
            'type': 'function_exit',
            'function_name': 'func',
            'function_returnvalue': asserted_returnvalue
        }

        self.assertEqual(fake_logger.extras[1], exit_extras)

    # --------------------------------------------------------------------------

    def test_log_timedelta(self):

        """
        Check if timedelta is logged correctly
        """

        fake_logger = FakeLogger()
        decorated = logs.log_timedelta(fake_logger)(func)
        decorated(2, 1)

        # ----------------------------------------------------------------------

        extras = fake_logger.extras[0]
        self.assertIn('type', extras)
        self.assertIn('function_name', extras)
        self.assertIn('timedelta', extras)

        self.assertEqual(extras['type'], 'function_timedelta')
        self.assertEqual(extras['function_name'], 'func')
        self.assertGreater(extras['timedelta'], 0)
