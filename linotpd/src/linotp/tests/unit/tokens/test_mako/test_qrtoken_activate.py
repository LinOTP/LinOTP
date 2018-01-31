#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
"""
Tests a very small subset of linotp.lib.reply
"""
import os

from mako.template import Template

from mako.runtime import Context
from StringIO import StringIO

import unittest


def mocked_translate(input_data=None):
    """
    mocked translator - returns input data :)
    """
    return input_data


class TestActivationMako(unittest.TestCase):

    class MyContext(object):
        scope = 'selfservice.activate'
        user = 'me'
        realm = 'home'
        _ = mocked_translate

    def setUp(self):
        os.path.abspath(__file__)
        self.dirname = os.path.dirname(__file__)
        self.lib_token_dir = os.path.abspath(
            os.path.dirname(
                self.dirname + '/../../../../../linotp/tokens/'))

        unittest.TestCase.setUp(self)

    def test_qrtoken_activate(self):

        qrtemplate = Template(
            filename=self.lib_token_dir + '/qrtoken/qrtoken.mako')

        buf = StringIO()
        ctx = Context(buf,
                      c=self.MyContext(),
                      _=mocked_translate)
        _res = qrtemplate.render_context(ctx)
        content = buf.getvalue()
        self.assertTrue("params['user'] = 'me@home';" in content)

        return

    def test_pushtoken_activate(self):

        qrtemplate = Template(
            filename=self.lib_token_dir + '/pushtoken/pushtoken.mako')

        buf = StringIO()
        ctx = Context(buf,
                      c=self.MyContext(),
                      _=mocked_translate)
        _res = qrtemplate.render_context(ctx)
        content = buf.getvalue()
        self.assertTrue("params['user'] = 'me@home';" in content)

        return
