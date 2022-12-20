# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2019 KeyIdentity GmbH
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
import unittest
import importlib

from mock import mock

from linotp.config.routing import make_map

class TestCustomStyleMap(unittest.TestCase):

    def setUp(self):
        super(TestCustomStyleMap, self).setUp()
        self.routeMap = make_map({}, {})

    def get_route_for_controller(self, controller):
        match = self.routeMap.match('/custom/%s-style.css' % controller)
        return match

    def check_style_route_for_controller(self, controller):
        match = self.get_route_for_controller(controller)
        self.assertEquals(match['action'], 'custom_style')
        self.assertEquals(match['controller'], controller)

    def check_style_response_for_controller(self, name):
        module = 'linotp.controllers.%s' % name
        imported_module = importlib.import_module(module)
        # importlib.import_module

        expected_headers = {
            'Content-type': 'text/css'
        }

        # selfservice -> SelfserviceController
        controller_name = name.capitalize() + 'Controller'

        returned_headers = {}

        with mock.patch(module + '.BaseController.__init__', return_value=None), \
                mock.patch(module + '.response') as mock_response:

            mock_response.headers = returned_headers
            test_controller = getattr(imported_module, controller_name)()

            body = test_controller.custom_style()

            self.assertDictEqual(returned_headers, expected_headers)
            self.assertEquals(body, '')

    def check_controller(self, controller):
        """
        Check for
        * Custom style route to /custom/{name}-style.css
        * Handler returns blank CSS response
        """
        self.check_style_route_for_controller(controller)
        self.check_style_response_for_controller(controller)

    def test_selfservice_custom_style_route(self):
        self.check_controller('selfservice')

    def test_manage_custom_style_route(self):
        self.check_controller('manage')

    def test_openid_custom_style_route(self):
        self.check_controller('openid')

    def test_admin_custom_style_route(self):
        "Check admin controller does not have its own custom style route"
        match = self.get_route_for_controller('admin')
        self.assertIsNone(match)
