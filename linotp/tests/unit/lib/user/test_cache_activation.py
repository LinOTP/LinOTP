# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

import pytest
import unittest

from mock import patch


from linotp.lib.user import _get_user_lookup_cache

# from linotp.lib.user import _get_resolver_lookup_cache


class MockedCacheManager(object):
    def get_cache(self, cache_name, type="memory", expiretime=None):
        self.expiretime = expiretime
        return {"cache": "dict"}


mocked_cache_manager = MockedCacheManager()


mocked_context = {
    "Config": {
        "linotp.user_lookup_cache.enabled": "True",
        "linotp.user_lookup_cache.expiration": "1d",
    },
    "CacheManager": mocked_cache_manager,
}


@pytest.mark.usefixtures("app")
class TestCacheActivation(unittest.TestCase):
    @patch("flask.g.request_context", new=mocked_context)
    def test_user_cache_activation(self):

        global mocked_context

        resolver_spec = "linotp.sqlresolver.mysql"

        ret = _get_user_lookup_cache(resolver_spec)
        assert "cache" in ret

        mocked_context["Config"]["linotp.user_lookup_cache.enabled"] = "False"
        mocked_context["Config"]["linotp.user_lookup_cache.expiration"] = "1d"

        ret = _get_user_lookup_cache(resolver_spec)
        assert ret is None

        mocked_context["Config"]["linotp.user_lookup_cache.enabled"] = "True"
        del mocked_context["Config"]["linotp.user_lookup_cache.expiration"]

        ret = _get_user_lookup_cache(resolver_spec)
        assert "cache" in ret

        mocked_cache_manager = mocked_context["CacheManager"]
        assert mocked_cache_manager.expiretime == 36 * 3600

        return
