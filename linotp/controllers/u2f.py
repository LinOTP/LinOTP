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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

"""
U2F controller - interface to the list of valid facets
"""

import json

from linotp.controllers.base import BaseController
from linotp.flap import response
from linotp.lib import deprecated_methods
from linotp.lib.config import getLinotpConfig
from linotp.lib.policy import getPolicy
from linotp.lib.policy.action import get_action_value
from linotp.lib.realm import getDefaultRealm

optional = True
required = False


class U2FController(BaseController):

    """
    This U2F controller can be used by the U2F clients to receive a list of valid facets
    for the specified realm:
        https://server/u2f/realm/valid_facets
    """

    @deprecated_methods(["POST"])
    def valid_facets(self, realm=None):
        """
        Show the JSON output for the valid facets configured by the enrollment
        policy 'u2f_valid_facets'. The form of the JSON output is specified by
        the FIDO Alliance.
        """
        if realm is None:
            realm = getDefaultRealm()

        # Get the valid facets as specified in the enrollment policy 'u2f_valid_facets'
        # for the specific realm
        get_policy_params = {
            "action": "u2f_valid_facets",
            "scope": "enrollment",
            "realm": realm,
        }
        valid_facets_action_value = get_action_value(
            getPolicy(get_policy_params),
            scope="enrollment",
            action="u2f_valid_facets",
            default="",
        )
        # the action value contains the semicolon-separated list of valid
        # facets
        valid_facets = valid_facets_action_value.split(";")

        # Prepare the response
        response.content_type = (
            "application/fido.trusted-­apps+json"  # as specified by FIDO
        )
        response_dict = {
            "trustedFacets": [{"version": {"major": 1, "minor": 0}, "ids": []}]
        }
        for facet in valid_facets:
            facet = facet.strip()
            response_dict["trustedFacets"][0]["ids"].append(facet)
        return json.dumps(response_dict)
