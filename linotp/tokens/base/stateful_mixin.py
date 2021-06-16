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


"""
    A mixin used by token types that have different
    rollout states (e.g. QRToken and OCRA2)
"""

import logging

from linotp.lib.error import TokenStateError

log = logging.getLogger(__name__)


class StatefulTokenMixin(object):

    """
    A mixin used by token types that have different
    rollout states (e.g. QRToken and OCRA2)
    """

    @property
    def current_state(self):
        """signifies the current state of the token"""

        current_state_id = self.getFromTokenInfo("state")
        return current_state_id

    def ensure_state(self, state_id):
        """
        a barrier method to ensure that a token has a certain state.

        :param state_id: The state the token has to be in
        :raises TokenStateError: If state_id is different from the
            current state of this token
        """

        self.ensure_state_is_in([state_id])

    def ensure_state_is_in(self, valid_state_ids):
        """
        a barrier method to ensure that the token state is
        in a list of valid_states

        :param valid_state_ids: A list of allowed states
        :raises TokenStateError: If token state is not in
            the list of valid states
        """

        current_state_id = self.getFromTokenInfo("state")
        if current_state_id not in valid_state_ids:
            raise TokenStateError(
                "Token %r must be in one of the following "
                "states for this action: %s, but current "
                "state is %s"
                % (self, ",".join(valid_state_ids), current_state_id)
            )

    def change_state(self, state_id):
        """
        changes the state of this token

        :param state_id: The new state_id this token should have
        """

        self.addToTokenInfo("state", state_id)


# eof #
