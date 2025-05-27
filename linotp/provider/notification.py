# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
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
"""
provider notification handling
"""

import logging

import linotp.lib.policy
from linotp.lib.context import request_context
from linotp.lib.policy.action import get_action_value

log = logging.getLogger(__name__)


class NotificationException(Exception):
    pass


def notify_user(user, action, info, required=False):
    """
    notify user via email, sms or other method (http/whatsapp...)

    :param user: the user who should be notified
    :param action: action is currently the notification action like
                   enrollment, setPin, which are defined in the
                   notification policies
    :param info: generic dict which is action specific
    :param required: if True an exception is raised if no notification could
                     be send eg if no provider is defined or could be found

    :return: boolean - true if notification is enabled
    """

    policies = linotp.lib.policy.get_client_policy(
        request_context["Client"],
        scope="notification",
        action=action,
        realm=user.realm,
        user=user.login,
    )

    provider_specs = get_action_value(
        policies, scope="notification", action=action, default=""
    )

    if not isinstance(provider_specs, list):
        provider_specs = [provider_specs]

    # TODO: use the ResouceSchduler to handle failover

    for provider_spec in provider_specs:
        provider_type, _sep, provider_name = provider_spec.partition("::")

        if provider_type == "email":
            notify_user_by_email(provider_name, user, action, info)
            return True

        # elif provider_type == 'sms':
        #    notify_user_by_email(provider_name, user, action, info)

    log.info("Failed to notify user %r", user)

    if required:
        raise NotificationException(
            "No notification has been sent - %r provider defined?" % action
        )

    return False


def notify_user_by_email(provider_name, user, action, info):
    """
    notify user via email

    :param provider_name: the name of the provider that should be used
    :param user: the user who should be notified
    :param action: action is currently the notification action like
                   enrollment, setPin, which are defined in the
                   notification policies
    :param info: generic dict which is action specific
    """
    user_detail = user.getUserInfo()
    if "cryptpass" in user_detail:
        del user_detail["cryptpass"]

    user_email = user_detail.get("email")
    if not user_email:
        raise NotificationException(
            "Unable to notify user via email - user has no email address"
        )

    replacements = {}
    replacements.update(info)
    replacements.update(user_detail)

    # --------------------------------------------------------------------- --

    # we need to define the loadProvider from here as this module is loaded
    # during a dynamic module which is detected as a recursive load and
    # therefore gives an error on server start

    from . import loadProvider

    try:
        provider = loadProvider("email", provider_name=provider_name)

        provider.submitMessage(
            email_to=user_email,
            message=info.get("message", ""),
            subject=info.get("Subject", ""),
            replacements=replacements,
        )

    except Exception as exx:
        log.error("Failed to notify user %r by email", user_email)
        raise NotificationException(
            "Failed to notify user %r by email:%r" % (user_email, exx)
        )


# eof
