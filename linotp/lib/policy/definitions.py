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
""" static policy definitions """


from typing import Dict

from linotp.lib.context import request_context

SYSTEM_ACTIONS = {
    "setDefault": "write",
    "setConfig": "write",
    "delConfig": "write",
    "getConfig": "read",
    "getRealms": "read",
    "delResolver": "write",
    "getResolver": "read",
    "setResolver": "write",
    "getResolvers": "read",
    "setDefaultRealm": "write",
    "getDefaultRealm": "read",
    "setRealm": "write",
    "delRealm": "write",
    "setPolicy": "write",
    "importPolicy": "write",
    "policies_flexi": "read",
    "getPolicy": "read",
    "getPolicyDef": "read",
    "checkPolicy": "read",
    "delPolicy": "write",
    "setSupport": "write",
    "setProvider": "write",
    "setDefaultProvider": "write",
    "delProvider": "write",
    "testProvider": "read",
    "getProvider": "read",
}

POLICY_DEFINTIONS = {
    "admin": {
        "enable": {"type": "bool"},
        "disable": {"type": "bool"},
        "set": {"type": "bool"},
        "setOTPPIN": {"type": "bool"},
        "setMOTPPIN": {"type": "bool"},
        "setSCPIN": {"type": "bool"},
        "resync": {"type": "bool"},
        "reset": {"type": "bool"},
        "assign": {"type": "bool"},
        "unassign": {"type": "bool"},
        "import": {"type": "bool"},
        "remove": {"type": "bool"},
        "userlist": {"type": "bool"},
        "tokenowner": {"type": "bool"},
        "token_method": {"type": "bool"},
        "checkstatus": {"type": "bool"},
        "manageToken": {"type": "bool"},
        "getserial": {"type": "bool"},
        "copytokenpin": {"type": "bool"},
        "copytokenuser": {"type": "bool"},
        "losttoken": {"type": "bool"},
        "totp_lookup": {"type": "bool"},
        "getotp": {
            "type": "bool",
            "desc": "allow the administrator to retrieve "
            "OTP values for tokens.",
        },
        "show": {"type": "bool"},
        "unpair": {"type": "bool"},
    },
    "gettoken": {
        "max_count_dpw": {"type": "int"},
        "max_count_hotp": {"type": "int"},
        "max_count_totp": {"type": "int"},
    },
    "selfservice": {
        "assign": {
            "type": "bool",
            "desc": "The user is allowed to assign an existing "
            "token using the token serial number.",
        },
        "disable": {"type": "bool"},
        "enable": {"type": "bool"},
        "delete": {"type": "bool"},
        "unassign": {"type": "bool"},
        "resync": {"type": "bool"},
        "verify": {"type": "bool"},
        "reset": {
            "type": "bool",
            "desc": "Allow to reset the failcounter of a token.",
        },
        "setOTPPIN": {"type": "bool"},
        "setDescription": {"type": "bool"},
        "setMOTPPIN": {"type": "bool"},
        "getotp": {"type": "bool"},
        "otp_pin_maxlength": {"type": "int", "value": list(range(0, 100))},
        "otp_pin_minlength": {"type": "int", "value": list(range(0, 100))},
        "otp_pin_contents": {"type": "str"},
        "webprovisionGOOGLE": {"type": "bool"},
        "webprovisionGOOGLEtime": {"type": "bool"},
        "max_count_dpw": {"type": "int"},
        "max_count_hotp": {"type": "int"},
        "max_count_totp": {"type": "int"},
        "history": {
            "type": "bool",
            "desc": "Allow the user to view his own token history",
        },
        "getserial": {
            "type": "bool",
            "desc": "Allow to search an unassigned token by OTP value.",
        },
        "mfa_login": {
            "type": "bool",
            "desc": "Requires OTP for selfservice authentication",
        },
        "mfa_3_fields": {
            "type": "bool",
            "desc": "optional OTP for selfservice authentication",
        },
        "mfa_passOnNoToken": {
            "type": "bool",
            "desc": (
                "support mfa login if user has no token with password only"
            ),
        },
        "show_landing_page": {
            "type": "bool",
            "desc": "show selfservice landing page as first tab",
        },
        "footer_text": {
            "type": "str",
            "desc": "Text to show on the selfservice page in the footer"
            "section. Replaces the LinOTP copyright notice",
        },
        "imprint_url": {
            "type": "str",
            "desc": "URL to link to an imprint page",
        },
        "privacy_notice_url": {
            "type": "str",
            "desc": "URL to link to a privacy notice page",
        },
    },
    "system": {
        "read": {"type": "bool"},
        "write": {"type": "bool"},
    },
    "enrollment": {
        "tokencount": {
            "type": "int",
            "desc": "Limit the number of tokens in a realm.",
        },
        "maxtoken": {
            "type": "int",
            "desc": "Limit the number of tokens a user in the realm may "
            "have assigned.",
        },
        "otp_pin_random": {"type": "int", "value": list(range(0, 100))},
        "otp_pin_random_content": {
            "type": "string",
            "desc": "The contents of the temporary password, "
            "described by the characters C, c, n, s.",
        },
        "otp_pin_encrypt": {"type": "int", "value": [0, 1]},
        "tokenlabel": {
            "type": "str",
            "desc": "the label for the google authenticator.",
        },
        "tokenissuer": {
            "type": "str",
            "desc": "the issuer label for the google authenticator.",
        },
        "autoenrollment": {
            "type": "str",
            "desc": "users can enroll a token just by using the "
            "pin to authenticate and will an otp for authentication",
        },
        "autoassignment_forward": {
            "type": "bool",
            "desc": "in case of an autoassignement with a remotetoken, "
            "the credentials are forwarded",
        },
        "autoassignment_from_realm": {
            "type": "str",
            "desc": "define the src realm, where the unassigned tokens "
            "should be taken from",
        },
        "autoassignment_without_password": {
            "type": "bool",
            "desc": "users can assign a token just by using the "
            "unassigned token to authenticate providing the "
            "otp value only.",
        },
        "autoassignment": {
            "type": "bool",
            "desc": "users can assign a token just by using the "
            "unassigned token to authenticate.",
        },
        "ignore_autoassignment_pin": {
            "type": "bool",
            "desc": "Do not set password from auto assignment as token pin.",
        },
        "lostTokenPWLen": {
            "type": "int",
            "desc": "The length of the password in case of "
            "temporary token.",
        },
        "lostTokenPWContents": {
            "type": "str",
            "desc": "The contents of the temporary password, "
            "described by the characters C, c, n, s.",
        },
        "lostTokenValid": {
            "type": "set",
            "value": ["int", "duration"],
            "desc": "The length of the validity for the temporary "
            'token as days or duration with "d"-days, "h"-hours,'
            ' "m"-minutes, "s"-seconds.',
        },
        "purge_rollout_token": {
            "type": "bool",
            "desc": (
                "After a successfull login with a second token, the"
                "rollout token is removed."
            ),
        },
    },
    "notification": {
        "autoenrollment": {
            "type": "str",
            "description": ("provider to be used for enrollment notification"),
        },
        "enrollment": {
            "type": "str",
            "description": ("provider to be used for enrollment notification"),
        },
        "setPin": {
            "type": "str",
            "description": ("provider to be used for setPin notification"),
        },
    },
    "authentication": {
        "delete_on_authentication_exceed": {
            "type": "bool",
            "desc": (
                "should the token be deleted if maximum "
                "authentication count was reached"
            ),
        },
        "disable_on_authentication_exceed": {
            "type": "bool",
            "desc": (
                "should the token be disabled if maximum "
                "authentication count was reached"
            ),
        },
        "voice_provider": {
            "type": "str",
            "desc": "The voice provider that should be used to "
            "send voice notifications",
        },
        "push_provider": {
            "type": "str",
            "desc": "The push provider that should be used to "
            "send push notifications",
        },
        "email_provider": {
            "type": "str",
            "desc": "The email provider that should be used to send emails",
        },
        "sms_provider": {
            "type": "str",
            "desc": "The sms provider that should be used to submit sms",
        },
        "trigger_sms": {
            "type": "bool",
            "desc": "should it be possible to trigger a sms challenge"
            "by check_s",
        },
        "smstext": {
            "type": "str",
            "desc": "The text that will be send via SMS for an SMS token. "
            "Use <otp> and <serial> as parameters.",
        },
        "enforce_smstext": {
            "type": "bool",
            "desc": 'if swith enforce_smstext, the challenge "data" is '
            "ignored ignored if smstext is set",
        },
        "otppin": {
            "type": "set",
            "value": [
                0,
                1,
                2,
                3,
                "token_pin",
                "password",
                "only_otp",
                "ignore_pin",
            ],
            "desc": "either use the Token PIN (0=token_pin), "
            "use the Userstore Password (1=password),"
            "use no fixed password component (2=only_otp) or"
            "ignore the pin/password (3=ignore_pin).",
        },
        "autosms": {
            "type": "bool",
            "desc": "if set, a new SMS OTP will be sent after "
            "successful authentication with one SMS OTP",
        },
        "passthru": {
            "type": "bool",
            "desc": "If set, the user in this realm will be authenticated "
            "against the UserIdResolver, if the user has no "
            "tokens assigned.",
        },
        "forward_server": {
            "type": "str",
            "desc": "If set, the users authentication request will be "
            "forwarded to another linotp or radius server.",
        },
        "forward_on_no_token": {
            "type": "bool",
            "desc": "the authentication request of the user will be"
            "forwarded, if the user has no token",
        },
        "passOnNoToken": {
            "type": "bool",
            "desc": "if the user has no token, the authentication request "
            "for this user will always be true.",
        },
        "qrtanurl": {
            "type": "str",
            "desc": "The URL for the half automatic mode that should be "
            "used in a QR Token",
        },
        "qrtanurl_init": {
            "type": "str",
            "desc": "The URL for rollout in the half automatic mode that "
            "should be used in a QR Token rollout.",
        },
        "challenge_response": {
            "type": "str",
            "desc": "A list of tokentypes for which challenge response "
            "should be used.",
        },
        "qrtoken_pairing_callback_url": {
            "type": "str",
            "desc": "The url the pairing response should be send to",
        },
        "qrtoken_pairing_callback_sms": {
            "type": "str",
            "desc": "The phone number the pairing response should "
            "be send to",
        },
        "qrtoken_challenge_callback_url": {
            "type": "str",
            "desc": "The url the challenge response should be send to",
        },
        "qrtoken_challenge_callback_sms": {
            "type": "str",
            "desc": "The sms number the challenge response should "
            "be send to",
        },
        "qrtoken_pairing_cert": {
            "type": "str",
            "desc": "Signifies the certificate id that should be used "
            "during pairing. If it is not set, the system will "
            "assume that pairing should be done without a "
            "certificate.",
        },
        "support_offline": {
            "type": "set",
            "value": ["qr", "u2f"],  # TODO: currently hardcoded
            "desc": "The token types that should support offline "
            "authentication",
        },
    },
    "authorization": {
        "authorize": {
            "type": "bool",
            "desc": "The user/realm will be authorized to login "
            "to the clients IPs.",
        },
        "tokentype": {
            "type": "str",
            "desc": "The user will only be authenticated with this "
            "very tokentype.",
        },
        "serial": {
            "type": "str",
            "desc": "The user will only be authenticated if the serial "
            "number of the token matches this regexp.",
        },
        "setrealm": {
            "type": "str",
            "desc": "The Realm of the user is set to this very realm. "
            "This is important if the user is not contained in "
            "the default realm and can not pass his realm.",
        },
        "detail_on_success": {
            "type": "bool",
            "desc": "In case of successful authentication additional "
            "detail information will be returned.",
        },
        "detail_on_fail": {
            "type": "bool",
            "desc": "In case of failed authentication additional "
            "detail information will be returned.",
        },
    },
    "audit": {"view": {"type": "bool"}},
    "tools": {
        "migrate_resolver": {
            "type": "bool",
            "desc": "Support the migration of assigned tokens to "
            "a new resolver ",
        },
        "import_users": {
            "type": "bool",
            "desc": "Import users from a file into a new resolver ",
        },
    },
    "monitoring": {
        "config": {
            "type": "bool",
            "desc": "Allow to see basic configuratiuon",
        },
        "license": {"type": "bool", "desc": "Allow to check the license"},
        "storageEncryption": {
            "type": "bool",
            "desc": "Allow to check if encryption works",
        },
        "tokens": {
            "type": "bool",
            "desc": "Allow to see number of tokens in realms",
        },
        "userinfo": {
            "type": "bool",
            "desc": "Allow to get information on user-id-resolvers",
        },
        "activeUsers": {
            "type": "bool",
            "desc": "Allow to get information on active user count",
        },
    },
    "reporting": {
        "token_total": {
            "type": "bool",
            "desc": "Report total number of tokens",
        },
        "token_user_total": {
            "type": "bool",
            "desc": "Report total number of token users",
        },
        "token_status": {
            "type": "str",
            "desc": "Report number of tokens which are in-/active,un-/assigned"
            ' or combinations of these concatenatet with "&"',
        },
    },
    "reporting.access": {
        "maximum": {"type": "bool"},
        "period": {"type": "bool"},
        "delete_all": {"type": "bool"},
        "delete_before": {
            "type": "bool",
            "desc": "Delete all reporting entries before given date."
            'Date must be geiven as "yyyy-mm-dd"',
        },
        "show": {"type": "bool"},
    },
}


def get_policy_definitions(scope: str = None) -> Dict:
    """cache the policy definitions access in the local request context.

    as the evaluation of the policy definition is resource intensive we cache
    the outcome on a per request base.

    :param scope: select only a scope of the definitions
    :return: the policy definition dict

    :sideeffect: the local request context is extendend by the dict of the
                 policy definitions. As they are pretty stable, there is no
                 interference expected
    """

    if not request_context["PolicyDefinitions"]:
        request_context["PolicyDefinitions"] = _get_policy_definitions()

    if scope:
        return request_context["PolicyDefinitions"].get(scope, {})

    return request_context["PolicyDefinitions"]


def _get_policy_definitions():
    """
    internal worker, which gathers all policy information in addition to the
    static ones

    :return: the policy definitions of all scopes with the available actions
             in scopes and their action types
    """

    pol = {}
    pol.update(POLICY_DEFINTIONS)

    linotp_config = request_context["Config"]
    oath_support = (
        str(linotp_config.get("linotp.OATHTokenSupport", "False")).lower()
        == "True"
    )

    if oath_support:
        pol["webprovisionOATH"] = {"type": "bool"}

    # --------------------------------------------------------------------- --

    # now add generic policies, which every token should provide:
    # - init<TT>
    # - enroll<TT>, but only, if there is a rendering section

    import linotp.lib.token

    token_type_list = linotp.lib.token.get_token_type_list()

    for ttype in token_type_list:
        pol["enrollment"]["maxtoken%s" % ttype.upper()] = {"type": "int"}

        pol["admin"]["init%s" % ttype.upper()] = {"type": "bool"}

        # ----------------------------------------------------------------- --

        # todo:
        # if all tokens are dynamic, the token init must be only shown
        # if there is a rendering section for:
        # conf = linotp.lib.token.getTokenConfig(ttype, section='init')
        # if len(conf) > 0:
        #    pol['admin']["init%s" % ttype.upper()]={'type': 'bool'}

        conf = linotp.lib.token.getTokenConfig(ttype, section="selfservice")
        if conf and "enroll" in conf:
            pol["selfservice"]["enroll%s" % ttype.upper()] = {
                "type": "bool",
                "desc": "The user is allowed to enroll a %s token." % ttype,
            }

        # ----------------------------------------------------------------- --

        # now merge the dynamic Token policy definition
        # into the global definitions

        policy = linotp.lib.token.getTokenConfig(ttype, section="policy")

        # get all policy sections like: admin, selfservice . . '''

        pol_keys = list(pol.keys())

        for pol_section in list(policy.keys()):
            # if we have a dyn token definition of this section type
            # add this to this section - and make sure, that it is
            # then token type prefixed

            if pol_section in pol_keys:
                pol_entry = policy.get(pol_section)
                for pol_def in pol_entry:
                    set_def = pol_def

                    # check if the token type is already part of
                    # the policy name

                    if ttype.lower() not in set_def.lower():
                        set_def = "%s_%s" % (ttype, pol_def)

                    pol[pol_section][set_def] = pol_entry.get(pol_def)

    return pol
