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
"""static policy definitions"""

import logging

import linotp.lib.token
from linotp.lib.context import request_context
from linotp.lib.policy.util import parse_action
from linotp.lib.type_utils import boolean, parse_duration

log = logging.getLogger(__name__)

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
    "getReportedStatuses": "read",
}

POLICY_DEFINTIONS = {
    "admin": {
        "enable": {"type": "bool"},
        "disable": {"type": "bool"},
        "set": {"type": "bool"},
        "setOTPPIN": {"type": "bool"},
        "setMOTPPIN": {"type": "bool"},
        "setOCRAPIN": {"type": "bool"},
        "resync": {"type": "bool"},
        "reset": {"type": "bool"},
        "assign": {"type": "bool"},
        "unassign": {"type": "bool"},
        "import": {"type": "bool"},
        "remove": {"type": "bool"},
        "userlist": {"type": "bool"},
        "tokenowner": {"type": "bool"},
        "checkstatus": {"type": "bool"},
        "manageToken": {"type": "bool"},
        "getserial": {"type": "bool"},
        "copytokenpin": {"type": "bool"},
        "copytokenuser": {"type": "bool"},
        "losttoken": {"type": "bool"},
        "totp_lookup": {"type": "bool"},
        "getotp": {
            "type": "bool",
            "desc": "allow the administrator to retrieve OTP values for tokens.",
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
        "otp_pin_maxlength": {"type": "int", "value": list(range(100))},
        "otp_pin_minlength": {"type": "int", "value": list(range(100))},
        "otp_pin_contents": {"type": "str"},
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
            "desc": ("support mfa login if user has no token with password only"),
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
            "desc": "Limit the number of tokens a user in the realm may have assigned.",
        },
        "otp_pin_random": {"type": "int", "value": list(range(100))},
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
            "desc": "The length of the password in case of temporary token.",
        },
        "lostTokenPWContents": {
            "type": "str",
            "desc": "The contents of the temporary password, "
            "described by the characters C, c, n, s.",
        },
        "lostTokenValid": {
            "type": ["int", "duration"],
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
            "desc": "The push provider that should be used to send push notifications",
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
            "desc": "should it be possible to trigger a sms challengeby check_s",
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
            # TODO: we can't define a list here as this is a capability which
            # is defined within a token - this should be joined within the
            # _add_dynamic_tokens() call, which queries every token policy
            # definition
            "desc": "A list of tokentypes for which challenge response should be used.",
        },
        "qrtoken_pairing_callback_url": {
            "type": "str",
            "desc": "The url the pairing response should be send to",
        },
        "qrtoken_pairing_callback_sms": {
            "type": "str",
            "desc": "The phone number the pairing response should be send to",
        },
        "qrtoken_challenge_callback_url": {
            "type": "str",
            "desc": "The url the challenge response should be send to",
        },
        "qrtoken_challenge_callback_sms": {
            "type": "str",
            "desc": "The sms number the challenge response should be send to",
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
            "range": ["qr", "u2f", "forward"],  # TODO: currently hardcoded
            "desc": "The token types that should support offline authentication",
        },
    },
    "authorization": {
        "authorize": {
            "type": "bool",
            "desc": "The user/realm will be authorized to login to the clients IPs.",
        },
        "tokentype": {
            "type": "str",
            "desc": "The user will only be authenticated with this very tokentype.",
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
            "desc": "Support the migration of assigned tokens to a new resolver ",
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


def get_policy_definitions(scope: str | None = None) -> dict:
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

    # --------------------------------------------------------------------- --

    # now add generic policies, which every token should provide:
    # - init<TT>
    # - enroll<TT>, but only, if there is a rendering section

    token_type_list = linotp.lib.token.get_token_type_list()

    for ttype in token_type_list:
        pol["enrollment"][f"maxtoken{ttype.upper()}"] = {"type": "int"}

        pol["admin"][f"init{ttype.upper()}"] = {"type": "bool"}

        # ----------------------------------------------------------------- --

        # todo:
        # if all tokens are dynamic, the token init must be only shown
        # if there is a rendering section for:
        # conf = linotp.lib.token.getTokenConfig(ttype, section='init')
        # if len(conf) > 0:
        #    pol['admin']["init%s" % ttype.upper()]={'type': 'bool'}

        conf = linotp.lib.token.getTokenConfig(ttype, section="selfservice")
        if conf and "enroll" in conf:
            pol["selfservice"][f"enroll{ttype.upper()}"] = {
                "type": "bool",
                "desc": f"The user is allowed to enroll a {ttype} token.",
            }

        # ----------------------------------------------------------------- --

        # now merge the dynamic Token policy definition
        # into the global definitions

        policy = linotp.lib.token.getTokenConfig(ttype, section="policy")

        # get all policy sections like: admin, selfservice . . '''

        pol_keys = pol.keys()

        for pol_section, pol_entry in policy.items():
            # if we have a dyn token definition of this section type
            # add this to this section - and make sure, that it is
            # then token type prefixed

            if pol_section in pol_keys:
                for pol_def, pol_value in pol_entry.items():
                    set_def = pol_def

                    # check if the token type is already part of
                    # the policy name
                    if ttype.lower() not in set_def.lower():
                        set_def = f"{ttype}_{pol_def}"

                    pol[pol_section][set_def] = pol_value

    return pol


def validate_policy_definition(policy):
    """
    verify that the to be stored policy values is compliant to
    the policy definitions, describing the action value and type.
    """

    scope = policy["scope"]

    # for legacy ocra and ocra2 scope there is no validation as there
    # is no clear action definition
    if scope in ["ocra", "ocra2"]:
        return

    actions = policy.get("action", {})

    # there are currently some known legacy definitions which are
    # not defined - so we exclude these from raising an exception
    # and skip them

    actions_to_skip = {
        "admin": [
            "*",
            "initETNG",
            "initSPASS",
        ],
        "selfservice": [],
        "system": ["*"],
        "tools": ["*"],
        "audit": ["*"],
        "monitoring": ["*"],
        "getToken": ["*"],
        "reporting.access": ["*"],
    }

    policy_definitions = get_policy_definitions(scope=scope)

    for action, value in parse_action(actions):
        # in the action value validation we only verify actions but not
        # the sub parts as these are used for naming items
        if "." in action:
            action = action.partition(".")[0]

        # if the scope/action is found in the actions_to_skip we skip the
        # validation for this
        if action in actions_to_skip.get(scope, {}):
            log.info(
                "action validation skipped for policy: %r action: %r",
                policy["name"],
                action,
            )
            continue

        # now lookup in the policy definitions of the scope, if the action is
        # defined. All exceptions from the lookup are handled before and we can
        # focus on: 1. lookup, 2. type conversion, 3. value / range comparison
        definition = policy_definitions.get(action)

        # .1. definition lookup
        if not definition:
            log.error(
                "policy: %r uses action %r which is not defined in the policy"
                " definitions!",
                policy["name"],
                action,
            )

            msg = "unsupported policy action {!r} in policy {!r} ".format(
                action, policy["name"]
            )
            raise ValueError(msg)

        # .2. type conversion
        # if there is a policy definition and there is a type declaration
        # we try to convert the value to that type
        if "type" in definition:
            try:
                value = convert_policy_value(value, definition["type"])
            except ValueError as exx:
                msg = (
                    "Action value {!r} for {}.{} not of the expected type {!r}".format(
                        value, scope, action, definition["type"]
                    )
                )
                raise Exception(msg) from exx

        # .3. a "value" comparison:
        # if there is a "value" definition, we have to assur that the value is
        # in the value range or in the set
        if "value" in definition:
            if value not in definition["value"]:
                msg = "Action value {!r} for {}.{} not in supported values {!r}".format(
                    value, scope, action, definition["value"]
                )
                raise Exception(msg)

        # .3. b "range" comparison
        # if there is a "range" definition all provided entries of the action
        # value must be in the range e.g. for "support_offline":
        # the range is ["qr", "u2f", "forward"]. Thus the policy action value
        # might contain ["qr", "forward"]
        elif "range" in definition:
            # normalize the value so that we always deal with the set()
            if not isinstance(value, set):
                value = {value}

            if len(value - set(definition["range"])) != 0:
                msg = "Action value {!r} for {}.{} not in supported range {!r}".format(
                    value, scope, action, definition["range"]
                )
                raise Exception(msg)

    return


def convert_policy_value(value, value_type):
    """
    convert the value to the type definition of the policy

    :return: converted value
    """

    def simple_type_conversion(value, value_type):
        """inner function to convert simple types"""
        if value_type == "bool":
            return boolean(value)

        elif value_type in ["str", "string"]:
            if not isinstance(value, str):
                msg = "value %r is not of type string!"
                raise ValueError(msg)
            return value

        elif value_type == "int":
            return int(value)

        elif value_type == "duration":
            parse_duration(value)

    if isinstance(value_type, list):
        # the value must be of one of these types
        for val_type in value_type:
            try:
                return simple_type_conversion(value, val_type)
            except ValueError:
                pass
        # if we end up here, none of the proposed types could be applied
        log.error("unable to convert value %r to %r", value, val_type)
        msg = f"unable to convert {value!r} to {val_type!r}"
        raise ValueError(msg)

    elif value_type == "set":
        # there is no easy way to deal with a set currently as a set defines
        # one of these value in the 'value' definition and could be of
        # different types
        value_set = set()

        values = value.split(" ")
        for val in values:
            if val.isdecimal():
                # we try to do here an implicit conversion that we need for the
                # otp pin policy which allows ints and strings
                val = int(val)
            value_set.add(val)

        if len(value_set) == 1:
            return next(iter(value_set))

        return value_set

    else:
        # remaining are the simple types like bool string and int ++
        return simple_type_conversion(value, value_type)
