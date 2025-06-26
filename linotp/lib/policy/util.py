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
"""policy processing utilities"""

import logging
from copy import deepcopy

from flask import g

from linotp.lib.context import request_context as context
from linotp.lib.user import getUserRealms

LOG = logging.getLogger(__name__)

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LETTERS = LOWERCASE + UPPERCASE
ASCII_LOWERCASE = LOWERCASE
ASCII_UPPERCASE = UPPERCASE
ASCII_LETTERS = ASCII_LOWERCASE + ASCII_UPPERCASE
DIGITS = "0123456789"
SPECIAL_CHARACTERS = "!#$%&()*+,-./:;<=>?@[]^_"


def _getUserRealms(user):
    return getUserRealms(
        user, allRealms=context["Realms"], defaultRealm=context["defaultRealm"]
    )


def _get_pin_values(config):
    REG_POLICY_C = config.get("linotpPolicy.pin_c", "[a-zA-Z]")
    REG_POLICY_N = config.get("linotpPolicy.pin_n", "[0-9]")
    REG_POLICY_S = config.get("linotpPolicy.pin_s", r"[.:,;-_<>+*!/()=?$§%&#~\^]")

    return REG_POLICY_C, REG_POLICY_N, REG_POLICY_S


def _getAuthenticatedUser():
    """
    replace the 'getUserFromRequest
    """
    return g.authUser


def _getLinotpConfig(config=None):
    lConfig = config
    return lConfig


def get_policies():
    return context["Policies"]


def get_copy_of_policies():
    lPolicies = deepcopy(context["Policies"])
    return lPolicies


def _get_client():
    client = context["Client"]
    return client


def _getUserFromParam():
    user = context["RequestUser"]
    return user


def _getDefaultRealm():
    return context["defaultRealm"]


def _getRealms():
    return context["Realms"]


def are_the_same(dict1, dict2):
    if not dict1 and not dict2:
        return True

    if dict1 and not dict2:
        return False

    if not dict1 and dict2:
        return False

    if len(list(dict1.keys())) != len(list(dict2.keys())):
        return False

    unmatch = set(dict1.keys()) ^ set(dict2.keys())
    if len(unmatch) != 0:
        return False

    return True


def _tokenise_action(action_value, separators=None, escapes=None):
    """
    iterate through the action value and yield
    token if '=' or ',' is reached.
    The tokenization takes care if we are in the string escape
    mode, which is started by the " or the ' sign

    :param action_value: the value of the action
    :param separators: the token separators as list, defaults to '=' and ','
    :param escapes: the text escapes to support value with separators like
                    voice_message="Hello sir, your otp is"
                    defaults to single and double quotes
    :yield: token, which is either string or separator
    """

    # separators are used to split the tokens

    if not separators:
        separators = ["=", ","]

    # escape of literals for text in "

    if not escapes:
        escapes = ['"', "'"]

    start = 0
    escape_mode = []

    i = -1

    for character in action_value:
        i += 1

        # if we recieve a ' or " sign
        # we either start or terminate the string escape mode

        if character in escapes:
            if not escape_mode:
                escape_mode.append(character)
            else:
                if character == escape_mode[-1]:
                    escape_mode.pop()
            continue

        if escape_mode:
            continue

        if character in separators:
            yield action_value[start:i]
            yield character

            start = i + 1

    last_part = action_value[start:]
    if last_part:
        yield last_part


def parse_action(action_value):
    """
    parse_action: yield tuples of key value pairs

    the tokenizer delivers a stream of tokens which could be either
    empty, ',' or '=' or a string. The parser_action iterates through the
    tokens, searching for key value pairs, which are either separated by "="
    or are unary keys, which are of value True

    '"' or "'" surrounded strings are striped

    :param action_value: the value of the action
    :yield: tuple of key and value
    """

    action = []

    for entry in _tokenise_action(f"{action_value},"):
        if entry != ",":  # in case of an ',' the key=value is completed
            action.append(entry)
            continue

        if len(action) == 1:  # boolean value
            key = action[0].strip()
            value = True

            if key.startswith("!"):
                key = key[1:]
                value = False

        elif len(action) > 2:  # key=value pair
            key = action[0].strip()
            value = "".join(action[2:]).strip()

            # if case of an escaped string, remove the sourounding " or '
            if "'" in value or '"' in value:
                value = _strip_quotes(value)

        if isinstance(value, str) and value.lower() == "false":
            value = False

        if key:
            yield key, value

        action = []

    if action:
        msg = f"non terminated action {action!r}"
        raise Exception(msg)

    return


def _strip_quotes(value):
    """
    remove surrounding quotes if possible

    valid: "'a = b '"
    invalid: "'a=b' 'c=d'"

    """
    # make sure that if it starts with a quote and
    for quote in ["'", '"']:
        if (value.startswith(quote) and not value.endswith(quote)) or (
            not value.startswith(quote) and value.endswith(quote)
        ):
            if quote not in value[1:-1]:
                msg = f"non terminated string value entry {value!r}"
                raise Exception(msg)

    for quote in ["'", '"']:
        if value.startswith(quote) and value.endswith(quote):
            if quote not in value[1:-1]:
                value = value.strip(quote)

    return value


def parse_action_value(action_value):
    """
    build up a dictionary from the tuples returned from the parse action
    :param action_value:
    :return: dict of all key and values
    """
    params = {}

    for key, value in parse_action(action_value):
        if key in params and params[key] != value:
            msg = f"duplicate key definition {key!r}"
            raise Exception(msg)

        params[key] = value

    return params


def split_value(policy, attribute="client", marks=False):
    """
    This function returns the parameter "client" or "user" in
    a policy as an array

    """
    attrs = policy.get(attribute, "")
    if attrs == "None" or attrs is None:
        attrs = ""

    attrs_array = []
    if marks:
        attrs_array = [
            co.strip()[:-1]
            for co in attrs.split(",")
            if len(co.strip()) and co.strip()[-1] == ":"
        ]
    else:
        attrs_array = [
            co.strip()
            for co in attrs.split(",")
            if len(co.strip()) and co.strip()[-1] != ":"
        ]

    # if for some reason the first element is empty, delete it.
    if len(attrs_array) and attrs_array[0] == "":
        del attrs_array[0]
    return attrs_array


def get_realm_from_policies(policies):
    """
    get all the realms from the policies:

    :param policies: the dict of all policies
    :param lowerRealms: bool - realm comparison should be/ be not case sensitiv

    :return: tuple of resolves and realms
    """
    realms = set()

    for _pol, val in list(policies.items()):
        pol_realm = val.get("realm", "") or ""
        pol_realms = [x.strip() for x in pol_realm.split(",")]
        realms.update(pol_realms)

    return list(realms)


def get_resolvers_for_realms(realms):
    """
    get resolvers from realms

    :param realms: the list of all realms
    :return: list of resolvers
    """

    resolvers = set()

    all_realms = context["Realms"]

    for realm in realms:
        if realm in all_realms:
            realm_conf = all_realms[realm]
            for resolver in realm_conf["useridresolver"]:
                resolvers.add(resolver.strip(" "))

    return list(resolvers)


def parse_policies(lConfig):
    """
    parse all policie defintions in the config into one policy dict

    :param lconfig: the linotp config dict
    :return: dict with all policies of the config
    """
    Policies = {}
    for entry in lConfig:
        if entry.startswith("linotp.Policy."):
            # log.debug("[getPolicy] entry: %s" % entry )
            policy = entry.split(".", 4)
            if len(policy) == 4:
                name = policy[2]
                key = policy[3]
                value = lConfig.get(entry)

                # prepare the value to be at least an empty string
                if (
                    key in ("user", "client", "realm", "time") and value is None
                ) or value.strip() == "None":
                    value = ""

                if key == "realm":
                    value = value.lower()

                if name in Policies:
                    Policies[name][key] = value
                else:
                    Policies[name] = {key: value}

    #
    # we make here some assumptions explicit:
    #  "empty values are treated as wildcards"
    # by replacing these empty values by '*'

    for _name, policy in sorted(Policies.items()):
        # time has not been used before, so we can define the empty as wildcard

        if "time" in policy and policy["time"] == "":
            policy["time"] = "* * * * * *;"

        if "active" not in policy:
            policy["active"] = True

        if "active" in policy and policy["active"] == "":
            policy["active"] = True

        if "scope" in policy and policy["scope"] in [
            "selfservice",
            "admin",
            "enrollment",
            "authorization",
            "authentication",
        ]:
            if "user" in policy and policy["user"] == "":
                policy["user"] = "*"
            if "client" in policy and policy["client"] == "":
                policy["client"] = "*"

    return Policies
