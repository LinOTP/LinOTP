#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP userid resolvers.
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
This module implements the communication interface for resolving user
info to the user base:

UserIdResolver Interface class.

Defines the rough interface for a UserId Resolver

== a UserId Resolver is required to resolve the
   Login Name to an unique User Identifier

- for /etc/passwd this will be the uid
- for ldap this might be the DN
- for SQL the unique index ( what's the right name here (tm))

"""

import logging
from collections.abc import Callable
from typing import Any

from linotp.lib.type_utils import boolean

log = logging.getLogger(__name__)


class ResolverLoadConfigError(Exception):
    pass


class ResolverNotAvailable(Exception):
    pass


ResParamsType = dict[str, tuple[bool, str | bool | int | None, Callable[[Any], Any]]]


class UserIdResolver:
    fields = {
        "username": 1,
        "userid": 1,
        "description": 0,
        "phone": 0,
        "mobile": 0,
        "email": 0,
        "givenname": 0,
        "surname": 0,
        "gender": 0,
    }
    name = ""
    id = ""

    critical_parameters: list[str] = []
    crypted_parameters: list[str] = []
    resolver_parameters: ResParamsType = {"readonly": (False, False, boolean)}

    def __init(self):
        """
        init - usual bootstrap hook
        """
        self.name = "UserIdResolver"

    def close(self):
        """
        Hook to close down the resolver after one request
        """
        return

    @classmethod
    def is_change_critical(cls, new_params, previous_params):
        """
        check if the parameter update are 'critical' and require
        a re-authentication

        :param new_params: the set of new parameters
        :param previous_params: the set of previous parameters

        :return: boolean
        """

        for crit in cls.critical_parameters:
            if new_params.get(crit, "") != previous_params.get(crit, ""):
                return True

        return False

    @classmethod
    def primary_key_changed(cls, new_params, previous_params):
        """
        check if the parameter update are 'critical' and require
        a re-authentication

        :param new_params: the set of new parameters
        :param previous_params: the set of previous parameters

        :return: boolean
        """

        return False

    @classmethod
    def merge_crypted_parameters(cls, new_params, previous_params):
        params = {}

        for crypt in cls.crypted_parameters:
            if crypt in previous_params and not new_params.get(crypt):
                params[crypt] = previous_params[crypt]

        return params

    @classmethod
    def missing_crypted_parameters(cls, new_params):
        """
        detect, which encrypted parameters are missing

        :param new_params: the set of new parameters
        :param previous_params: the set of previous parameters

        :return: list of missing parameters
        """
        return [
            crypt for crypt in cls.crypted_parameters if new_params.get(crypt) is None
        ]

    @classmethod
    def getResolverClassType(cls):
        """
        provide the resolver type for registration
        """
        return "UserIdResolver"

    def getResolverType(self):
        """
        getResolverType - return the type of the resolver

        :return: returns the string 'ldapresolver'
        :rtype:  string
        """
        return "UserIdResolver"

    @classmethod
    def getResolverClassDescriptor(cls):
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor["clazz"] = "useridresolver.UserIdResolver"
        descriptor["config"] = {}
        return {typ: descriptor}

    def getResolverDescriptor(self):
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        return UserIdResolver.getResolverClassDescriptor()

    def getUserId(self, loginName):
        """getUserId(LoginName)
        - returns the identifier string
        - empty string if not exist

        """
        return self.id

    def getUsername(self, userid):
        """
        getUsername(LoginId)
          - returns the loginname string
          - empty string if not exist

        """

        return self.name

    def getUserInfo(self, userid):
        """
        This function returns all user information for a given user object
        identified by UserID.

        :return:  dictionary, if no object is found, the dictionary is empty
        """
        return ""

    def getUserList(self, search_dict):
        """
        This function finds the user objects,
        that have the term 'value' in the user object field 'key'

        :param searchDict:  dict with key values of user attributes -
                    the key may be something like 'loginname' or 'email'
                    the value is a regular expression.

        :return: list of dictionaries (each dictionary contains a
                 user object) or an empty string if no object is found.
        """
        return [{}]

    def getResolverId(self):
        """
        get resolver specific information
        :return: the resolver identifier string - empty string if not exist
        """
        return self.name

    @classmethod
    def filter_config(cls, config, conf=""):
        """
        build a dict with the parameters of the resolver

        the config could either be a linotp config object or a local dictionary
        which is used to check if all required parameters are correctly set

        - we have to support as well linotp global config entries, which are
          indicated by starting with a 'linotp.' prefix. Example is the
          linotp.use_system_certs, which is used in the ldap resolver

        to support the variations of key, an list of search keys is build. for
        each of these keys a lookup in the config is made.

        :param config: the config which is provided during runtime of the
                       resolver loading and while testconnection
        :param conf: the resolver name and configuration identifier

        :return: tuple with the dictionary with the filtered entries and the
                 list of missing parameters
        """

        l_config = {}
        missing = []

        # ------------------------------------------------------------------ --

        # filtering in the provided config for the resolver required parameters

        for key, attr in list(cls.resolver_parameters.items()):
            required, default, typ = attr

            search_keys = [key]

            if "linotp." in key:
                ext_key = ".".join(key.split(".")[1:])
                search_keys.append(ext_key)

            else:
                ext_key = f"linotp.{cls.getResolverClassType()}.{key}.{conf}"

                search_keys.append(ext_key)

            for search_key in search_keys:
                if search_key in config:
                    l_config[key] = typ(config.get(search_key))
                    break

            if key not in l_config:
                if required:
                    missing.append(key)
                else:
                    l_config[key] = typ(default)

        # we show the readonly attribute only, if it is True

        if "readonly" in l_config and not l_config["readonly"]:
            del l_config["readonly"]

        return l_config, missing

    def loadConfig(self, config, conf):
        return self

    def checkPass(self, uid, password):
        """
        This function checks the password for a given uid.
        - returns true in case of success
        -         false if password does not match
        """
        return False


def getResolverClass(packageName, className):
    """
    helper method to load the UserIdResolver class from a given
    package in literal. Checks, if the getUserId method exists,
    if not an error is thrown

    example:

        getResolverClass("PasswdIdResolver", "IdResolver")()

    :param packageName: the name package + module
    :param className: the name of the class, which should be loaded

    :return: the class object
    """
    mod = __import__(packageName, globals(), locals(), [className], 1)
    klass = getattr(mod, className)
    ret = ""
    attribute = ""
    try:
        attrs = [
            "getUserId",
            "getUsername",
            "getUserInfo",
            "getUserList",
            "checkPass",
            "loadConfig",
            "getResolverId",
            "getResolverType",
            "getResolverDescriptor",
        ]

        for att in attrs:
            attribute = att
            getattr(klass, att)
        ret = klass
    except BaseException as exx:
        msg = f"IdResolver AttributeError: {packageName}.{className} instance has no attribute '{attribute}'"
        raise NameError(msg) from exx

    return ret
