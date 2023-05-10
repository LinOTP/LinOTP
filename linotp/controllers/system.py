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
system controller - to configure the system
"""
import binascii
import json
import logging
from html import escape

from configobj import ConfigObj
from flask_babel import gettext as _
from werkzeug.datastructures import FileStorage

from flask import current_app, g
from flask import send_file as flask_send_file

from linotp import flap
from linotp.flap import config, request, response
from linotp.flap import tmpl_context as c
from linotp.lib import deprecated_methods
from linotp.lib.config import (
    getFromConfig,
    getLinotpConfig,
    removeFromConfig,
    storeConfig,
    updateConfig,
)
from linotp.lib.context import request_context
from linotp.lib.crypto import utils
from linotp.lib.error import ParameterError
from linotp.lib.policy import (
    PolicyException,
    checkPolicyPre,
    get_client_policy,
    search_policy,
)
from linotp.lib.policy.definitions import get_policy_definitions
from linotp.lib.policy.manage import (
    create_policy_export_file,
    deletePolicy,
    import_policies,
    setPolicy,
)
from linotp.lib.realm import (
    deleteRealm,
    getDefaultRealm,
    getRealms,
    setDefaultRealm,
)
from linotp.lib.reply import sendError, sendResult, sendXMLError, sendXMLResult
from linotp.lib.resolver import (
    defineResolver,
    deleteResolver,
    getResolverInfo,
    getResolverList,
    getResolverObject,
    parse_resolver_spec,
    prepare_resolver_parameter,
)
from linotp.lib.support import (
    do_nagging,
    getSupportLicenseInfo,
    isSupportLicenseValid,
    running_on_appliance,
    setDemoSupportLicense,
    setSupportLicense,
)
from linotp.lib.tools.migrate_resolver import MigrateResolverHandler
from linotp.lib.type_utils import boolean
from linotp.lib.user import (
    delete_realm_resolver_cache,
    delete_resolver_user_cache,
    getUserFromRequest,
    setRealm,
)
from linotp.lib.util import check_session, get_client, getLowerParams
from linotp.model import db
from linotp.model.imported_user import ImportedUser
from linotp.provider import (
    delProvider,
    getProvider,
    loadProvider,
    setDefaultProvider,
    setProvider,
)
from linotp.tokens import tokenclass_registry
from linotp.useridresolver.UserIdResolver import ResolverLoadConfigError

from .base import BaseController, methods

log = logging.getLogger(__name__)


class RemoveForbiddenError(Exception):
    pass


class SystemController(BaseController):

    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server. The SystemController is used to configure the LinOTP
    server. The functions of the SystemController are invoked like this

        https://server/system/<functionname>

    The functions are described below in more detail.
    """

    def __before__(self, **params):
        """
        __before__ is called before every action so we can check the
                   authorization

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:
            g.audit["success"] = False
            g.audit["client"] = get_client(request)

            # check session might raise an abort()
            check_session(request)

            audit = config.get("audit")
            request_context["Audit"] = audit

            # check authorization
            if action not in [
                "_add_dynamic_tokens",
                "setupSecurityModule",
                "getSupportInfo",
                "isSupportValid",
            ]:
                checkPolicyPre("system", action)

            # default return for the __before__ is nothing
            return

        except PolicyException as pex:
            log.error("[__before__::%r] policy exception %r", action, pex)
            db.session.rollback()
            return sendError(response, pex, context="before")

        except flap.HTTPUnauthorized as acc:
            # the exception, when an abort() is called if forwarded
            log.error("[__before__::%r] webob.exception %r", action, acc)
            db.session.rollback()
            raise acc

        except Exception as exx:
            log.error("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(response, exx, context="before")

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        try:
            g.audit["administrator"] = getUserFromRequest()
            current_app.audit_obj.log(g.audit)
            # default return for the __before__ and __after__
            return response

        except Exception as exx:
            log.error("[__after__] exception %r", exx)
            db.session.rollback()
            return sendError(response, exx, context="after")

    ########################################################
    @methods(["POST"])
    def setDefault(self):
        """
        define default settings for tokens

        These default settings are used when new tokens are generated.
        The default settings will not affect already enrolled tokens.


        :param DefaultMaxFailCount:    - Default value for the maximum allowed authentication failures
        :param DefaultSyncWindow:      - Default value for the synchronization window
        :param DefaultCountWindow:     - Default value for the counter window
        :param DefaultOtpLen:          - Default value for the OTP value length - usually 6 or 8
        :param DefaultResetFailCount:  - Default value, if the FailCounter should be reset on successful authentication [True|False]

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        count = 0
        description = "setDefault: parameters are\
        DefaultMaxFailCount\
        DefaultSyncWindow\
        DefaultCountWindow\
        DefaultOtpLen\
        DefaultResetFailCount\
        "
        keys = [
            "DefaultMaxFailCount",
            "DefaultSyncWindow",
            "DefaultCountWindow",
            "DefaultOtpLen",
            "DefaultResetFailCount",
        ]

        try:
            param = getLowerParams(self.request_params)
            log.info(
                "[setDefault] saving default configuration: %r",
                list(param.keys()),
            )

            for k in keys:
                if k.lower() in param:
                    value = param[k.lower()]
                    ret = storeConfig(k, value)
                    des = "set " + k
                    res[des] = ret
                    count = count + 1

                    g.audit["success"] = count
                    g.audit["info"] += "%s=%s, " % (k, value)

            if count == 0:
                log.warning(
                    "[setDefault] Failed saving config. Could not "
                    "find any known parameter. %s",
                    description,
                )
                raise ParameterError("Usage: %s" % description, id=77)

            db.session.commit()
            return sendResult(response, res)

        except Exception as exx:
            log.error("[setDefault] commit failed: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @methods(["POST"])
    def setConfig(self):
        """
        set a configuration key or a set of configuration entries

        parameter could either be in the form key=..&value=..
        or as a set of generic keyname=value pairs.

        .. note:: In case of key-value pairs the type information could be
           provided by an additional parameter with same keyname with the
           postfix ".type". Value could then be 'password' to trigger the
           storing of the value in an encrypted form

        :param key: configuration entry name
        :param value: configuration value
        :param type: type of the value: int or string/text or password
                     password will trigger to store the encrypted value
        :param description: additional information for this config entry

        or

        :param key-value pairs: pair of &keyname=value pairs

        :return: a json result with a boolean "result": true

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        res = {}
        param = self.request_params

        try:
            log.info(
                "[setConfig] saving configuration: %r", list(param.keys())
            )

            if "key" in param:
                key = param["key"]
                val = param.get("value")
                typ = param.get("type")
                des = param.get("description")

                if val is None or key is None:
                    raise ParameterError("Required parameters: value and key")

                ret = storeConfig(key, val, typ, des)
                string = "setConfig %s" % key
                res[string] = ret

                # --------------------------------------------------------- --
                # after successfully storing run the direct config callback

                self._config_callback(key, val)

                # --------------------------------------------------------- --

                g.audit["success"] = True
                g.audit["info"] = "%s=%s" % (key, val)

            else:
                # we gather all key value pairs in the conf dict
                conf = {}
                for key in param:
                    if key == "session":
                        continue

                    val = param.get(key, "") or ""

                    Key = key
                    if not key.startswith("linotp"):
                        Key = "linotp." + key
                    conf[Key] = val

                    string = "setConfig " + key + ":" + val
                    res[string] = True

                    g.audit["success"] = True
                    g.audit["info"] += "%s=%s, " % (key, val)

                updateConfig(conf)

                # --------------------------------------------------------- --
                # after successfully storing run the direct config callback

                for key, val in list(conf.items()):
                    self._config_callback(key, val)

                # --------------------------------------------------------- --

            db.session.commit()
            log.debug(
                "[setConfig] saved configuration: %r", list(param.keys())
            )
            return sendResult(response, res, 1)

        except ValueError as exx:
            log.error("[setConfig] error saving config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

        except Exception as exx:
            log.error("[setConfig] error saving config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    # config callback helper

    def _config_callback(self, key, val):
        """helper to run a direct config change action"""

        f_name = "_" + key.replace(".", "_")

        if hasattr(self, f_name):
            config_action = getattr(self, f_name)
            config_action(val)

    # config callback methods

    def _linotp_user_lookup_cache_enabled(self, state):
        "helper to flush the user lookup cache"

        if boolean(state) is False:
            resolvers = request_context["Resolvers"]

            for resolver in resolvers:
                delete_resolver_user_cache(resolver)

    def _linotp_resolver_lookup_cache_enabled(self, state):
        """helper to flush the resolver lookup cache"""

        if boolean(state) is False:
            realms = request_context["Realms"]

            for realm in realms:
                delete_realm_resolver_cache(realm)

    ########################################################
    @methods(["POST"])
    def delConfig(self):
        """
        delete a configuration key
        if an error occurs an exception is serializedsetConfig and returned

        :param key: configuration key name
        :returns: a json result with the deleted value

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        log.info("[delConfig] with params: %r", self.request_params)

        res = {}

        try:
            if "key" not in self.request_params:
                raise ParameterError("missing required parameter: key")
            key = self.request_params["key"]
            ret = removeFromConfig(key)
            string = "delConfig " + key
            res[string] = ret

            g.audit["success"] = ret
            g.audit["info"] = key

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[delConfig] error deleting config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    ########################################################
    @deprecated_methods(["POST"])
    def getConfig(self):
        """
        retrieve value of a defined configuration key, or if no key is given,
        the complete configuration is returned
        if an error occurs an exception is serialized and returned

        .. note:: the assumption is, that the access to system/getConfig
                  is only allowed to privileged users

        :param key: generic configuration entry name (optional)

        :return: a json result with key value or all key + value pairs

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        res = {}

        try:
            param = self.request_params.copy()
            log.debug("[getConfig] with params: %r", param)

            if "session" in param:
                del param["session"]

            # if there is no parameter, we return them all
            if len(param) == 0:
                conf = getLinotpConfig()
                keys = sorted(conf.keys())
                for key in keys:
                    parts = key.split(".")

                    if parts[0] == "enclinotp":
                        continue

                    if parts[0] == "linotp":
                        Key = key[len("linotp.") :]

                        #
                        # Todo: move the handling of extra data to the
                        #       json reply formatter
                        #

                        typ = type(conf.get(key)).__name__
                        if typ not in ["str", "unicode"]:
                            if typ == "datetime":
                                res[Key] = str(conf.get(key))
                            else:
                                res[Key] = conf.get(key)
                        else:
                            res[Key] = conf.get(key)

                g.audit["success"] = True
                g.audit["info"] = "complete config"

            else:
                if "key" not in param:
                    raise ParameterError("missing required parameter: key")
                key = param["key"]

                #
                # prevent access to the decrypted data
                #

                if key.startswith("enclinotp."):
                    key = "linotp.%s" % key[len("enclinotp.") :]

                ret = getFromConfig(key)
                string = "getConfig " + key
                res[string] = ret

                g.audit["success"] = ret
                g.audit["info"] = "config key %s" % key

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[getConfig] error getting config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @deprecated_methods(["POST"])
    def getRealms(self):
        """
        returns all realm definitinos as a json result.
        :params realm: (optional) a realm name
        :return:
            a json result with a list of Realms

        :raises Exception:
            if an error occurs an exception is serialized and returned


        """

        try:
            log.debug("[getRealms] with params: %r", self.request_params)

            g.audit["success"] = True

            realm_name = self.request_params.get("realm")

            realms = getRealms(realm_name)

            db.session.commit()
            return sendResult(response, realms, 1)

        except PolicyException as pex:
            log.error("[getRealms] policy exception: %r", pex)
            db.session.rollback()
            return sendError(response, pex)

        except Exception as exx:
            log.error("[getRealms] error getting realms: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @methods(["POST"])
    def setResolver(self):
        """

        creates or updates a useridresolver

        :param name: the name of the resolver
        :param type: the type of the resolver [ldapsersolver, sqlresolver]

        for LDAP resolver:
        :param LDAPURI:
        :param LDAPBASE:
        :param BINDDN:
        :param BINDPW:
        :param TIMEOUT:
        :param SIZELIMIT:
        :param LOGINNAMEATTRIBUTE:
        :param LDAPSEARCHFILTER:
        :param LDAPFILTER:
        :param USERINFO:
        :param NOREFERRALS:        - True|False

        for SQL resolver:
        :param Database:
        :param Driver:
        :param Server:
        :param Port:
        :param User:
        :param Password:
        :param Table:
        :param Map:

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params.copy()
        resolver_loaded = False
        msg = _(
            "Unable to instantiate the resolver %r."
            "Please verify configuration or connection!"
        )

        try:
            if "name" not in param:
                raise ParameterError('missing required parameter "name"')

            new_resolver_name = param["name"]
            previous_name = param.get("previous_name", "")

            if "readonly" in param:
                # the default for the readonly attribute is - to not exist :)
                # if it does, the conversion will fail and we raise an
                # exception
                if not param["readonly"]:
                    # remove empty 'readonly' attribute
                    del param["readonly"]
                else:
                    try:
                        boolean(param["readonly"])
                    except Exception as exx:
                        msg = (
                            "Failed to convert attribute 'readonly' to"
                            " a boolean value! %r"
                        )
                        log.error(msg, param["readonly"])
                        raise Exception(msg % param["readonly"])

            if not previous_name:
                mode = "create"
            else:
                if new_resolver_name == previous_name:
                    mode = "update"
                else:
                    mode = "rename"

            log.info(
                "[setResolver] saving configuration %r", list(param.keys())
            )

            #
            # before storing the new resolver, we check if already a
            # resolver with same name exists.
            #
            if (
                mode in ["create", "rename"]
                and new_resolver_name in getResolverList()
            ):
                raise Exception(
                    "Cound not %s resolver, resolver %r already"
                    " exists!" % (mode, new_resolver_name)
                )

            #
            # we do not support changing the resolver type
            # except via Tools -> Migrate Resolver

            if previous_name:
                previous_resolver = getResolverInfo(
                    previous_name, passwords=True
                )

                if param["type"] != previous_resolver["type"]:
                    raise Exception(
                        "Modification of resolver type is not supported!"
                    )

            (param, missing, primary_key_changed) = prepare_resolver_parameter(
                new_resolver_name=new_resolver_name,
                param=param,
                previous_name=previous_name,
            )

            if missing:
                raise ParameterError(_("Missing parameter: %r") % missing)

            # finally define the resolver
            resolver_loaded = defineResolver(param)

            if resolver_loaded is False:
                raise ResolverLoadConfigError(msg % new_resolver_name)

            # -------------------------------------------------------------- --

            # the rename of a resolver requires a cleanup:
            # 1. rename the resolver in all realm definitions
            # 2. migrate the resolver to the new userid resolver

            if mode == "rename":
                # lookup in which realm definition the resolvers is used

                change_realms = {}

                for realm_name, realm_description in list(getRealms().items()):
                    resolvers = realm_description.get("useridresolver")

                    for current_resolver in resolvers:
                        if previous_name == current_resolver.split(".")[-1]:
                            # Resolver has changed - reconfigure this realm
                            new_resolvers = []

                            for resolver in resolvers:
                                parts = resolver.split(".")
                                if previous_name == parts[-1]:
                                    parts[-1] = new_resolver_name
                                    new_resolvers.append(".".join(parts))
                                else:
                                    new_resolvers.append(resolver)

                            setRealm(realm_name, ",".join(new_resolvers))
                            break

            #
            # migrate the tokens to the new resolver -
            # we can re-use the resolver migration handler here :-)

            if mode == "rename" or primary_key_changed:
                resolvers = getResolverList()
                src_resolver = resolvers.get(previous_name, None)
                target_resolver = resolvers.get(new_resolver_name, None)

                mg = MigrateResolverHandler()
                ret = mg.migrate_resolver(
                    src=src_resolver, target=target_resolver
                )

                log.info("Token migrated to the new resolver: %r", ret)

            if mode == "rename":
                # finally delete the previous resolver definition
                deleteResolver(previous_name)

            db.session.commit()
            return sendResult(response, True, 1)

        except ResolverLoadConfigError as exx:
            log.error(
                "Failed to load resolver definition %r \n %r",
                exx,
                list(param.keys()),
            )
            db.session.rollback()
            return sendError(response, msg % new_resolver_name)

        except Exception as exx:
            log.error("[setResolver] error saving config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @deprecated_methods(["POST"])
    def getResolvers(self):
        """
        returns a json list of all useridresolvers

        :return:
            a json result with a list of all available resolvers

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            res = getResolverList()

            g.audit["success"] = True
            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[getResolvers] error getting resolvers: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @methods(["POST"])
    def delResolver(self):
        """
        this function deletes an existing resolver
        All config keys of this resolver get deleted

        :param resolver: the name of the resolver to delete.

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            param = getLowerParams(self.request_params)
            log.info("[delResolver] deleting resolver: %r", param)

            if "resolver" not in param:
                raise ParameterError("missing required parameter: resolver")

            resolver_name = param["resolver"]

            # only delete a resolver, if it is not used by any realm
            found = False
            fRealms = []
            realms = getRealms()
            for realm in realms:
                info = realms.get(realm)
                resolver_specs = info.get("useridresolver")

                for resolver_spec in resolver_specs:
                    __, config_identifier = parse_resolver_spec(resolver_spec)
                    if resolver_name == config_identifier:
                        fRealms.append(realm)
                        found = True

            if found is True:
                g.audit["failed"] = res
                err = "Resolver %r  still in use by the realms: %r" % (
                    resolver_name,
                    fRealms,
                )
                g.audit["info"] = err
                raise Exception("%r !" % err)

            is_manged_resolver = getResolverInfo(resolver_name).get(
                "readonly", False
            )

            if is_manged_resolver:
                imported_user = ImportedUser(resolver_name)
                imported_user.remove_all_users()

            res = deleteResolver(resolver_name)
            g.audit["success"] = res
            g.audit["info"] = resolver_name

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[delResolver] error deleting resolver: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @deprecated_methods(["POST"])
    def getResolver(self):
        """
        this function retrieves the definition of the resolver

        :param resolver: the name of the resolver

        :return:
            a json result with the configuration of a specified resolver
        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            param = getLowerParams(self.request_params)
            log.debug("[getResolver] with param: %r", param)

            if "resolver" not in param:
                raise ParameterError("missing required parameter: resolver")

            resolver = param["resolver"]

            if len(resolver) == 0:
                raise Exception("[getResolver] missing resolver name")

            res = getResolverInfo(resolver)

            g.audit["success"] = True
            g.audit["info"] = resolver

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[getResolver] error getting resolver: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

        finally:
            log.debug("[getResolver] done")

    ########################################################
    @methods(["POST"])
    def setDefaultRealm(self):
        """
        set the given realm to the default realm

        :param realm: the name of the realm, that should be the default realm

        :return:
            a json result with a list of Realms

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = False

        try:
            param = getLowerParams(self.request_params)
            log.info("[setDefaultRealm] with param: %r", param)

            defRealm = param.get("realm", "")

            defRealm = defRealm.lower().strip()
            res = setDefaultRealm(defRealm)
            if res is False and defRealm != "":
                g.audit["info"] = "The realm %s does not exist" % defRealm

            g.audit["success"] = True
            g.audit["info"] = defRealm

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error(
                "[setDefaultRealm] setting default realm failed: %r", exx
            )
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @deprecated_methods(["POST"])
    def getDefaultRealm(self):
        """
        return the default realm

        :return:
            a json description of the default realm

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        res = False

        try:
            defRealm = getDefaultRealm()
            res = getRealms(defRealm)

            g.audit["success"] = True
            g.audit["info"] = defRealm

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[getDefaultRealm] return default realm failed: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @methods(["POST"])
    def setRealm(self):
        """
        define a realm with the given useridresolvers

        :param realm: name of the realm
        :param resolvers: comma separated list of resolvers, that should be
              in this realm

        :return:
            a json result with a list of Realms

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = False
        err = ""
        realm = ""
        param = self.request_params

        try:
            log.info("[setRealm] setting a realm: %r", param)

            if "realm" not in param:
                raise ParameterError("missing required parameter: realm")
            realm = param["realm"]

            if "resolvers" not in param:
                raise ParameterError("missing required parameter: resolvers")
            resolver_specs = param["resolvers"].split(",")

            valid_resolver_specs = []
            valid_resolver_names = []
            for resolver_spec in resolver_specs:
                resolver_spec = resolver_spec.strip()
                resolver_spec = resolver_spec.replace('"', "")

                # check if resolver exists
                resolver = getResolverObject(resolver_spec)
                if resolver is None:
                    raise Exception(
                        "unknown resolver or invalid resolver "
                        "class specification: %r" % resolver_spec
                    )
                valid_resolver_specs.append(resolver_spec)
                valid_resolver_names.append(resolver_spec.rpartition(".")[-1])

            valid_resolver_specs_str = ",".join(valid_resolver_specs)

            # compare the 'to be modified realm' with the one of the
            # authenticated user
            auth_user = getUserFromRequest()
            admin_realm_name = auth_user.realm
            admin_resolver_name = auth_user.resolver_config_identifier

            if realm == admin_realm_name:
                if admin_resolver_name not in valid_resolver_names:
                    raise RemoveForbiddenError(
                        f"Resolver {admin_resolver_name} can not be removed from {admin_realm_name}. "
                        "It is not allowed to remove the resolver to which you belong to prevent "
                        "locking yourself out."
                    )

            res = setRealm(realm, valid_resolver_specs_str)
            g.audit["success"] = res
            g.audit["info"] = "realm: %r, resolvers: %r" % (
                realm,
                valid_resolver_specs_str,
            )

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            err = "Failed to set realm with %r " % param
            log.error("[setRealm] %r %r", err, exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @methods(["POST"])
    def delRealm(self):
        """
        deletes the specified realm

        :param realm - the name of the realm to be deleted

        :return:
            a json result if deleting the realm was successful

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        param_err_msg = "missing required parameter: realm"

        try:
            log.info("[delRealm] deleting realm: %r ", self.request_params)

            if "realm" not in self.request_params:
                raise ParameterError(param_err_msg)
            realm = self.request_params["realm"]

            result_of_deletion = deleteRealm(realm)

            res["delRealm"] = {"result": result_of_deletion}
            db.session.commit()

            g.audit["success"] = True
            g.audit["info"] = realm

            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[delRealm] error deleting realm: %r", exx)
            g.audit["success"] = False
            g.audit["info"] = (
                "no realm specified"
                if hasattr(exx, "message") and exx.message == param_err_msg
                else realm
            )
            return sendError(response, exx)

    ########################################################
    @methods(["POST"])
    def setPolicy(self):
        """
        Stores a policy that define ACL or behaviour of several different
            actions in LinOTP. The policy is stored as configuration values
            like this::

                Policy.<NAME>.action
                Policy.<NAME>.scope
                Policy.<NAME>.realm


        :param name: name of the policy
        :param action: which action may be executed
        :param scope: selfservice
        :param realm: This polcy holds for this realm
        :param user: (optional) This polcy binds to this user
        :param time: (optional) on which time does this policy hold
        :param client: (optional) for which requesting client this should be:
        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        param = self.request_params.copy()
        try:
            log.debug("[setPolicy] params: %r", param)

            if "session" in param:
                del param["session"]

            if "name" not in param:
                raise ParameterError("missing required parameter: name")
            name = param["name"]

            if not name:
                raise Exception(_("The name of the policy must not be empty"))

            if "action" not in param:
                raise ParameterError("missing required parameter: action")
            action = param["action"]

            if "scope" not in param:
                raise ParameterError("missing required parameter: scope")
            scope = param["scope"]

            if "realm" not in param:
                raise ParameterError("missing required parameter: realm")
            realm = param["realm"]

            user = param.get("user")
            time = param.get("time")
            client = param.get("client")
            active = param.get("active", "True")

            p_param = {
                "name": name,
                "action": action,
                "scope": scope,
                "realm": realm,
                "user": user,
                "time": time,
                "client": client,
                "active": active,
            }

            enforce = param.get("enforce", "False")
            if enforce.lower() == "true":
                enforce = True
                p_param["enforce"] = enforce

            g.audit["action_detail"] = str(param)

            if len(name) > 0 and len(action) > 0:
                log.debug("[setPolicy] saving policy %r", p_param)
                ret = setPolicy(p_param)
                log.debug("[setPolicy] policy %s successfully saved.", name)

                string = "setPolicy " + name
                res[string] = ret

                g.audit["success"] = True

                db.session.commit()
            else:
                log.error(
                    "[setPolicy] failed: policy with empty name"
                    " or action %r",
                    p_param,
                )
                string = "setPolicy <%r>" % name
                res[string] = False

                g.audit["success"] = False
                raise Exception("setPolicy failed: name and action required!")

            return sendResult(response, res, 1)

        except Exception as exx:
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @deprecated_methods(["POST"])
    def policies_flexi(self):
        """
        This function is used to fill the policies tab

        Unlike the complex /system/getPolcies function, it only returns a
        simple array of the tokens.

        :param name:
        :param realm:
        :param scope:
        :param sortname:
        :param sortorder:
        :param page:
        :param psize:

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        pol = {}

        try:
            param = getLowerParams(self.request_params)
            log.debug(
                "[policies_flexi] viewing policies with params: %r", param
            )

            name = param.get("name")
            realm = param.get("realm")
            scope = param.get("scope")
            sortname = param.get("sortname")
            sortorder = param.get("sortorder")
            page = param.get("page", 1)
            psize = param.get("rp", 0)

            log.debug(
                "[policies_flexi] retrieving policy name: %s, realm:"
                " %s, scope: %s, sort:%s by %s",
                name,
                realm,
                scope,
                sortorder,
                sortname,
            )

            pols = search_policy(
                {"name": name, "realm": realm, "scope": scope},
                only_active=False,
            )

            lines = []
            for pol in pols:
                active = 0
                if pols[pol].get("active", "True") == "True":
                    active = 1

                cell = [
                    active,
                    pol,
                    pols[pol].get("user", ""),
                    pols[pol].get("scope", ""),
                    escape(pols[pol].get("action", "") or ""),
                    pols[pol].get("realm", ""),
                    pols[pol].get("client", ""),
                    pols[pol].get("time", ""),
                ]

                lines.append({"id": pol, "cell": cell})
            # sorting
            reverse = False
            sortnames = {
                "active": 0,
                "name": 1,
                "user": 2,
                "scope": 3,
                "action": 4,
                "realm": 5,
                "client": 6,
                "time": 7,
            }

            if sortorder == "desc":
                reverse = True
            lines = sorted(
                lines,
                key=lambda policy: policy["cell"][sortnames[sortname]],
                reverse=reverse,
            )
            # end: sorting
            lines_total = len(lines)

            # reducing the page
            if page and psize:
                page = int(page)
                psize = int(psize)
                start = psize * (page - 1)
                end = start + psize
                lines = lines[start:end]

            # We need to return 'page', 'total', 'rows'
            res = {"page": int(page), "total": lines_total, "rows": lines}

            g.audit["success"] = True
            g.audit["info"] = "name = %s, realm = %s, scope = %s" % (
                name,
                realm,
                scope,
            )
            db.session.commit()
            return json.dumps(res, indent=3)

        except Exception as exx:
            log.error("[policies_flexi] error in policy flexi: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @deprecated_methods(["POST"])
    def getPolicyDef(self):
        """

        This is a helper function that returns the POSSIBLE policy
        definitions, that can be used to define your policies.

        :param scope: (optional) if given, the function will only return policy
                               definitions for the given scope.

        :return:
             the policy definitions of
              - allowed scopes
              - allowed actions in scopes
              - type of actions

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        pol = {}

        try:
            param = getLowerParams(self.request_params)
            log.debug("[getPolicy] getting policy definitions: %r", param)

            scope = param.get("scope")
            pol = get_policy_definitions(scope)
            dynpol = self._add_dynamic_tokens(scope)
            pol.update(dynpol)

            g.audit["success"] = True
            g.audit["info"] = scope

            db.session.commit()
            return sendResult(response, pol, 1)

        except Exception as exx:
            log.error(
                "[getPolicyDef] error getting policy definitions: %r", exx
            )
            db.session.rollback()
            return sendError(response, exx)

    #########################################################
    def _add_dynamic_tokens(self, scope):
        """
        add the policy description of the dynamic token

        :param scope: scope of the policy definition

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        pol = {}

        for tclass_object in set(tokenclass_registry.values()):
            tok = tclass_object.getClassType()

            if hasattr(tclass_object, "getClassInfo"):
                # check if we have a policy in the definition
                try:
                    policy = tclass_object.getClassInfo("policy", ret=None)
                    if policy is not None and scope in policy:
                        scope_policy = policy.get(scope)
                        pol.update(scope_policy)

                except Exception as exx:
                    log.info(
                        "[dynamicToken] no policy for tokentype %r "
                        "found (%r)",
                        tok,
                        exx,
                    )

        return pol

    #########################################################
    @methods(["POST"])
    def importPolicy(self):
        """
        import policies from a file.

        :param file: (mandatory) The policy file in the POST request

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        # setup the response methods
        sendResultMethod = sendResult
        sendErrorMethod = sendError

        res = True
        try:
            log.debug("[importPolicy] getting POST request: %r", request.files)

            policy_file = request.files.get("file")
            fileString = ""
            log.debug(
                "[importPolicy] loading policy file to server using POST"
                " request. File: %r",
                policy_file,
            )
            if not policy_file:
                raise ParameterError("missing input file")

            if isinstance(policy_file, FileStorage):
                log.debug("[importPolicy] Field storage file: %s", policy_file)
                fileString = policy_file.read().decode()

                sendResultMethod = sendXMLResult
                sendErrorMethod = sendXMLError

            else:
                fileString = policy_file

            log.debug("[importPolicy] fileString: %s", fileString)

            if fileString == "":
                log.error(
                    "[importPolicy] Error loading/importing policy "
                    "file. file empty!"
                )
                return sendErrorMethod(
                    response, "Error loading policy. File is empty!"
                )

            # the contents of filestring needs to be parsed and
            # stored as policies.
            config = fileString.split("\n")
            policies = ConfigObj(config)
            log.info(
                "[importPolicy] read the following policies: %r", policies
            )

            # -- ------------------------------------------------------ --
            # finally import the policies
            # -- ------------------------------------------------------ --
            res = import_policies(policies)

            g.audit["info"] = "Policies imported from file %s" % policy_file
            g.audit["success"] = 1

            db.session.commit()

            return sendResultMethod(response, res)

        except Exception as exx:
            log.error("[importPolicy] failed! %r", exx)
            db.session.rollback()
            return sendErrorMethod(response, exx)

    ############################################################
    @deprecated_methods(["POST"])
    def checkPolicy(self):
        """
        checks if a the given parameter will trigger a policy or not.

        :param user:  the name of the user
        :param realm: the realm
        :param scope: the scope
        :param action: the action
        :param client: the client IP

        :return:
            a json result like this:
              value : { "allowed" : "true",
                        "policy" : <Name der Policy, die das erlaubt hat> }
              value : { "allowed" : "false",
                         "info" : <sowas wie die Fehlermeldung> }

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            param = getLowerParams(self.request_params)

            if "user" not in param:
                raise ParameterError("missing required parameter: user")
            user = param["user"]

            if "realm" not in param:
                raise ParameterError("missing required parameter: realm")
            realm = param["realm"]

            if "scope" not in param:
                raise ParameterError("missing required parameter: scope")
            scope = param["scope"]

            if "action" not in param:
                raise ParameterError("missing required parameter: action")
            action = param["action"]

            if "client" not in param:
                raise ParameterError("missing required parameter: client")
            client = param["client"]

            pol = {}
            if scope in ["admin", "system"]:
                pol = search_policy({"scope": scope})
                if len(pol) > 0:
                    # Policy active for this scope!
                    pol = search_policy(
                        {
                            "user": user,
                            "realm": realm,
                            "scope": scope,
                            "action": action,
                            "client": client,
                        }
                    )
                    res["allowed"] = len(pol) > 0
                    res["policy"] = pol
                    if len(pol) > 0:
                        g.audit["info"] = "allowed by policy %s" % list(
                            pol.keys()
                        )
                else:
                    # No policy active for this scope
                    g.audit["info"] = (
                        "allowed since no policies in scope %s" % scope
                    )
                    res["allowed"] = True
                    res["policy"] = "No policies in scope %s" % scope
            else:
                log.debug(
                    "[checkPolicy] checking policy for client %s, "
                    "scope %s, action %s, realm %s and user %s",
                    client,
                    scope,
                    action,
                    realm,
                    user,
                )

                pol = get_client_policy(client, scope, action, realm, user)
                res["allowed"] = len(pol) > 0
                res["policy"] = pol
                if len(pol) > 0:
                    g.audit["info"] = "allowed by policy %s" % list(pol.keys())

            g.audit[
                "action_detail"
            ] = "action = %s, realm = %s, scope = %s" % (action, realm, scope)
            g.audit["success"] = True

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[checkPolicy] error checking policy: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ##########################################################################
    @deprecated_methods(["POST"])
    def getPolicy(self, id=None):
        """
        retrieve a specified policies

        :param id: (optional) Unused (but left for compatibility).
        :param realm: (optional) will return all policies in the given realm
        :param name:  (optional) will only return the policy with the given name
        :param action:  (optional) will only return the policy with the given action
        :param user:  (optional) will only return the policy for this user
        :param scope: (optional) will only return the policies within the given scope

        :param display_inactive: (optional) if set, then also inactive policies will be displayed

        :return:
            a json result with the configuration of the specified policies

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        param = getLowerParams(self.request_params)

        log.debug("[getPolicy] getting policy: %r", param)
        action = None
        user = None

        try:
            name = param.get("name")
            realm = param.get("realm")
            scope = param.get("scope")

            if "action" in param:
                action = param.get("action") or None
            if "user" in param:
                user = param.get("user") or None

            only_active = True
            display_inactive = param.get("display_inactive", False)
            if display_inactive:
                only_active = False

            do_export = param.get("export", "false").lower() == "true"

            log.debug(
                "[getPolicy] retrieving policy name: %s, realm: %s,"
                " scope: %s",
                name,
                realm,
                scope,
            )
            pol = {}
            if name is not None:
                for nam in name.split(","):
                    search_param = {
                        "name": nam,
                        "realm": realm,
                        "scope": scope,
                    }
                    if action:
                        search_param["action"] = action
                    poli = search_policy(search_param, only_active=only_active)

                    pol.update(poli)
            else:
                search_param = {"name": name, "realm": realm, "scope": scope}
                if action:
                    search_param["action"] = action
                pol = search_policy(search_param, only_active=only_active)

            #
            # due to bug in getPolicy we have to post check
            # if user is in policy!
            #

            if user:
                rpol = {}
                for p_name, policy in list(pol.items()):
                    if policy["user"] is None:
                        rpol[p_name] = policy
                    else:
                        users = policy["user"].split(",")
                        for usr in users:
                            if (
                                usr.strip() == user.strip()
                                or usr.strip() == "*"
                            ):
                                rpol[p_name] = policy
                pol = rpol

            g.audit["success"] = True
            g.audit["info"] = "name = %s, realm = %s, scope = %s" % (
                name,
                realm,
                scope,
            )

            db.session.commit()

            # The export filename is hard-coded to "policy.cfg".
            # It used to be possible to pass this as the final part of
            # the invocation URL, but this functionality was removed
            # in LinOTP 3.x because it caused problems elsewhere and
            # was never actually used; the management UI used "policy.cfg"
            # as a fixed and unchangeable default.

            if do_export:
                filename = create_policy_export_file(pol, "policy.cfg")
                return flask_send_file(
                    filename, mimetype="text/plain", as_attachment=True
                )
            else:
                return sendResult(response, pol, 1)

        except Exception as exx:
            log.error("[getPolicy] error getting policy: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    @methods(["POST"])
    def delPolicy(self):
        """
        deletes the specified policy

        :param name: the policy with the given name

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        ret = {}
        try:
            log.info("[delPolicy] deleting policy: %r", self.request_params)

            # support the ignor of policy impact check
            enforce = self.request_params.get("enforce", "False")
            if enforce.lower() == "true":
                enforce = True
            else:
                enforce = False

            name_param = self.request_params["name"]
            names = name_param.split(",")
            for name in names:
                log.debug("[delPolicy] trying to delete policy %s", name)
                ret.update(deletePolicy(name, enforce))

            res["delPolicy"] = {"result": ret}

            g.audit["success"] = ret
            g.audit["info"] = name

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[delPolicy] error deleting policy: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

        finally:
            db.session.close()

    ########################################################
    @methods(["POST"])
    def setupSecurityModule(self):
        """
        start the pool of security modules

        :param hsm_id: the id for the hsm (mostly the slot id)
        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        res = {}

        try:
            params = getLowerParams(self.request_params)
            log.debug(
                "[setupSecurityModule] parameters: %r", list(params.keys())
            )

            hsm_id = params.get("hsm_id", None)

            sep = current_app.security_provider

            if hsm_id is None:
                hsm_id = sep.activeOne
                hsm = c.hsm.get("obj")
                error = c.hsm.get("error")
                if hsm is None or len(error) != 0:
                    raise Exception(
                        "current activeSecurityModule >%r< is not"
                        "initialized::%s:: - Please check your "
                        "security module configuration and "
                        "connection!" % (hsm_id, error)
                    )

                ready = hsm.isReady()
                res["setupSecurityModule"] = {
                    "activeSecurityModule": hsm_id,
                    "connected": ready,
                }
                ret = ready
            else:
                if hsm_id != sep.activeOne:
                    raise Exception(
                        "current activeSecurityModule >%r< could"
                        " only be changed through the "
                        "configuration!" % sep.activeOne
                    )

                ret = sep.setupModule(hsm_id, config=params)

                hsm = c.hsm.get("obj")
                ready = hsm.isReady()
                res["setupSecurityModule"] = {
                    "activeSecurityModule": hsm_id,
                    "connected": ready,
                    "result": ret,
                }

            g.audit["success"] = ret
            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("[setupSecurityModule] : setup failed: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    @deprecated_methods(["POST"])
    def getSupportInfo(self):
        """
        return the support status, which is community support by default
        or the support subscription info, which could be the old license

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        res = {}
        try:
            (lic_info, _sig) = getSupportLicenseInfo()
            res = {}
            res.update(lic_info)

            g.audit["success"] = True
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error(
                "[getSupportInfo] : failed to access support info: %r", exx
            )
            db.session.rollback()
            return sendError(response, exx)

    @deprecated_methods(["POST"])
    def isSupportValid(self):
        """
        verifies the support license status

        if ok
            status and value in response are both true
        else
            value is false and the detail is returned as detail in the response

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        res = {}
        info = {}
        contact_info = [
            "<h2>",
            _("Thank you for your interest in our products."),
            "</h2>",
            "",
            "<p>",
            _(
                "Your current LinOTP Smart Virtual Appliance"
                "demo license is about to expire in a few days. "
                "For licenses for productive use or an extended "
                "evaluation period, "
            ),
            "<a href='mailto:vertrieb@linotp.de'>",
            _("please contact us"),
            "</a>.</p>",
            "",
            "<p>",
            _(
                "If you have questions about our products or your "
                "evaluation we are happy to answer your inquiry. "
                "We would also like to learn about your feedback "
                "concerning our products and your evaluation."
            ),
            "</p>",
            "",
            "<p class='center'><a href='mailto:vertrieb@linotp.de'>vertrieb@linotp.de</a></p>",
            "",
            "<p class='center'>",
            _("Sales hotline: "),
            "<a href='tel:+49615186086277'>",
            _("+49 6151 86086 277"),
            "</a></p>",
        ]

        contact_hint = " ".join(contact_info)

        try:
            license_txt = getFromConfig("license", "")
            try:
                licString = binascii.unhexlify(license_txt).decode()
            except TypeError:
                licString = license_txt

            # if there is no license and we are running on an appliance
            # we install the demo license

            if not licString and running_on_appliance():
                res, msg = setDemoSupportLicense()
                db.session.flush()
                license_txt = getFromConfig("license", "")
                licString = binascii.unhexlify(license_txt).decode()

            (res, msg, lic_info) = isSupportLicenseValid(licString)

            if msg:
                info["reason"] = msg

            if do_nagging(lic_info, nag_days=7):
                info["download_licence_info"] = contact_hint

            g.audit["action_detail"] = msg
            g.audit["success"] = res

            db.session.commit()

            return sendResult(response, res, 1, opt=info)

        except Exception as exx:
            log.error("[isSupportValid] failed verify support info: %r", exx)

            db.session.rollback()
            return sendError(response, exx)

    @methods(["POST"])
    def setSupport(self):
        """
        hook to load a support subscription file

        receives the data with a form post file upload
        and installes it after license verification

        :param format: the response format, either xml/htmll or jsom

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        res = False
        message = None

        sendResultMethod = sendResult
        sendErrorMethod = sendError

        try:
            response_format = self.request_params.get("format", "")
            if response_format == "xml":
                sendResultMethod = sendXMLResult
                sendErrorMethod = sendXMLError

            key = "license"
            if key in request.files:
                license_file = request.files[
                    key
                ]  # license_file is an instance of FileStorage
                log.debug("[setSupport] file storage: %s", license_file)
                support_description = license_file.read().decode()
            elif key in self.request_params:
                support_description = self.request_params[key]
                log.debug("[setSupport] plaintext: %s", support_description)
            else:
                return sendErrorMethod(
                    response, "No key 'license' in the upload request"
                )

            log.debug("[setSupport] license %s", support_description)

            res, msg = setSupportLicense(support_description)
            g.audit["success"] = res

            if res is False:
                raise Exception(msg)

            db.session.commit()
            return sendResultMethod(response, res, 1, opt=message)

        except Exception as exx:
            log.error("[setSupport] failed to set support license: %r", exx)
            db.session.rollback()
            return sendErrorMethod(response, exx)

    @methods(["POST"])
    def setProvider(self):
        """
        creates or updates SMS- and Email-provider

        :param name: the name of the provider in LinOTP
        :param type: the type of the provider [email, sms]
        :param class: the name of the provider
        :param config: the configuration for this provider
        :param timeout: the timeout

        :return: jsom document with value True or False with message in detail

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        res = {}
        params = self.request_params.copy()

        try:
            try:
                name = params["name"]
                p_type = params["type"]
                _provider_class = params["class"]
                _timeout = params["timeout"]
            except KeyError as exx:
                raise ParameterError("missing key %r" % exx)

            # -------------------------------------------------------------- --

            # check if the provider is already defined as a managed one

            provider_def = getProvider(p_type, name)

            if not provider_def and "managed" in params:
                # hash the provided password

                password = params["managed"]

                params["managed"] = utils.crypt_password(password)

            if provider_def and "Managed" in provider_def[name]:
                if "managed" not in params:
                    raise Exception(
                        "Not allowed to overwrite the "
                        "configuration of a managed provider"
                    )

                password = params["managed"]
                crypt_password = provider_def[name]["Managed"]

                if not utils.compare_password(password, crypt_password):
                    raise Exception(
                        "Not allowed to overwrite the "
                        "configuration of a managed provider"
                    )

                params["managed"] = crypt_password

            # -------------------------------------------------------------- --

            res, reply = setProvider(params)

            g.audit["success"] = res
            g.audit["info"] = name

            db.session.commit()
            return sendResult(response, res, 1, opt=reply)

        except Exception as exx:
            log.error("error saving config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    @deprecated_methods(["POST"])
    def getProvider(self):
        """
        get a dict of SMS- and Email-providers

        :param name: (optional) the name of the provider in LinOTP
        :param type:  the type of the provider: SMS or EMail

        :return: dictionary of provider with its entries as dictionary
                 {'ProviderA' : { 'Timeout': '100', ...}

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        res = {}
        param = self.request_params

        try:
            try:
                provider_type = param["type"]
            except KeyError as exx:
                raise ParameterError("missing key %r" % exx)

            # optional parameters
            provider_name = param.get("name")

            res = getProvider(provider_type, provider_name, decrypted=True)
            if res:
                for provider_name, desc in list(res.items()):
                    if "Managed" in desc:
                        res[provider_name]["Managed"] = True

            g.audit["success"] = len(res) > 0
            if provider_name:
                g.audit["info"] = provider_name

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("error getting config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    @methods(["POST"])
    def testProvider(self):
        """
        if the provider has a test interface, the provider test is run

        :param name: required - the name of the provider in LinOTP

        :return: dictionary of provider with its entries as dictionary
                 {'ProviderA' : { 'Timeout': '100', ...}

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        status = False
        p_response = "Can't Connect"

        try:
            try:
                provider_name = self.request_params["name"]
                provider_type = self.request_params["type"]
            except KeyError as exx:
                raise ParameterError("missing key %r" % exx)

            provider = loadProvider(
                provider_type=provider_type, provider_name=provider_name
            )
            if provider and hasattr(provider, "test_connection"):
                status, p_response = provider.test_connection()

            g.audit["success"] = status
            g.audit["info"] = provider_name

            db.session.commit()
            return sendResult(response, status, 1)

        except Exception as exx:
            log.error("error getting config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    @methods(["POST"])
    def delProvider(self):
        """
        delete the specified SMS- and Email-providers

        :param name: the name of the SMS or EMail Provider
        :param type: the provider type

        :return: boolean, true if number of deleted config entries is > 0
                          else False with message in detail

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        res = {}

        try:
            try:
                provider_name = self.request_params["name"]
                provider_type = self.request_params["type"]
            except KeyError as exx:
                raise ParameterError("missing key %r" % exx)

            provider_def = getProvider(provider_type, provider_name)

            if (
                provider_def
                and provider_name in provider_def
                and "Managed" in provider_def[provider_name]
            ):
                if "managed" not in self.request_params:
                    raise Exception(
                        "Not allowed to delete the managed provider"
                    )

                password = self.request_params["managed"]
                crypt_password = provider_def[provider_name]["Managed"]

                if not utils.compare_password(password, crypt_password):
                    raise Exception(
                        "Not allowed to delete the managed provider"
                    )

            res, reply = delProvider(provider_type, provider_name)

            g.audit["success"] = res > 0
            g.audit["info"] = provider_name

            db.session.commit()
            return sendResult(response, res > 0, 1, opt=reply)

        except Exception as exx:
            log.error("error saving config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    @methods(["POST"])
    def setDefaultProvider(self):
        """
        set the specified provider (SMS- and Email) as default

        :param name: the name of the SMS or EMail Provider
        :param type: the provider type

        :return: boolean, true if number of deleted config entries is > 0
                          else False with message in detail

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        res = {}

        try:
            try:
                provider_name = self.request_params["name"]
                provider_type = self.request_params["type"]
            except KeyError as exx:
                raise ParameterError("missing key %r" % exx)

            res, reply = setDefaultProvider(provider_type, provider_name)

            g.audit["success"] = res
            g.audit["info"] = provider_name

            db.session.commit()
            return sendResult(response, res, 1, opt=reply)

        except Exception as exx:
            log.error("error saving config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    @deprecated_methods(["POST"])
    def getProviderDef(self):
        """
        get the definition of the specified  provider
        - used for automatic rendering

        :param type: (required) the provider type
        :param class: (optional) the specific class definition or the parent
                               class definition if not specified
        :return:  dictionary with the class as key and the parameters with
                  their types as dictionaries

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        res = {}

        try:
            try:
                _provider_name = self.request_params["name"]
                _provider_type = self.request_params["type"]
            except KeyError as exx:
                raise ParameterError("missing key %r" % exx)

            # TODO:  to be implemented
            res = {}

            db.session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.error("error saving config: %r", exx)
            db.session.rollback()
            return sendError(response, exx)


# eof #########################################################################
