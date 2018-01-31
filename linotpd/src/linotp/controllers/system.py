# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
system controller - to configure the system
"""
import base64

from os import urandom

import json
import webob
import binascii
from configobj import ConfigObj

from pylons import request, response, config, tmpl_context as c

from linotp.useridresolver.UserIdResolver import ResolverLoadConfigError

from linotp.lib.selftest import isSelfTest
from linotp.lib.base import BaseController

from linotp.lib.config import storeConfig
from linotp.lib.config import getLinotpConfig
from linotp.lib.config import getFromConfig
from linotp.lib.config import updateConfig
from linotp.lib.config import removeFromConfig

from linotp.lib.realm import setDefaultRealm
from linotp.lib.realm import isRealmDefined

from linotp.lib.util import check_session
from linotp.lib.util import get_client
from linotp.lib.util import getLowerParams

from linotp.lib.resolver import defineResolver
from linotp.lib.resolver import getResolverObject
from linotp.lib.resolver import getResolverList
from linotp.lib.resolver import getResolverInfo
from linotp.lib.resolver import deleteResolver
from linotp.lib.resolver import parse_resolver_spec
from linotp.lib.resolver import prepare_resolver_parameter

from linotp.lib.tools.migrate_resolver import MigrateResolverHandler

from linotp.lib.error import ParameterError

from linotp.lib.reply import sendResult
from linotp.lib.reply import sendError
from linotp.lib.reply import sendXMLResult
from linotp.lib.reply import sendXMLError

from linotp.lib.realm import getRealms
from linotp.lib.realm import getDefaultRealm
from linotp.lib.realm import deleteRealm


from linotp.lib.user import setRealm
from linotp.lib.user import getUserFromRequest

from linotp.tokens import tokenclass_registry

from linotp.lib.policy import checkPolicyPre
from linotp.lib.policy import checkPolicyPost
from linotp.lib.policy import PolicyException

from linotp.lib.policy import getPolicy
from linotp.lib.policy import search_policy

from linotp.lib.policy.manage import setPolicy
from linotp.lib.policy.manage import deletePolicy
from linotp.lib.policy.manage import import_policies
from linotp.lib.policy.definitions import getPolicyDefinitions

from linotp.lib.policy.manage import create_policy_export_file
from linotp.lib.policy import get_client_policy

from linotp.lib.support import getSupportLicenseInfo
from linotp.lib.support import setSupportLicense
from linotp.lib.support import do_nagging
from linotp.lib.support import isSupportLicenseValid

from linotp.provider import getProvider
from linotp.provider import setProvider
from linotp.provider import loadProvider
from linotp.provider import delProvider
from linotp.provider import setDefaultProvider

from linotp.lib.type_utils import boolean

from linotp.lib.crypto import libcrypt_password

from paste.fileapp import FileApp
from cgi import escape
from pylons.i18n.translation import _

from linotp.lib.context import request_context

import logging
import linotp.model.meta

Session = linotp.model.meta.Session

audit = config.get('audit')
log = logging.getLogger(__name__)


class SystemController(BaseController):

    '''
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server. The SystemController is used to configure the LinOTP
    server. The functions of the SystemController are invoked like this

        https://server/system/<functionname>

    The functions are described below in more detail.
    '''

    def __before__(self, action, **params):
        '''
        __before__ is called before every action
             so we can check the authorization (fixed?)

        :param action: name of the to be called action
        :param params: the list of http parameters

        :return: return response
        :rtype:  pylon response
        '''
        try:

            c.audit = request_context['audit']
            c.audit['success'] = False
            c.audit['client'] = get_client(request)

            # check session might raise an abort()
            check_session(request)
            request_context['Audit'] = audit

            # check authorization
            if action not in ["_add_dynamic_tokens",
                              'setupSecurityModule',
                              'getSupportInfo',
                              'isSupportValid']:
                checkPolicyPre('system', action)

            # default return for the __before__ and __after__
            return response

        except PolicyException as pex:
            log.exception("[__before__::%r] policy exception %r", action, pex)
            Session.rollback()
            Session.close()
            return sendError(response, pex, context='before')

        except webob.exc.HTTPUnauthorized as acc:
            # the exception, when an abort() is called if forwarded
            log.exception("[__before__::%r] webob.exception %r", action, acc)
            Session.rollback()
            Session.close()
            raise acc

        except Exception as exx:
            log.exception("[__before__::%r] exception %r", action, exx)
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')


    def __after__(self):
        '''
        __after is called after every action

        :return: return the response
        :rtype:  pylons response
        '''
        try:
            c.audit['administrator'] = getUserFromRequest(request).get("login")
            audit.log(c.audit)
            # default return for the __before__ and __after__
            return response

        except Exception as exx:
            log.exception("[__after__] exception %r", exx)
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='after')



########################################################

    def setDefault(self):
        """
        method:
            system/set

        description:
            define default settings for tokens. These default settings
            are used when new tokens are generated. The default settings will
            not affect already enrolled tokens.

        arguments:
            DefaultMaxFailCount    - Default value for the maximum allowed
                                     authentication failures
            DefaultSyncWindow      - Default value for the
                                     synchronization window
            DefaultCountWindow     - Default value for the counter window
            DefaultOtpLen          - Default value for the OTP value length --
                                     usuall 6 or 8
            DefaultResetFailCount  - Default value, if the FailCounter should
                                     be reset on successful authentication
                                     [True|False]


        returns:
            a json result with a boolean
              "result": true

        exception:
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
        keys = ["DefaultMaxFailCount", "DefaultSyncWindow",
                "DefaultCountWindow", "DefaultOtpLen",
                "DefaultResetFailCount"]

        try:
            param = getLowerParams(request.params)
            log.info("[setDefault] saving default configuration: %r",
                     param.keys())

            for k in keys:
                if k.lower() in param:
                    value = param[k.lower()]
                    ret = storeConfig(k, value)
                    des = "set " + k
                    res[des] = ret
                    count = count + 1

                    c.audit['success'] = count
                    c.audit['info'] += "%s=%s, " % (k, value)

            if count == 0:
                log.warning("[setDefault] Failed saving config. Could not "
                            "find any known parameter. %s", description)
                raise ParameterError("Usage: %s" % description, id=77)

            Session.commit()
            return sendResult(response, res)

        except Exception as exx:
            log.exception('[setDefault] commit failed: %r', exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()


########################################################
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
        """

        res = {}
        param = {}

        try:
            param.update(request.params)
            log.info("[setConfig] saving configuration: %r", param.keys())

            if "key" in param:

                key = param.get("key") or None
                val = param.get("value", None)
                typ = param.get("type", None)
                des = param.get("description", None)

                if val is None or key is None:
                    raise ParameterError("Required parameters: value and key")

                ret = storeConfig(key, val, typ, des)
                string = "setConfig %s" % key
                res[string] = ret

                c.audit['success'] = True
                c.audit['info'] = "%s=%s" % (key, val)

            else:
                # we gather all key value pairs in the conf dict
                conf = {}
                for key in param:

                    if key == 'session':
                        continue

                    val = param.get(key, '') or ''

                    Key = key
                    if not key.startswith('linotp'):
                        Key = 'linotp.' + key
                    conf[Key] = val

                    string = "setConfig " + key + ":" + val
                    res[string] = True

                    c.audit['success'] = True
                    c.audit['info'] += "%s=%s, " % (key, val)

                updateConfig(conf)

            Session.commit()
            return sendResult(response, res, 1)

        except ValueError as exx:
            log.exception("[setConfig] error saving config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        except Exception as exx:
            log.exception("[setConfig] error saving config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################

    def delConfig(self):
        """
        delete a configuration key
        * if an error occurs an exception is serializedsetConfig and returned

        :param key: configuration key name
        :returns: a json result with the deleted value

        """
        res = {}

        try:
            param = getLowerParams(request.params)
            log.info("[delConfig] with params: %r", param)

            if 'key' not in param:
                raise ParameterError("missing required parameter: key")
            key = param["key"]
            ret = removeFromConfig(key)
            string = "delConfig " + key
            res[string] = ret

            c.audit['success'] = ret
            c.audit['info'] = key

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[delConfig] error deleting config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()


########################################################
########################################################

    def getConfig(self):
        """
        retrieve value of a defined configuration key, or if no key is given,
        the complete configuration is returned
        if an error occurs an exception is serialized and returned

        * remark: the assumption is, that the access to system/getConfig
                  is only allowed to privileged users

        :param key: generic configuration entry name (optional)

        :return: a json result with key value or all key + value pairs

        """
        res = {}
        param = {}
        try:
            param.update(request.params)
            log.debug("[getConfig] with params: %r", param)

            if 'session' in param:
                del param['session']

            # if there is no parameter, we return them all
            if len(param) == 0:
                conf = getLinotpConfig()
                keys = conf.keys()
                keys.sort()
                for key in keys:

                    parts = key.split('.')

                    if parts[0] == "enclinotp":
                        continue

                    if parts[0] == "linotp":
                        Key = key[len("linotp."):]

                        #
                        # Todo: move the handling of extra data to the
                        #       json reply formatter
                        #

                        typ = type(conf.get(key)).__name__
                        if typ not in ['str', 'unicode']:
                            if typ == 'datetime':
                                res[Key] = unicode(conf.get(key))
                            else:
                                res[Key] = conf.get(key)
                        else:
                            res[Key] = conf.get(key)

                c.audit['success'] = True
                c.audit['info'] = "complete config"

            else:
                if 'key' not in param:
                    raise ParameterError("missing required parameter: key")
                key = param["key"]

                #
                # prevent access to the decrypted data
                #

                if key.startswith('enclinotp.'):
                    key = 'linotp.%s' % key[len('enclinotp.'):]

                ret = getFromConfig(key)
                string = "getConfig " + key
                res[string] = ret

                c.audit['success'] = ret
                c.audit['info'] = "config key %s" % key

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[getConfig] error getting config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def getRealms(self):
        '''
        method:
            system/getRealms

        description:
            returns all realm definitinos as a json result.

        arguments:

        returns:
            a json result with a list of Realms

        exception:
            if an error occurs an exception is serialized and returned


        Either the admin has the policy scope=system, action=read
        or he is rights in scope=admin for some realms.
        If he does not have the system-read-right, then he will only
        see the realms, he is admin of.
        '''

        try:
            param = getLowerParams(request.params)
            log.debug("[getRealms] with params: %r", param)

            c.audit['success'] = True
            all_realms = getRealms()

            #
            # If the admin is not allowed to see all realms,
            #                 (policy scope=system, action=read)
            # the realms, where he has no administrative rights need,
            # to be stripped, which is done by the checkPolicyPost, that
            # returns the acl with the allowed realms as entry
            #

            polPost = checkPolicyPost('system', 'getRealms',
                                      {'realms': all_realms})
            res = polPost['realms']

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pex:
            log.exception("[getRealms] policy exception: %r", pex)
            Session.rollback()
            return sendError(response, pex)

        except Exception as exx:
            log.exception("[getRealms] error getting realms: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()


########################################################
    def setResolver(self):
        """
        method:
            system/setResolver

        description:
            creates or updates a useridresolver

        arguments:
            name    -    the name of the resolver
            type    -    the type of the resolver [ldapsersolver, sqlresolver]

            LDAP:
                LDAPURI
                LDAPBASE
                BINDDN
                BINDPW
                TIMEOUT
                SIZELIMIT
                LOGINNAMEATTRIBUTE
                LDAPSEARCHFILTER
                LDAPFILTER
                USERINFO
                NOREFERRALS        - True|False
            SQL:
                Database
                Driver
                Server
                Port
                User
                Password
                Table
                Map

        returns:
            a json result with the found value

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = {}
        resolver_loaded = False
        msg = _("Unable to instantiate the resolver %r."
                "Please verify configuration or connection!")

        try:
            param.update(request.params)

            if 'name' not in param:
                raise ParameterError('missing required parameter "name"')

            new_resolver_name = param['name']
            previous_name = param.get('previous_name', '')


            if 'readonly' in param:

                # the default for the readonly attribute is - to not exist :)
                # if it does, the conversion will fail and we raise an exception
                if not param['readonly']:
                    # remove empty 'readonly' attribute
                    del param['readonly']
                else:
                    try:
                        boolean(param['readonly'])
                    except Exception as exx:
                        msg = ("Failed to convert attribute 'readonly' to"
                               " a boolean value! %r")
                        log.error(msg, param['readonly'])
                        raise Exception(msg % param['readonly'])

            if not previous_name:
                mode = 'create'
            else:
                if new_resolver_name == previous_name:
                    mode = 'update'
                else:
                    mode = 'rename'

            log.info("[setResolver] saving configuration %r", param.keys())

            #
            # before storing the new resolver, we check if already a
            # resolver with same name exists.
            #
            if (mode in ["create", "rename"] and
               new_resolver_name in getResolverList()):

                raise Exception("Cound not %s resolver, resolver %r already"
                                " exists!" % (mode, new_resolver_name))

            #
            # we do not support changing the resolver type
            # except via Tools -> Migrate Resolver

            if previous_name:
                previous_resolver = getResolverInfo(previous_name,
                                                    passwords=True)

                if param['type'] != previous_resolver['type']:
                    raise Exception('Modification of resolver type is not '
                                    'supported!')

            (param, missing,
             primary_key_changed) = prepare_resolver_parameter(
                                        new_resolver_name=new_resolver_name,
                                        param=param,
                                        previous_name=previous_name)

            if missing:
                raise ParameterError(_("Missing parameter: %r") %
                                     missing)

            # finally define the resolver
            resolver_loaded = defineResolver(param)

            if resolver_loaded is False:
                raise ResolverLoadConfigError(msg % new_resolver_name)

            # -------------------------------------------------------------- --

            # the rename of a resolver requires a cleanup:
            # 1. rename the resolver in all realm definitions
            # 2. migrate the resolver to the new userid resolver

            if mode == 'rename':

                # lookup in which realm definition the resolvers is used

                change_realms = {}

                for realm_name, realm_description in getRealms().items():

                    resolvers = realm_description.get('useridresolver')

                    for current_resolver in resolvers:
                        if previous_name == current_resolver.split('.')[-1]:
                            # Resolver has changed - reconfigure this realm
                            new_resolvers = []

                            for resolver in resolvers:
                                parts = resolver.split('.')
                                if previous_name == parts[-1]:
                                    parts[-1] = new_resolver_name
                                    new_resolvers.append('.'.join(parts))
                                else:
                                    new_resolvers.append(resolver)

                            setRealm(realm_name, ','.join(new_resolvers))
                            break

                #
                # migrate the tokens to the new resolver -
                # we can re-use the resolver migration handler here :-)


            if mode == 'rename' or primary_key_changed:

                resolvers = getResolverList()
                src_resolver = resolvers.get(previous_name, None)
                target_resolver = resolvers.get(new_resolver_name, None)

                mg = MigrateResolverHandler()
                ret = mg.migrate_resolver(src=src_resolver,
                                          target=target_resolver)

                log.info("Token migrated to the new resolver: %r",
                         ret)

            if mode == 'rename':
                # finally delete the previous resolver definition
                deleteResolver(previous_name)

            Session.commit()
            return sendResult(response, True, 1)

        except ResolverLoadConfigError as exx:
            log.exception("Failed to load resolver definition %r \n %r",
                          exx, param.keys())
            Session.rollback()
            return sendError(response, msg % new_resolver_name)

        except Exception as exx:
            log.exception("[setResolver] error saving config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def getResolvers(self):
        """
        method:
            system/getResolvers

        descriptions:
            returns a json list of all useridresolvers

        arguments:

        returns:
            a json result with a list of all available resolvers

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            res = getResolverList()

            c.audit['success'] = True
            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[getResolvers] error getting resolvers: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def delResolver(self):
        """
        method:
            system/delResolver

        description:
            this function deletes an existing resolver
            All config keys of this resolver get deleted

        arguments:
            resolver - the name of the resolver to delete.

        returns:
            success state

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            param = getLowerParams(request.params)
            log.info("[delResolver] deleting resolver: %r", param)

            if 'resolver' not in param:
                raise ParameterError("missing required parameter: resolver")
            resolver = param["resolver"]

            # only delete a resolver, if it is not used by any realm
            found = False
            fRealms = []
            realms = getRealms()
            for realm in realms:
                info = realms.get(realm)
                resolver_specs = info.get('useridresolver')

                for resolver_spec in resolver_specs:
                    __, config_identifier = parse_resolver_spec(resolver_spec)
                    if resolver == config_identifier:
                        fRealms.append(realm)
                        found = True

            if found is True:
                c.audit['failed'] = res
                err = ('Resolver %r  still in use by the realms: %r' %
                       (resolver, fRealms))
                c.audit['info'] = err
                raise Exception('%r !' % err)

            res = deleteResolver(resolver)
            c.audit['success'] = res
            c.audit['info'] = resolver

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[delResolver] error deleting resolver: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################

    def getResolver(self):
        """
        method:
            system/getResolver

        description:
            this function retrieves the definition of the resolver

        arguments:
            resolver - the name of the resolver

        returns:
            a json result with the configuration of a specified resolver

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            param = getLowerParams(request.params)
            log.debug("[getResolver] with param: %r", param)

            if 'resolver' not in param:
                raise ParameterError("missing required parameter: resolver")
            resolver = param["resolver"]

            if (len(resolver) == 0):
                raise Exception("[getResolver] missing resolver name")

            res = getResolverInfo(resolver)

            c.audit['success'] = True
            c.audit['info'] = resolver

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[getResolver] error getting resolver: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()
            log.debug('[getResolver] done')

########################################################
    def setDefaultRealm(self):
        """
        method:
            system/setDefaultRealm

        description:
            this function sets the given realm to the default realm

        arguments:
            realm - the name of the realm, that should be the default realm

        returns:
            a json result with a list of Realms

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = False

        try:
            param = getLowerParams(request.params)
            log.info("[setDefaultRealm] with param: %r", param)

            defRealm = param.get("realm", '')

            defRealm = defRealm.lower().strip()
            res = setDefaultRealm(defRealm)
            if res is False and defRealm != "":
                c.audit['info'] = "The realm %s does not exist" % defRealm

            c.audit['success'] = True
            c.audit['info'] = defRealm

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[setDefaultRealm] setting default realm failed: %r",
                          exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def getDefaultRealm(self):
        """
        method:
            system/getDefaultRealm

        description:
            this function returns the default realm

        arguments:
            ./.

        returns:
            a json description of the default realm

        exception:
            if an error occurs an exception is serialized and returned
        """
        res = False

        try:
            defRealm = getDefaultRealm()
            res = getRealms(defRealm)

            c.audit['success'] = True
            c.audit['info'] = defRealm

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[getDefaultRealm] return default realm failed: %r",
                          exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def setRealm(self):
        """
        method:
            system/setRealm

        description:
            this function is used to define a realm with the given
            useridresolvers

        arguments:
            * realm     - name of the realm
            * resolvers - comma separated list of resolvers, that should be
              in this realm

        returns:
            a json result with a list of Realms

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = False
        err = ""
        realm = ""
        param = {}

        try:
            param.update(request.params)
            log.info("[setRealm] setting a realm: %r", param)

            if 'realm' not in param:
                raise ParameterError("missing required parameter: realm")
            realm = param["realm"]

            if 'resolvers' not in param:
                raise ParameterError("missing required parameter: resolvers")

            resolver_specs_str = param["resolvers"]
            resolver_specs = resolver_specs_str.split(',')

            valid_resolver_specs = []
            for resolver_spec in resolver_specs:

                resolver_spec = resolver_spec.strip()
                resolver_spec = resolver_spec.replace("\"", "")

                # check if resolver exists
                resolver = getResolverObject(resolver_spec)
                if resolver is None:
                    raise Exception('unknown resolver or invalid resolver '
                                    'class specification: %r' % resolver_spec)
                valid_resolver_specs.append(resolver_spec)

            valid_resolver_specs_str = ",".join(valid_resolver_specs)
            res = setRealm(realm, valid_resolver_specs_str)
            c.audit['success'] = res
            c.audit['info'] = 'realm: %r, resolvers: %r' % \
                              (realm, valid_resolver_specs_str)

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            err = ("Failed to set realm with %r " % param)
            log.exception("[setRealm] %r %r", err, exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def delRealm(self):
        """
        method:
            system/delRealm

        description:
            this function deletes the given realm

        arguments:
            realm - the name of the realm to be deleted

        returns:
            a json result if deleting the realm was successful

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}

        try:
            param = request.params
            log.info("[delRealm] deleting realm: %r ", param)

            if 'realm' not in param:
                raise ParameterError("missing required parameter: realm")
            realm = param["realm"]

            #
            # we test if before delete there has been a default
            # if yes - check after delete, if still one there
            #         and set the last available to default
            #

            defRealm = getDefaultRealm()
            hadDefRealmBefore = False
            if defRealm != "":
                hadDefRealmBefore = True

            # now test if realm is defined
            if isRealmDefined(realm) is True:
                if realm.lower() == defRealm.lower():
                    setDefaultRealm("")
                if realm == "_default_":
                    realmConfig = "useridresolver"
                else:
                    realmConfig = "useridresolver.group." + realm

                res["delRealm"] = {"result":
                                   removeFromConfig(realmConfig, iCase=True)}

            ret = deleteRealm(realm)

            if hadDefRealmBefore is True:
                defRealm = getDefaultRealm()
                if defRealm == "":
                    realms = getRealms()
                    if len(realms) == 2:
                        for k in realms:
                            if k != realm:
                                setDefaultRealm(k)
            c.audit['success'] = ret
            c.audit['info'] = realm

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[delRealm] error deleting realm: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()


########################################################

    def setPolicy(self):
        """
        method:
            system/setPolicy

        description:
            Stores a policy that define ACL or behaviour of several different
            actions in LinOTP. The policy is stored as configuration values
            like this::

                Policy.<NAME>.action
                Policy.<NAME>.scope
                Policy.<NAME>.realm

        arguments:
            name:       name of the policy
            action:     which action may be executed
            scope:      selfservice
            realm:      This polcy holds for this realm
            user:       (optional) This polcy binds to this user
            time:       (optional) on which time does this policy hold
            client:     (optional) for which requesting client this should be

        returns:
            a json result with success or error

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        param = {}
        try:
            log.debug("[setPolicy] params: %r", request.params)
            param.update(request.params)

            if 'session' in param:
                del param['session']

            if 'name' not in param:
                raise ParameterError("missing required parameter: name")
            name = param["name"]

            if not name:
                raise Exception(_("The name of the policy must not be empty"))

            if 'action' not in param:
                raise ParameterError("missing required parameter: action")
            action = param["action"]

            if 'scope' not in param:
                raise ParameterError("missing required parameter: scope")
            scope = param["scope"]

            if 'realm' not in param:
                raise ParameterError("missing required parameter: realm")
            realm = param["realm"]

            user = param.get("user")
            time = param.get("time")
            client = param.get("client")
            active = param.get("active", 'True')

            p_param = {'name': name,
                       'action': action,
                       'scope': scope,
                       'realm': realm,
                       'user': user,
                       'time': time,
                       'client': client,
                       'active': active}

            enforce = param.get('enforce', 'False')
            if enforce.lower() == 'true':
                enforce = True
                p_param['enforce'] = enforce

            c.audit['action_detail'] = unicode(param)

            if len(name) > 0 and len(action) > 0:
                log.debug("[setPolicy] saving policy %r", p_param)
                ret = setPolicy(p_param)
                log.debug("[setPolicy] policy %s successfully saved.", name)

                string = "setPolicy " + name
                res[string] = ret

                c.audit['success'] = True

                Session.commit()
            else:
                log.error("[setPolicy] failed: policy with empty name"
                          " or action %r", p_param)
                string = "setPolicy <%r>" % name
                res[string] = False

                c.audit['success'] = False
                raise Exception('setPolicy failed: name and action required!')

            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[setPolicy] error saving policy: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def policies_flexi(self):
        '''
        This function is used to fill the policies tab
        Unlike the complex /system/getPolcies function, it only returns a
        simple array of the tokens.
        '''

        pol = {}

        try:
            param = getLowerParams(request.params)
            log.debug("[policies_flexi] viewing policies with params: %r",
                      param)

            name = param.get("name")
            realm = param.get("realm")
            scope = param.get("scope")
            sortname = param.get("sortname")
            sortorder = param.get("sortorder")
            page = param.get("page", "1")
            psize = param.get("rp", )

            log.debug("[policies_flexi] retrieving policy name: %s, realm:"
                      " %s, scope: %s, sort:%s by %s", name, realm, scope,
                      sortorder, sortname)

            pols = search_policy({'name': name, 'realm': realm, 'scope': scope},
                                 only_active=False)

            lines = []
            for pol in pols:

                active = 0
                if pols[pol].get('active', "True") == "True":
                    active = 1

                cell = [active,
                        pol,
                        pols[pol].get('user', ""),
                        pols[pol].get('scope', ""),
                        escape(pols[pol].get('action', "") or ""),
                        pols[pol].get('realm', ""),
                        pols[pol].get('client', ""),
                        pols[pol].get('time', "")]

                lines.append({'id': pol, 'cell': cell})
            # sorting
            reverse = False
            sortnames = {'active': 0, 'name': 1, 'user': 2, 'scope': 3,
                         'action': 4, 'realm': 5, 'client': 6, 'time': 7}

            if sortorder == "desc":
                reverse = True
            lines = sorted(lines,
                           key=lambda policy: policy['cell'][sortnames[sortname]],
                           reverse=reverse)
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
            response.content_type = 'application/json'
            res = {"page": int(page),
                   "total": lines_total,
                   "rows": lines}

            c.audit['success'] = True
            c.audit['info'] = ("name = %s, realm = %s, scope = %s" %
                               (name, realm, scope))
            Session.commit()
            response.content_type = 'application/json'
            return json.dumps(res, indent=3)

        except Exception as exx:
            log.exception("[policies_flexi] error in policy flexi: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def getPolicyDef(self):
        '''
        method:
            system/getPolicyDef

        description:
            This is a helper function that returns the POSSIBLE policy
            definitions, that can be used to define your policies.

        arguments:
            scope - optional - if given, the function will only return policy
                               definitions for the given scope.

        returns:
             the policy definitions of
              - allowed scopes
              - allowed actions in scopes
              - type of actions

        exception:
            if an error occurs an exception is serialized and returned
        '''
        pol = {}

        try:
            param = getLowerParams(request.params)
            log.debug("[getPolicy] getting policy definitions: %r", param)

            scope = param.get("scope")
            pol = getPolicyDefinitions(scope)
            dynpol = self._add_dynamic_tokens(scope)
            pol.update(dynpol)

            c.audit['success'] = True
            c.audit['info'] = scope

            Session.commit()
            return sendResult(response, pol, 1)

        except Exception as exx:
            log.exception("[getPolicyDef] error getting policy "
                          "definitions: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

#########################################################
    def _add_dynamic_tokens(self, scope):
        '''
            add the policy description of the dynamic token

            :param scope: scope of the policy definition
            :type  scope: string

            :return: policy dict
            :rtype:  dict

        '''
        pol = {}

        for tclass_object in set(tokenclass_registry.values()):

            tok = tclass_object.getClassType()

            if hasattr(tclass_object, 'getClassInfo'):

                # check if we have a policy in the definition
                try:
                    policy = tclass_object.getClassInfo('policy', ret=None)
                    if policy is not None and scope in policy:
                        scope_policy = policy.get(scope)
                        pol.update(scope_policy)

                except Exception as exx:
                    log.info("[dynamicToken] no policy for tokentype %r "
                             "found (%r)", tok, exx)

        return pol

#########################################################
    def importPolicy(self):
        '''
        method:
            system/importPolicy

        description:
            This function is used to import policies from a file.

        arguments:
            file - mandatory: The policy file in the POST request
        '''

        # setup the response methods
        sendResultMethod = sendResult
        sendErrorMethod = sendError

        res = True
        try:

            log.debug("[importPolicy] getting POST request: %r", request.POST)

            policy_file = request.POST['file']
            fileString = ""
            log.debug("[importPolicy] loading policy file to server using POST"
                      " request. File: %r", policy_file)

            # -- ----------------------------------------------------------- --
            # In case of form post requests, it is a "instance" of FieldStorage
            # i.e. the Filename is selected in the browser and the data is
            # transferred in an iframe.
            #     see: http://jquery.malsup.com/form/#sample4
            # -- ----------------------------------------------------------- --

            if type(policy_file).__name__ == 'instance':
                log.debug("[importPolicy] Field storage file: %s", policy_file)
                fileString = policy_file.value
                sendResultMethod = sendXMLResult
                sendErrorMethod = sendXMLError
            else:
                fileString = policy_file

            log.debug("[importPolicy] fileString: %s", fileString)

            if fileString == "":
                log.error("[importPolicy] Error loading/importing policy "
                          "file. file empty!")
                return sendErrorMethod(response,
                                       "Error loading policy. File is empty!")

            # the contents of filestring needs to be parsed and
            # stored as policies.

            policies = ConfigObj(fileString.split('\n'), encoding="UTF-8")
            log.info("[importPolicy] read the following policies: %r",
                     policies)

            # -- ------------------------------------------------------ --
            # finally import the policies
            # -- ------------------------------------------------------ --
            res = import_policies(policies)

            c.audit['info'] = "Policies imported from file %s" % policy_file
            c.audit['success'] = 1

            Session.commit()

            return sendResultMethod(response, res)

        except Exception as exx:
            log.exception("[importPolicy] failed! %r", exx)
            Session.rollback()
            return sendErrorMethod(response, exx)

        finally:
            Session.close()

############################################################
    def checkPolicy(self):
        '''
        method:
            system/checkPolicy

        description:
            this function checks if a the given parameter will trigger a
            policy or not.

        arguments:
            * user   - the name of the user
            * realm  - the realm
            * scope  - the scope
            * action
            * client - the client IP

        returns:
            a json result like this:
              value : { "allowed" : "true",
                        "policy" : <Name der Policy, die das erlaubt hat> }
              value : { "allowed" : "false",
                         "info" : <sowas wie die Fehlermeldung> }

        '''
        res = {}

        try:
            param = getLowerParams(request.params)

            if 'user' not in param:
                raise ParameterError("missing required parameter: user")
            user = param["user"]

            if 'realm' not in param:
                raise ParameterError("missing required parameter: realm")
            realm = param["realm"]

            if 'scope' not in param:
                raise ParameterError("missing required parameter: scope")
            scope = param["scope"]

            if 'action' not in param:
                raise ParameterError("missing required parameter: action")
            action = param["action"]

            if 'client' not in param:
                raise ParameterError("missing required parameter: client")
            client = param["client"]

            pol = {}
            if scope in ["admin", "system"]:
                pol = search_policy({"scope": scope})
                if len(pol) > 0:
                    # Policy active for this scope!
                    pol = search_policy({"user": user,
                                         "realm": realm,
                                         "scope": scope,
                                         "action": action,
                                         "client": client})
                    res["allowed"] = len(pol) > 0
                    res["policy"] = pol
                    if len(pol) > 0:
                        c.audit['info'] = "allowed by policy %s" % pol.keys()
                else:
                    # No policy active for this scope
                    c.audit['info'] = ("allowed since no policies in scope %s"
                                       % scope)
                    res["allowed"] = True
                    res["policy"] = "No policies in scope %s" % scope
            else:
                log.debug("[checkPolicy] checking policy for client %s, "
                          "scope %s, action %s, realm %s and user %s",
                          client, scope, action, realm, user)

                pol = get_client_policy(client, scope, action, realm, user)
                res["allowed"] = len(pol) > 0
                res["policy"] = pol
                if len(pol) > 0:
                    c.audit['info'] = "allowed by policy %s" % pol.keys()

            c.audit['action_detail'] = ("action = %s, realm = %s, scope = %s"
                                        % (action, realm, scope))
            c.audit['success'] = True

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[checkPolicy] error checking policy: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

##########################################################################
    def getPolicy(self):
        """
        method:
            system/getPolicy

        description:
            this function is used to retrieve the policies that you
            defined.

        arguments:
            * realm - (optional) will return all policies in the given realm
            * name  - (optional) will only return the policy with the given
                                name
            * action  (optional) will only return the policy with the given
                                 action
            * user    (optional) will only return the policy for this user
            * scope - (optional) will only return the policies within the
                                 given scope
            * export - (optional) The filename needs to be specified as the
                                  third part of the URL like
                                  /system/getPolicy/policy.cfg.
                                  It will then be exported to this file.
            * display_inactive - (optional) if set, then also inactive policies
                                            will be displayed

        returns:
            a json result with the configuration of the specified policies

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = getLowerParams(request.params)

        log.debug("[getPolicy] getting policy: %r", param)
        export = None
        action = None
        user = None

        try:
            name = param.get("name")
            realm = param.get("realm")
            scope = param.get("scope")

            if 'action' in param:
                action = param.get('action') or None
            if 'user' in param:
                user = param.get('user') or None

            only_active = True
            display_inactive = param.get("display_inactive", False)
            if display_inactive:
                only_active = False

            route_dict = request.environ.get('pylons.routes_dict')
            export = route_dict.get('id')

            log.debug("[getPolicy] retrieving policy name: %s, realm: %s,"
                      " scope: %s", name, realm, scope)
            pol = {}
            if name is not None:
                for nam in name.split(','):
                    search_param = {'name': nam,
                                    'realm': realm,
                                    'scope': scope}
                    if action:
                        search_param['action'] = action
                    poli = search_policy(search_param,
                                         only_active=only_active)

                    pol.update(poli)
            else:

                search_param = {'name': name,
                                'realm': realm,
                                'scope': scope}
                if action:
                    search_param['action'] = action
                pol = search_policy(search_param,
                                    only_active=only_active)

            #
            # due to bug in getPolicy we have to post check
            # if user is in policy!
            #

            if user:
                rpol = {}
                for p_name, policy in pol.items():
                    if policy['user'] is None:
                        rpol[p_name] = policy
                    else:
                        users = policy['user'].split(',')
                        for usr in users:
                            if (usr.strip() == user.strip() or
                               usr.strip() == '*'):
                                rpol[p_name] = policy
                pol = rpol

            c.audit['success'] = True
            c.audit['info'] = ("name = %s, realm = %s, scope = %s"
                               % (name, realm, scope))

            Session.commit()

            if export:
                filename = create_policy_export_file(pol, export)
                wsgi_app = FileApp(filename)
                return wsgi_app(request.environ, self.start_response)
            else:
                return sendResult(response, pol, 1)

        except Exception as exx:
            log.exception("[getPolicy] error getting policy: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################
    def delPolicy(self):
        """
        method:
            system/delPolicy

        description:
            this function deletes the policy with the given name

        arguments:
            name  - the policy with the given name

        returns:
            a json result about the delete success

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        ret = {}
        param = {}
        try:
            param.update(request.params)
            log.info("[delPolicy] deleting policy: %r", param)

            # support the ignor of policy impact check
            enforce = param.get("enforce", 'False')
            if enforce.lower() == 'true':
                enforce = True
            else:
                enforce = False

            name_param = param["name"]
            names = name_param.split(',')
            for name in names:
                log.debug("[delPolicy] trying to delete policy %s", name)
                ret.update(deletePolicy(name, enforce))

            res["delPolicy"] = {"result": ret}

            c.audit['success'] = ret
            c.audit['info'] = name

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[delPolicy] error deleting policy: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################

    def setupSecurityModule(self):

        res = {}

        try:
            params = getLowerParams(request.params)
            log.debug("[setupSecurityModule] parameters: %r", params.keys())

            hsm_id = params.get('hsm_id', None)

            from linotp.lib.config.global_api import getGlobalObject
            glo = getGlobalObject()
            sep = glo.security_provider

            # for test purpose we switch to an errHSM
            if isSelfTest():
                if params.get('__hsmexception__') == '__ON__':
                    hsm = c.hsm.get('obj')
                    hsm_id = sep.activeOne
                    if type(hsm).__name__ == 'DefaultSecurityModule':
                        hsm_id = sep.setupModule('err', params)

                if params.get('__hsmexception__') == '__OFF__':
                    hsm = c.hsm.get('obj')
                    hsm_id = sep.activeOne
                    if type(hsm).__name__ == 'ErrSecurityModule':
                        hsm_id = sep.setupModule('default', params)

            if hsm_id is None:
                hsm_id = sep.activeOne
                hsm = c.hsm.get('obj')
                error = c.hsm.get('error')
                if hsm is None or len(error) != 0:
                    raise Exception("current activeSecurityModule >%r< is not"
                                    "initialized::%s:: - Please check your "
                                    "security module configuration and "
                                    "connection!" % (hsm_id, error))

                ready = hsm.isReady()
                res['setupSecurityModule'] = {'activeSecurityModule': hsm_id,
                                              'connected': ready}
                ret = ready
            else:
                if hsm_id != sep.activeOne:
                    raise Exception("current activeSecurityModule >%r< could"
                                    " only be changed through the "
                                    "configuration!" % sep.activeOne)

                ret = sep.setupModule(hsm_id, config=params)

                hsm = c.hsm.get('obj')
                ready = hsm.isReady()
                res['setupSecurityModule'] = {'activeSecurityModule': hsm_id,
                                              'connected': ready,
                                              'result': ret}

            c.audit['success'] = ret
            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[setupSecurityModule] : setup failed: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

########################################################

    def getSupportInfo(self):
        """
        return the support status, which is community support by default
        or the support subscription info, which could be the old license
        """
        res = {}
        try:

            (lic_info, _sig) = getSupportLicenseInfo()
            res = {}
            res.update(lic_info)

            c.audit['success'] = True
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("[getSupportInfo] : failed to access support info:"
                          " %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def isSupportValid(self):
        """
        verifies the support license status

        if ok
            status and value in response are both true
        else
            value is false and the detail is returned as detail in the response
        """

        res = {}
        info = {}
        contact_info = [
            "<h2>", _("Thank you for your interest in our products."), "</h2>",
            "",
            "<p>", _("Your current LinOTP Smart Virtual Appliance"
                     "demo license is about to expire in a few days. "
                     "For licenses for productive use or an extended "
                     "evaluation period, "),
            "<a href='mailto:sales@keyidentity.com'>", _("please contact us"), "</a>.</p>",
            "",
            "<p>", _("If you have questions about our products or your "
                     "evaluation we are happy to answer your inquiry. "
                     "We would also like to learn about your feedback "
                     "concerning our products and your evaluation."), "</p>",
            "",
            "<p class='center'><a href='mailto:sales@keyidentity.com'>sales@keyidentity.com</a></p>",
            "",
            "<p class='center'>", _("Sales hotline: "), "<a href='tel:+49615186086277'>", _("+49 6151 86086 277"), "</a></p>"
        ]

        contact_hint = " ".join(contact_info)

        try:

            license_txt = getFromConfig('license', '')
            try:
                licString = binascii.unhexlify(license_txt)
            except TypeError:
                licString = license_txt

            (res, msg,
             lic_info) = isSupportLicenseValid(licString)

            if res is False:
                info['reason'] = msg

            if do_nagging(lic_info, nag_days=7):
                info['download_licence_info'] = contact_hint

            c.audit['success'] = res
            Session.commit()
            return sendResult(response, res, 1, opt=info)

        except Exception as exx:
            log.exception("[isSupportValid] failed verify support info: %r",
                          exx)

            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def setSupport(self):
        """
        hook to load a support subscription file

        receives the data with a form post file upload
        and installes it after license verification
        """
        res = False
        message = None

        sendResultMethod = sendResult
        sendErrorMethod = sendError

        try:

            try:
                licField = request.POST['license']
            except KeyError as _keyerr:
                return sendErrorMethod(response, 'No key \'license\': '
                                       'Not a form request')

            response_format = request.POST.get('format', '')
            if response_format == 'xml':
                sendResultMethod = sendXMLResult
                sendErrorMethod = sendXMLError

            log.info("[setSupport] setting support: %s", licField)

            # In case of normal post requests, it is a "instance" of
            # FieldStorage
            if type(licField).__name__ == 'instance':
                log.debug("[setSupport] Field storage: %s", licField)
                support_description = licField.value
            else:
                # we got UTF-8!
                support_description = licField.encode('utf-8')
            log.debug("[setSupport] license %s", support_description)

            res, msg = setSupportLicense(support_description)
            if res is False:
                message = {'reason': msg}

            c.audit['success'] = res

            Session.commit()
            return sendResultMethod(response, res, 1, opt=message)

        except Exception as exx:
            log.exception("[setSupport] failed to set support license: %r",
                          exx)
            Session.rollback()
            return sendErrorMethod(response, exx)

        finally:
            Session.close()

    def setProvider(self):
        """
        method:
            system/setProvider

        description:
            creates or updates SMS- and Email-provider

        arguments:
            name        - the name of the provider in LinOTP
            type        - the type of the provider [email, sms]
            class       - the name of the provider
            config      - the configuration for this provider
            timeout     - the timeout

        :return: boolean - True or False with message in detail
        """

        res = {}
        params = {}

        try:
            params.update(request.params)
            try:
                name = params['name']
                p_type = params['type']
                _provider_class = params['class']
                _timeout = params['timeout']
            except KeyError as exx:
                raise ParameterError('missing key %r' % exx)

            # -------------------------------------------------------------- --

            # check if the provider is already defined as a managed one

            provider_def = getProvider(p_type, name)

            if not provider_def and 'managed' in params:

                # hash the provided password

                password = params['managed']

                params['managed'] = libcrypt_password(password)

            if provider_def and 'Managed' in provider_def[name]:

                if 'managed' not in params:
                    raise Exception('Not allowed to overwrite the '
                                    'configuration of a managed provider')

                password = params['managed']
                crypt_password = provider_def[name]['Managed']

                if libcrypt_password(
                        password, crypt_password) != crypt_password:

                    raise Exception('Not allowed to overwrite the '
                                    'configuration of a managed provider')

                params['managed'] = crypt_password

            # -------------------------------------------------------------- --

            res, reply = setProvider(params)

            c.audit['success'] = res
            c.audit['info'] = name

            Session.commit()
            return sendResult(response, res, 1, opt=reply)

        except Exception as exx:
            log.exception("error saving config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def getProvider(self):
        """
        method:
            system/getProviders

        description:
            get a dict of SMS- and Email-providers

        arguments:
            name (optional) - the name of the provider in LinOTP
            type - the type of the provider: SMS or EMail

        :return: dictionary of provider with its entries as dictionary
                 {'ProviderA' : { 'Timeout': '100', ...}
        """

        res = {}
        param = {}

        try:
            param.update(request.params)
            try:
                provider_type = param['type']
            except KeyError as exx:
                raise ParameterError('missing key %r' % exx)

            # optional parameters
            provider_name = param.get('name')

            res = getProvider(provider_type, provider_name, decrypted=True)
            if res:
                for provider_name, desc in res.items():
                    if 'Managed' in desc:
                        res[provider_name]['Managed'] = True

            c.audit['success'] = len(res) > 0
            if provider_name:
                c.audit['info'] = provider_name

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("error getting config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def testProvider(self):
        """
        method:
            system/testProviders

        description:
            if the provider has a test interface, the provider test is run

        arguments:
            name required - the name of the provider in LinOTP

        :return: dictionary of provider with its entries as dictionary
                 {'ProviderA' : { 'Timeout': '100', ...}
        """

        status = False
        p_response = "Can't Connect"
        param = {}

        try:
            param.update(request.params)
            try:
                provider_name = param['name']
                provider_type = param['type']
            except KeyError as exx:
                raise ParameterError('missing key %r' % exx)

            provider = loadProvider(provider_type=provider_type,
                                    provider_name=provider_name)
            if provider and hasattr(provider, 'test_connection'):
                status, p_response = provider.test_connection()

            c.audit['success'] = status
            c.audit['info'] = provider_name

            Session.commit()
            return sendResult(response, status, 1)

        except Exception as exx:
            log.exception("error getting config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()


    def delProvider(self):
        """
        method:
            system/delProviders

        description:
            delete a SMS- and Email-providers

        arguments:
            name - the name of the SMS or EMail Provider
            type - the provider type

        :return: boolean, true if number of deleted config entries is > 0
                          else False with message in detail
        """

        res = {}
        params = {}

        try:
            params.update(request.params)
            try:
                provider_name = params['name']
                provider_type = params['type']
            except KeyError as exx:
                raise ParameterError('missing key %r' % exx)

            provider_def = getProvider(provider_type, provider_name)

            if (provider_def and provider_name in provider_def and
                'Managed' in provider_def[provider_name]):

                if 'managed' not in params:
                    raise Exception('Not allowed to delete the '
                                    'managed provider')

                password = params['managed']
                crypt_password = provider_def[provider_name]['Managed']

                if libcrypt_password(
                        password, crypt_password) != crypt_password:

                    raise Exception('Not allowed to delete the '
                                    'managed provider')

            res, reply = delProvider(provider_type, provider_name)

            c.audit['success'] = res > 0
            c.audit['info'] = provider_name

            Session.commit()
            return sendResult(response, res > 0, 1, opt=reply)

        except Exception as exx:
            log.exception("error saving config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def setDefaultProvider(self):
        """
        method:
            system/setDefaultProvider

        description:
            set provider (SMS- and Email) as default

        arguments:
            name - the name of the SMS or EMail Provider
            type - the provider type

        :return: boolean, true if number of deleted config entries is > 0
                          else False with message in detail
        """

        res = {}
        params = {}

        try:
            params.update(request.params)
            try:
                provider_name = params['name']
                provider_type = params['type']
            except KeyError as exx:
                raise ParameterError('missing key %r' % exx)

            res, reply = setDefaultProvider(provider_type, provider_name)

            c.audit['success'] = res
            c.audit['info'] = provider_name

            Session.commit()
            return sendResult(response, res, 1, opt=reply)

        except Exception as exx:
            log.exception("error saving config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def getProviderDef(self):
        """
        method:
            system/getProviderDef

        description:
            get definition of a provider - used for automatic rendering

        arguments:
            type (required) - the provider type
            class (optional) - the specific class definition or the parent
                               class definition if not specified
        :return:  dictionary with the class as key and the parameters with
                  their types as dictionaries
        """

        res = {}
        params = {}

        try:
            params.update(request.params)
            try:
                _provider_name = params['name']
                _provider_type = params['type']
            except KeyError as exx:
                raise ParameterError('missing key %r' % exx)

            # TODO:  to be implemented
            res = {}

            Session.commit()
            return sendResult(response, res, 1)

        except Exception as exx:
            log.exception("error saving config: %r", exx)
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()


# eof #########################################################################
