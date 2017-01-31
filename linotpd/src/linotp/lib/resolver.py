# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
""" resolver objects and processing """


import logging
import re
import copy
import json
from functools import partial

from linotp.lib.context import request_context as context

from linotp.lib.config import storeConfig
from linotp.lib.config import getGlobalObject
from linotp.lib.config import removeFromConfig
from linotp.lib.config import getLinotpConfig

from linotp.lib.util import getParam

from linotp.lib.type_utils import get_duration

from linotp.lib.crypt import decryptPassword

required = True
optional = False


__all__ = ['defineResolver', 'parse_resolver_spec',
           'getResolverList', 'getResolverInfo', 'deleteResolver',
           'getResolverObject', 'initResolvers', 'closeResolvers',
           'setupResolvers'
          ]

log = logging.getLogger(__name__)


class Resolver(object):
    """
    helper class to define a new resolver
    """
    def __init__(self, name=None):
        self.name = name
        self.type = None
        self.data = {}
        self.types = {}
        self.desc = {}

    def getDefinition(self, param):
        self.name = getParam(param, 'resolver', required)
        return getResolverInfo(self.name)

    def setDefinition(self, param):
        '''
            handle name
        '''
        self.name = getParam(param, 'name', required)

        # We should have no \. in resolver name
        # This only leads to problems.
        nameExp = "^[A-Za-z0-9_\-]+$"
        if re.match(nameExp, self.name) is None:
            exx = Exception("non conformant characters in resolver name: %s "
                            " (not in %s)", self.name, nameExp)
            raise exx

        # handle resolver types
        self.type = getParam(param, 'type', required)
        resolvertypes = get_resolver_types()
        if self.type not in resolvertypes:
            exx = Exception("resolver type : %s not in %s" %
                            (self.type, unicode(resolvertypes)))
            raise exx

        #
        # retrieve the resolver typing info

        resolver_config = get_resolver_class_config(self.type)
        if self.type in resolver_config:
            res_config = resolver_config.get(self.type).get('config', {})
        else:
            res_config = resolver_config

        #
        # process the provided arguments

        for key, data_ in param.items():
            type_ = None
            desc_ = None

            #
            # skip not necessary parameter

            if key in ['name', 'type', 'session']:
                continue

            #
            # skip parameterized type and description entries
            # - we integrate these information below

            if key.startswith('desc.') or key.startswith('type.'):
                continue
            #
            # get the 'type' information from the resolver

            if key in res_config:
                type_ = res_config[key]

            #
            # if provided use type information from the parameters and
            # overwrite the resolver specific typing

            if 'type.' + key in param:
                type_ = param["type." + key]

            #
            # if provided, use description information from the parameters

            if 'desc.' + key in param:
                desc_ = param["desc." + key]

            self.data[key] = (data_, type_, desc_)

        return

    def getConfig(self, linotp_prefix=''):
        """
        generator to access the resolver entries

        :param linotp_prefix: the pre prefix for the key
        :return: generator for the access of the next() element
        """

        if self.name is None:
            raise Exception("no resolver name defined")

        #
        # prepare the fully qualified key name

        prefix = "%s%s" % (linotp_prefix, self.type)
        postfix = self.name

        for entry_name, entry in self.data.items():

            key = "%s.%s.%s" % (prefix, entry_name, postfix)
            val, type_, desc = entry

            yield key, val, type_, desc

    def saveConfig(self):
        """
        save the processed config to the global linotp config and to the db

        """
        res = True

        config = self.getConfig()

        for entry in config:
            key, val, type_, desc = entry
            res = storeConfig(key, val, type_, desc)

        return res


def defineResolver(params):
    """
    set up a new resolver from request parameters

    the setup of the resolver includes the loading of the resolver config.
    this is required to allow the resolver to check if all required parameters
    are available.

    As the resolver (for historical reasons) has access to the overall LinOTP
    config, we have to prepare the resolver definition, which is done by the
    Resolver() class. Thus during the defineResolver, we have first to merge
    the LinOTP config with the new resolver config (from the params) and if the
    loading of the config went well, we will do the saving of the resolver.

    :param params: dict of request parameters
    """

    typ = params['type']
    conf = params['name']
    resolver_clazz = None

    for clazz_name, clazz_type in context.get('resolver_types').items():
        if typ.lower() in clazz_type.lower():
            resolver_clazz = clazz_name

    if not resolver_clazz:
        raise Exception("no such resolver type '%r' defined!" % typ)

    resolver_spec = resolver_clazz + '.' + conf

    #
    # we have to add the system wide configurations like
    # "linotp.certificates.use_system_certificates"

    config = {}
    lconf = context['Config']
    config.update(lconf)

    #
    # get the adjusted resolver configuration from the parameters

    rconf = {}
    resolver_definition = Resolver()
    resolver_definition.setDefinition(params)

    resolver_config = resolver_definition.getConfig(linotp_prefix='linotp.')

    for entry in resolver_config:
        key, val, _type_, _desc = entry
        rconf[key] = val

    #
    # merge that config definition into the overall config, which is required
    # for the loading of the resolvers - that will do the check if all
    # required parameter are provided

    config.update(rconf)

    resolver = getResolverObject(resolver_spec, config=config)

    if resolver is None:
        return False

    #
    # if all went fine we finally save the config and
    # in case of an update, flush the cache

    resolver_definition.saveConfig()
    _flush_user_resolver_cache(resolver_spec)
    return resolver


def similar_resolver_exists(config_identifier):
    """
    Signifies if a resolver identified by config_identifer
    exists in the configuration.

    :remark: matches case insensitive

    :returns: bool
    """

    config = context.get('Config')
    cls_identifiers = context.get('resolver_classes').keys()

    for config_entry in config:
        for cls_identifier in cls_identifiers:
            if config_entry.startswith('linotp.' + cls_identifier):
                __, __, entry_config_identifier = config_entry.rpartition('.')
                if entry_config_identifier.lower() == config_identifier.lower():
                    return True

    return False


def get_cls_identifier(config_identifier):

    """
    Returns the class identifier string for a existing resolver
    identified by config_identifier (or None, if config_identifier
    doesn't exist)
    """

    config = context.get('Config')
    cls_identifiers = context.get('resolver_classes').keys()

    for config_entry in config:

        if not config_entry.endswith(config_identifier):
            continue

        for cls_identifier in cls_identifiers:
            if config_entry.startswith('linotp.' + cls_identifier):
                return cls_identifier

    return None

# external system/getResolvers
def getResolverList(filter_resolver_type=None):
    '''
    Gets the list of configured resolvers

    :param filter_resolver_type: Only resolvers of the given type are returned
    :type filter_resolver_type: string
    :rtype: Dictionary of the resolvers and their configuration
    '''
    Resolvers = {}
    resolvertypes = get_resolver_types()

    conf = context.get('Config')
    # conf = getLinotpConfig()
    for entry in conf:

        for typ in resolvertypes:
            if entry.startswith("linotp." + typ):
                # the realm might contain dots "."
                # so take all after the 3rd dot for realm
                r = {}
                resolver = entry.split(".", 3)
                # An old entry without resolver name
                if len(resolver) <= 3:
                    break
                r["resolvername"] = resolver[3]
                r["entry"] = entry
                r["type"] = typ

                if ((filter_resolver_type is None) or
                        (filter_resolver_type and filter_resolver_type == typ)):
                    Resolvers[resolver[3]] = r
                # Dont check the other resolver types
                break

    return Resolvers


def getResolverInfo(resolvername, passwords=False):
    '''
    return the resolver info of the given resolvername

    :param resolvername: the requested resolver
    :type  resolvername: string

    :return : dict of resolver description
    '''

    result = {"type": None, "data": {}, "resolver": resolvername}

    resolver_dict = {}
    descr = {}

    resolver_entries = {}
    resolvertypes = get_resolver_types()

    linotp_config = context.get('Config')

    for typ in resolvertypes:
        for config_entry in linotp_config:
            if (config_entry.startswith("linotp." + typ) and
               config_entry.endswith(resolvername)):
                resolver_entries[config_entry] = linotp_config.get(config_entry)

    if not resolver_entries:
        return result

    resolver_parts = resolver_entries.keys()[0].split('.')

    #
    # TODO: remove legacy code: An old entry without resolver name
    #
    if len(resolver_parts) <= 3:
        return result

    #
    # get the type descriptions for the resolver type
    #

    resolver_type = resolver_parts[1]
    resolver_conf = get_resolver_class_config(resolver_type)

    if resolver_type in resolver_conf:
        resolver_descr = resolver_conf.get(resolver_type).get('config', {})
    else:
        resolver_descr = resolver_conf

    #
    # build up the resolver dictionary
    #

    for key, value in resolver_entries.items():
        resolver_key = key.split(".")[2]

        if resolver_key in resolver_descr:

            if (resolver_descr.get(resolver_key) == 'password' and
               passwords is True):

                # do we already have the decrypted pass?
                if 'enc%s' % key in linotp_config:
                    value = linotp_config.get('enc%s' % key)
                else:
                    # if no, we take the entry and try to de crypt it
                    value = linotp_config.get(key)

                    try:
                        value = decryptPassword(value)
                    except Exception as exc:
                        log.exception("Decryption of resolver entry "
                                      "failed: %r", exc)

        resolver_dict[resolver_key] = value

    result["type"] = resolver_type
    result["data"] = resolver_dict

    return result


def deleteResolver(resolvername):
    '''
    delete a resolver and all related config entries

    :paramm resolvername: the name of the to be deleted resolver
    :type   resolvername: string
    :return: sucess or fail
    :rtype:  boelean

    '''
    res = False

    resolvertypes = get_resolver_types()
    conf = context.get('Config')
    # conf = getLinotpConfig()

    delEntries = []
    resolver_specs = set()

    for entry in conf:
        rest = entry.split(".", 3)
        lSplit = len(rest)
        if lSplit > 3:
            rConf = rest[lSplit - 1]
            if rConf == resolvername:
                if rest[0] == "linotp" or rest[0] == "enclinotp":
                    typ = rest[1]
                    if typ in resolvertypes:
                        delEntries.append(entry)
                        resolver_conf = get_resolver_class_config(typ)
                        resolver_class = resolver_conf.get(typ, {}).get('clazz')
                        fqn = ".".join([resolver_class, resolvername])
                        resolver_specs.add(fqn)

    if len(delEntries) > 0:
        try:
            for entry in delEntries:
                res = removeFromConfig(entry)
                log.debug("[deleteResolver] removing key: %s" % entry)
                res = True
        except Exception as e:
            log.exception("deleteResolver: %r" % e)
            res = False

    if res:
        # on success we can flush the caches
        for resolver_spec in resolver_specs:
            _flush_user_resolver_cache(resolver_spec)
            _delete_from_resolver_config_cache(resolver_spec)

    return res


def getResolverClass(resolver_type, resolver_conf=''):
    """
    get the resolver class for an resolver type

    :param resolver_type: string like 'ldapresolver'
    :return: class or None
    """

    resolver_clazz = None

    for clazz_name, clazz_type in context.get('resolver_types').items():
        if resolver_type.lower() in clazz_type.lower():
            resolver_clazz = clazz_name

    if not resolver_clazz:
        raise Exception("no such resolver type '%r' defined!" % resolver_type)

    resolver_spec = resolver_clazz + '.' + resolver_conf

    cls_identifier, _config_identifier = parse_resolver_spec(resolver_spec)

    if not cls_identifier :
        log.error('Format error: resolver_spec must have the format '
                  '<resolver_class_identifier>.<config_identifier>, but '
                  'value was %s' % resolver_spec)
        return None

    resolver_cls = get_resolver_class(cls_identifier)

    return resolver_cls


# external in token.py user.py validate.py
def getResolverObject(resolver_spec, config=None, load_config=True):

    """
    get the resolver instance from a resolver specification.

    :remark: internally this function uses the request context for caching.

    :param resolver_spec: the resolver string as from the token including
                          the config identifier.

                          format:
                          <resolver class identifier>.<config identifier>

    :return: instance of the resolver with the loaded config (or None
             if specification was invalid or didn't match a resolver)

    """

    #  this patch is a bit hacky:
    # the normal request has a request context, where it retrieves
    # the resolver info from and preserves the loaded resolvers for reusage
    # But in case of a authentication request (by a redirect from a 401)
    # the caller is no std request and the context object is missing :-(
    # The solution is to deal with local references, either to the
    # global context or to local data (where we have no reuse of the resolver)

    resolvers_loaded = context.setdefault('resolvers_loaded', {})

    if not config:
        config = getLinotpConfig()

    # test if the resolver is in the cache
    if resolver_spec in resolvers_loaded:
        return resolvers_loaded.get(resolver_spec)

    # no resolver - so instatiate one
    else:

        cls_identifier, config_identifier = parse_resolver_spec(resolver_spec)

        if not cls_identifier or not config_identifier:
            log.error('Format error: resolver_spec must have the format '
                      '<resolver_class_identifier>.<config_identifier>, but '
                      'value was %s' % resolver_spec)
            return None

        resolver_cls = get_resolver_class(cls_identifier)

        if resolver_cls is None:
            log.error('unknown resolver class: %s' % cls_identifier)
            return None

        resolver = resolver_cls()

        if load_config:

            try:
                resolver.loadConfig(config, config_identifier)
            except Exception as exx:
                # FIXME: Except clause is too general. resolver
                # exceptions in the useridresolver modules should
                # have their own type, so we can filter here
                log.error('resolver config loading failed for resolver with '
                          'specification %s: %r', resolver_spec, exx)
                return None

            # in case of the replication there might by difference
            # in the used resolver config and the config from the LinOTP config
            _check_for_resolver_cache_flush(resolver_spec, config_identifier)

            resolvers_loaded[resolver_spec] = resolver

        return resolver


def _check_for_resolver_cache_flush(resolver_spec, config_identifier):
    """
    check if the current resolver config is still the current one

    this is done by using as well the caching with a dedicated cache
    that holds the former configuration. If the current config does not match
    the retrieved value, the cache is out dated and we have to flush the
    related caches

    :param resolver_spec: resolver spec - fully qualified resolver
    :param config_identifier: the resolver config identifier
    """

    resolver_config = _get_resolver_config(config_identifier)
    resolver_config_dump = json.dumps(resolver_config)

    res_conf_hash = _lookup_resolver_config(resolver_spec, resolver_config)

    if res_conf_hash != resolver_config_dump:
        # now we delete the user_resolver cache
        _flush_user_resolver_cache(resolver_spec)

        # and establish the new config in the resolver config cache
        # by deleting the reference key and adding the entry

        _delete_from_resolver_config_cache(resolver_spec)
        _lookup_resolver_config(resolver_spec, resolver_config)

    return


def _flush_user_resolver_cache(resolver_spec):
    """
    flush the user realm cache
        in case of a change of the resolver, all realms which use
        this resolver must be flushed

    :param resolver_spec: the resolve which has been updated
    :return: - nothing -
    """

    from linotp.lib.user import delete_resolver_user_cache
    from linotp.lib.user import delete_realm_resolver_cache

    delete_resolver_user_cache(resolver_spec)

    config = context["Config"]
    realms = config.getRealms()

    # if a resolver is redefined, we have to refresh the related realm cache
    for realm_name, realm_spec in realms.items():
        resolvers = realm_spec.get('useridresolver', [])
        if resolver_spec in resolvers:
            delete_realm_resolver_cache(realm_name)


def _get_resolver_config(resolver_config_identifier):
    """
    get the resolver config of a resolver identified by its config identifier
        helper to access the resolver configuration

    :param resolver_config_identifier: resolver config identifier as string
    :return: dict with the resolver configuration
    """

    # identify the fully qualified resolver spec by all possible resolver
    # prefixes, which are taken from the resolver_classes list
    lookup_keys = []
    config_keys = context['resolver_classes'].keys()
    for entry in config_keys:
        lookup_keys.append('linotp.' + entry)

    # we got the resolver prefix, now we can search in the config for
    # all resolver configuration entries
    resolver_config = {}
    config = context['Config']

    for key, value in config.items():
        if key.endswith(resolver_config_identifier):
            for entry in lookup_keys:
                if key.startswith(entry):
                    resolver_config[key] = value

    return resolver_config


# -- -------------------------------------------------------------------- --

def _lookup_resolver_config(resolver_spec, resolver_config=None):
    """
    lookup resolver configuration for a given resolver spec

    :param resolver_spec: resolver specification (full qualified)
    :param resolver_config: used for cache filling

    :return: resolver configuration as dict
    """

    def __lookup_resolver_config(resolver_spec, resolver_config=None):
        """
        inner function which is called on a cache miss

        :param resolver_spec: resolver specification (full qualified)
        :param resolver_config: used for cache filling

        :return: resolver configuration as dict

        """
        if resolver_config:
            return json.dumps(resolver_config)

        return None

    # get the resolver configuration cache, if any
    resolver_config_cache = _get_resolver_config_cache()
    if not resolver_config_cache:
        return __lookup_resolver_config(resolver_spec, resolver_config)

    # define the cache lookup function as partial as the standard
    # beaker cache manager does not support arguments
    # for the inner cache function
    p_lookup_resolver_config = partial(__lookup_resolver_config,
                                       resolver_spec, resolver_config)

    p_key = resolver_spec

    # retrieve config from the cache, accessed by the p_key
    conf_hash = resolver_config_cache.get_value(key=p_key,
                                        createfunc=p_lookup_resolver_config,
                                                )

    return conf_hash


def _get_resolver_config_cache():
    """
    helper - common getter to access the resolver_config cache

    the resolver config cache is used to track the resolver configuration
    changes. therefore for each resolver spec the resolver config is stored
    in a cache. In case of an request the comparison of the resolver config
    with the cache value is made and in case of inconsistancy the resolver
    user cache is flushed.

    :remark: This cache is only enabled, if the resolver user lookup cache
             is enabled too

    :return: the resolver config cache
    """

    config = context['Config']

    enabled = config.get('linotp.resolver_lookup_cache.enabled',
                         'True') == 'True'
    if not enabled:
        return None

    try:
        expiration_conf = config.get('linotp.resolver_lookup_cache.expiration',
                                     36 * 3600)

        expiration = get_duration(expiration_conf)

    except ValueError:
        log.info("resolver caching is disabled due to a value error in "
                 "resolver_lookup_cache.expiration config")
        return None

    cache_manager = context['CacheManager']
    cache_name = 'resolver_config'
    resolver_config_cache = cache_manager.get_cache(cache_name,
                                                    type="memory",
                                                    expiretime=expiration)

    return resolver_config_cache


def _delete_from_resolver_config_cache(resolver_spec):
    """
    delete one entry from the resolver config lookup cache
    :param resolver_spec: the resolver spec (fully qualified)
    :return: - nothing -
    """
    resolver_config_cache = _get_resolver_config_cache()
    if resolver_config_cache:
        resolver_config_cache.remove_value(key=resolver_spec)


# external lib/base.py
def setupResolvers(config=None, cache_dir="/tmp"):
    """
    hook at the server start to initialize the resolvers classes

    :param config: the linotp config
    :param cache_dir: the cache directory, which could be used in each resolver

    :return: -nothing-
    """

    glo = getGlobalObject()
    resolver_classes = copy.deepcopy(glo.getResolverClasses())

    # resolver classes is a dict with aliases as key and the resolver classes
    # as values - as we require only unique classes we put them in a set.
    # On server startup  we call the setup once for each resolver class.

    for resolver_cls in set(resolver_classes.values()):
        if hasattr(resolver_cls, 'setup'):
            try:
                resolver_cls.setup(config=config, cache_dir=cache_dir)
            except Exception as exx:
                log.exception("failed to call setup of %r; %r",
                              resolver_cls, exx)

    return


def initResolvers():
    """
    hook for the request start -
        create  a deep copy of the dict with the global resolver classes
    """
    try:
        glo = getGlobalObject()

        resolver_classes = copy.deepcopy(glo.getResolverClasses())
        resolver_types = copy.deepcopy(glo.getResolverTypes())

        context['resolver_classes'] = resolver_classes
        context['resolver_types'] = resolver_types
        # dict of all resolvers, which are instatiated during the request
        context['resolvers_loaded'] = {}

    except Exception as exx:
        log.exception("Failed to initialize resolver in context %r" % exx)
    return context

# external lib/base.py
def closeResolvers():
    """
    hook to close the resolvers at the end of the request
    """
    try:
        for resolver in context.get('resolvers_loaded', {}).values():
            if hasattr(resolver, 'close'):
                resolver.close()
    except Exception as exx:
            log.exception("Failed to close resolver in context %r" % exx)
    return

def getResolverClassName(resolver_type, resolver_name):

    res = ""
    for clazz_name, clazz_type in context.get('resolver_types', {}).items():
        if clazz_type == resolver_type:
            res = "%s.%s" % (clazz_name, resolver_name)
            break

    return res


# internal functions
def get_resolver_class(cls_identifier):
    '''
    return the class object for a resolver type
    :param resolver_type: string specifying the resolver
                          fully qualified or abreviated
    :return: resolver object class
    '''

    # ## this patch is a bit hacky:
    # the normal request has a request context, where it retrieves
    # the resolver info from and preserves the loaded resolvers for reusage
    # But in case of a authentication request (by a redirect from a 401)
    # the caller is no std request and the context object is missing :-(
    # The solution is, to deal with local references, either to the
    # global context or to local data

    resolver_classes = context.get('resolver_classes')
    if resolver_classes is None:
        glo = getGlobalObject()
        resolver_classes = copy.deepcopy(glo.getResolverClasses())

    return resolver_classes.get(cls_identifier)


def get_resolver_types():
    """
    get the array of the registred resolvers

    :return: array of resolvertypes like 'passwdresolver'
    """
    return context.get('resolver_types').values()


def get_resolver_class_config(claszzesType):
    """
    get the configuration description of a resolver

    :param claszzesType: literal resolver type
    :return: configuration description dict
    """
    descriptor = None
    resolver_class = get_resolver_class(claszzesType)

    if resolver_class is not None:
        descriptor = resolver_class.getResolverClassDescriptor()

    return descriptor


def parse_resolver_spec(resolver_spec):

    """
    expects a resolver specification and returns a tuple
    containing the resolver class identifier and the config
    identifier

    :param resolver_spec: a resolver specification

                          format:
                          <resolver class identifier>.<config identifier>

    :return: (cls_identifier, config_identifier)

    """

    cls_identifier, _sep, config_identifier = resolver_spec.rpartition('.')
    return cls_identifier, config_identifier

# eof #########################################################################

