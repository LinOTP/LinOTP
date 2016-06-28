# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
""" resolver objects and processing """


import logging
import re
import copy

from linotp.lib.context import request_context as context

from linotp.lib.config import storeConfig
from linotp.lib.config import getGlobalObject
from linotp.lib.config import removeFromConfig
from linotp.lib.config import getLinotpConfig

from linotp.lib.util import getParam
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
        # We should have no \.
        # This only leads to problems.
        nameExp = "^[A-Za-z0-9_\-]+$"
        if re.match(nameExp, self.name) is None:
            exx = Exception("non conformant characters in resolver name: %s "
                          " (not in %s)", self.name, nameExp)
            raise exx

        # handle types
        self.type = getParam(param, 'type', required)
        resolvertypes = get_resolver_types()
        if self.type not in resolvertypes:
            exx = Exception("resolver type : %s not in %s" %
                          (self.type, unicode(resolvertypes)))
            raise exx

        resolver_config = get_resolver_class_config(self.type)
        if self.type in resolver_config:
            config = resolver_config.get(self.type).get('config', {})
        else:
            config = resolver_config

        for k in param:
            if k != 'name' and k != 'type':
                if k.startswith('type.') is True:
                    key = k[len('type.'):]
                    self.types[key] = param.get(k)
                elif k.startswith('desc.') is True:
                    key = k[len('desc.'):]
                    self.desc[key] = param.get(k)

                elif 'session' == k:
                    # supress session parameter
                    pass
                else:
                    self.data[k] = param.get(k)
                    if k in config:
                        self.types[k] = config.get(k)
                    else:
                        log.warn("[setDefinition]: the passed key %r is not a "
                                 "parameter for the resolver %r" % (k, self.type))
        # now check if we have for every type def an parameter
        ok = self._sanityCheck()
        if ok is not True:
            raise Exception("type definition does not match parameter! %s"
                            % unicode(param))

        return

    def _sanityCheck(self):
        ret = True
        for t in self.types:
            if self.data.has_key(t) is False:
                ret = False
        for t in self.desc:
            if self.data.has_key(t) is False:
                ret = False

        return ret

    def saveConfig(self):
        res = 'success'
        if self.name is None:
            return "no resolver name defined"
        # do the setConfig()'s
        prefix = self.type + "."
        postfix = "." + self.name

        for d in self.data:
            key = prefix + d + postfix
            val = self.data.get(d)
            typ = None
            desc = None
            if d in self.types:
                typ = self.types.get(d)

            if d in self.desc:
                desc = self.desc.get(d)

            res = storeConfig(key, val, typ, desc)

        return res


def defineResolver(params):
    """
    set up a new resolver from request parameters

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

    resolver = Resolver()
    resolver.setDefinition(params)
    res = resolver.saveConfig()

    resolver = getResolverObject(resolver_clazz + '.' + conf)

    return resolver is not None


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


def getResolverInfo(resolvername):
    '''
    return the resolver info of the given resolvername

    :param resolvername: the requested resolver
    :type  resolvername: string

    :return : dict of resolver description
    '''
    resolver_dict = {}
    typ = ""
    resolvertypes = get_resolver_types()

    descr = {}

    conf = context.get('Config')
    # conf = getLinotpConfig()

    for entry in conf:

        for typ in resolvertypes:

            # get the typed values of the descriptor!
            resolver_conf = get_resolver_class_config(typ)
            if typ in resolver_conf:
                descr = resolver_conf.get(typ).get('config', {})
            else:
                descr = resolver_conf

            if entry.startswith("linotp." + typ) and entry.endswith(resolvername):
                # the realm might contain dots "."
                # so take all after the 3rd dot for realm
                resolver = entry.split(".", 3)
                # An old entry without resolver name
                if len(resolver) <= 3:
                    break

                value = conf.get(entry)
                if resolver[2] in descr:
                    configEntry = resolver[2]
                    if descr.get(configEntry) == 'password':

                        # do we already have the decrypted pass?
                        if 'enc' + entry in conf:
                            value = conf.get('enc' + entry)
                        else:
                            # if no, we take the encpass and decrypt it
                            value = conf.get(entry)
                            try:
                                en = decryptPassword(value)
                                value = en
                            except:
                                log.info("Decryption of resolver passwd failed: compatibility issue?")

                resolver_dict[resolver[2]] = value
                # Dont check the other resolver types

                break

    return {"type": typ, "data": resolver_dict, "resolver": resolvername}


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

    if len(delEntries) > 0:
        try:
            for entry in delEntries:
                res = removeFromConfig(entry)
                log.debug("[deleteResolver] removing key: %s" % entry)
                res = True
        except Exception as e:
            log.exception("deleteResolver: %r" % e)
            res = False


    return res


# external in token.py user.py validate.py
def getResolverObject(resolver_spec):

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

        config = getLinotpConfig()
        try:
            resolver.loadConfig(config, config_identifier)
        except:
            # FIXME: Except clause is too general. resolver
            # exceptions in the useridresolver modules should
            # have their own type, so we can filter here
            log.error('resolver config loading failed for resolver with '
                      'specification %s' % resolver_spec)
            return None
        resolvers_loaded[resolver_spec] = resolver

        return resolver

# external lib/base.py
def setupResolvers(config=None, cache_dir="/tmp"):
    """
    hook for the server start -
        initialize the resolvers
    """
    glo = getGlobalObject()

    resolver_classes = copy.deepcopy(glo.getResolverClasses())
    for resolver_cls in resolver_classes.values():
        if hasattr(resolver_cls, 'setup'):
            try:
                resolver_cls.setup(config=config, cache_dir=cache_dir)
            except:
                log.exception("failed to call setup of %r" % resolver_cls)

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
    return

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

