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
"""  Pylons environment configuration """

import os
from os import listdir


from mako.lookup import TemplateLookup
from pylons import config
from pylons.error import handle_mako_error
from sqlalchemy import engine_from_config

import linotp.lib.app_globals as app_globals
import linotp.lib.helpers

from useridresolver.UserIdResolver import UserIdResolver
from linotp.config.routing import make_map
from linotp.lib.error import TokenTypeNotSupportedError


import sys
import inspect
import urllib2
import pkg_resources

import warnings
warnings.filterwarnings(action='ignore', category=DeprecationWarning)


def _uniqify_list(input_list):
    """
    Returns a list containing only unique elements from input_list whilst
    preserving the original order.
    See http://www.peterbe.com/plog/uniqifiers-benchmark
    """
    seen = {}
    result = []
    for item in input_list:
        if item in seen:
            continue
        seen[item] = 1
        result.append(item)
    return result


def fxn():
    warnings.warn("deprecated", DeprecationWarning)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    fxn()

import logging

log = logging.getLogger(__name__)


def load_environment(global_conf, app_conf):
    """
    Configure the Pylons environment via the ``pylons.config``
    object
    """

    # Pylons paths
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = dict(root=root,
                 controllers=os.path.join(root, 'controllers'),
                 static_files=os.path.join(root, 'public'),
                 templates=[app_conf.get('custom_templates',
                                         os.path.join(root, 'templates')),
                            os.path.join(root, 'templates')])

    # Initialize config with the basic options
    config.init_app(global_conf, app_conf, package='linotp', paths=paths)

    config['linotp.root'] = root
    config['routes.map'] = make_map(global_conf, app_conf)
    config['pylons.app_globals'] = app_globals.Globals()
    config['pylons.h'] = linotp.lib.helpers

    # add per token a location for the mako template lookup
    # @note: the location is defined in the .ini file by
    # the entry [linotpTokenModules]

    directories = paths['templates']

    # add a template path for every token
    modules = get_token_module_list()
    for module in modules:
        mpath = os.path.dirname(module.__file__)
        directories.append(mpath)

    # add a template path for every resolver
    modules = get_resolver_module_list()
    for module in modules:
        mpath = os.path.dirname(module.__file__)
        directories.append(mpath)

    unique_directories = _uniqify_list(directories)
    log.debug("[load_environment] Template directories: %r" % unique_directories)

    config['pylons.app_globals'].mako_lookup = TemplateLookup(
        directories=unique_directories,
        error_handler=handle_mako_error,
        module_directory=os.path.join(app_conf['cache_dir'], 'templates'),
        input_encoding='utf-8', default_filters=['escape'],
        imports=['from webhelpers.html import escape'])

    # Setup the SQLAlchemy database engine
    # If we load the linotp.model here, the pylons.config is loaded with
    # the entries from the config file. if it is loaded at the top of the file,
    # the pylons.config does not contain the config file, yet.
    from linotp.model import init_model
    engine = engine_from_config(config, 'sqlalchemy.')
    init_model(engine)

    # CONFIGURATION OPTIONS HERE (note: all config options will override
    # any Pylons config options)

    from linotp.lib.audit.base import getAudit
    audit = getAudit()
    config['audit'] = audit

    # setup Security provider definition
    try:
        log.debug('[load_environment] loading token list definition')
        g = config['pylons.app_globals']
        g.security_provider.load_config(config)
    except Exception as e:
        log.exception("Failed to load security provider definition: %r" % e)
        raise e

    # load the list of tokenclasses
    try:
        log.debug('[load_environment] loading token list definition')
        (tcl, tpl) = get_token_class_list()

        config['tokenclasses'] = tcl
        g.setTokenclasses(tcl)

        config['tokenprefixes'] = tpl
        g.setTokenprefixes(tpl)

    except Exception as e:
        log.exception("Failed to load token class list: %r" % e)
        raise e

    # load the list of resolvers
    try:
        log.debug('[load_environment] loading resolver list definition')
        (rclass, rname) = get_resolver_class_list()

        # make this globaly avaliable
        g.setResolverClasses(rclass)
        g.setResolverTypes(rname)

    except Exception as exx:
        log.exception("Faild to load the list of resolvers: %r" % exx)
        raise exx

    # get the help url
    url = config.get("linotpHelp.url", None)
    if url is None:
        version = pkg_resources.get_distribution("linotp").version
        # First try to get the help for this specific version
        url = "https://linotp.org/doc/%s/index.html" % version
    config['help_url'] = url

    log.debug("[load_environment] done")
    return config

#######################################


def get_token_list():
    '''
    returns the list of the modules

    :return: list of token module names from the config file
    '''
    module_list = []

    # append our derfault list so this will overwrite in
    # the loaded classes finally
    module_list.append("linotp.lib.tokenclass")

    fallback_tokens = get_default_tokens()

    config_modules = config.get("linotpTokenModules", ",".join(fallback_tokens))
    log.debug("[get_module_list] %s " % config_modules)
    if config_modules:
        # in the config *.ini files we have some line continuation slashes,
        # which will result in ugly module names, but as they are followed by
        # \n they could be separated as single entries by the following two
        # lines
        lines = config_modules.splitlines()
        coco = ",".join(lines)
        for module in coco.split(','):
            if module.strip() != '\\':
                module_list.append(module.strip())

    return module_list


def get_default_tokens():
    """
    get the list of the linotp default tokens from linotp.lib.tokens

    :return: array of all token module names like
             ["linotp.lib.tokens.smstoken", ..]
    """
    token_modules = []

    import linotp.lib.tokens
    module_loaction = linotp.lib.tokens.__file__
    idx = module_loaction.rfind(os.sep)
    base_dir = module_loaction[:idx]

    for file_name in listdir(base_dir):
        if file_name[-3:] == '.py' and file_name != '__init__.py':
            token_modules.append("linotp.lib.tokens.%s" % file_name[:-3])

    return token_modules

def get_token_module_list():
    '''
    return the list of the available token classes like hmac, spass, totp

    :return: list of token modules
    '''

    # def load_token_modules
    module_list = get_token_list()
    log.debug("[get_token_class_list] using the module list: %s" % module_list)

    modules = []
    for mod_name in module_list:
        if mod_name == '\\' or len(mod_name.strip()) == 0:
            continue

        # load all token modules if not already loaded
        if mod_name not in sys.modules:
            try:
                log.debug("import module: %s" % mod_name)
                __import__(mod_name)
            except TokenTypeNotSupportedError as exx:
                module = None
                log.warning('Token type not supported on this setup: %s', mod_name)
                continue
            except Exception as exx:
                module = None
                log.debug('unable to load token module : %r (%r)'
                          % (mod_name, exx))
                raise Exception('unable to load token module : %r (%r)'
                                % (mod_name, exx))

        module = sys.modules[mod_name]
        if module is not None:
            modules.append(module)
            log.debug('module %s loaded' % (mod_name))
        else:
            log.error('module %s failed to load!' % (mod_name))

    return modules


def get_token_class_list():
    '''
    provide a dict of token types and their classes

    :return: tupple of two dict
             -tokenclass_dict  {token type : token class}
             -tokenprefix_dict {token type : token prefix}
    '''
    modules = get_token_module_list()

    # load_token_classes
    tokenclass_dict = {}
    tokenprefix_dict = {}

    for module in modules:
        log.debug("[get_token_class_list] module: %s" % module)
        for name in dir(module):
            obj = getattr(module, name)
            if inspect.isclass(obj):
                try:
                    # check if this is a TOKEN class
                    if issubclass(obj, linotp.lib.tokenclass.TokenClass):
                        typ = obj.getClassType()
                        class_name = "%s.%s" % (module.__name__, obj.__name__)

                        if typ is not None:
                            tokenclass_dict[typ] = class_name

                            prefix = 'LSUN'
                            if hasattr(obj, 'getClassPrefix'):
                                prefix = obj.getClassPrefix().upper()
                            tokenprefix_dict[typ.lower()] = prefix

                except Exception as e:
                    log.info("[get_token_class_list] error constructing" +
                             " tokenclass_list: %r" % e)

    log.debug("[get_token_class_list] the tokenclass list: %r"
              % tokenclass_dict)

    return (tokenclass_dict, tokenprefix_dict)

###############################################################################


def get_resolver_list():
    '''
    get the list of the resolvers
    :return: list of resolver names from the config file
    '''
    module_list = set()

    module_list.add("useridresolver.PasswdIdResolver")
    module_list.add("useridresolver.LDAPIdResolver")
    module_list.add("useridresolver.SQLIdResolver")

    config_modules = config.get("linotpResolverModules", '')
    log.debug("[get_resolver_module_list] %s " % config_modules)
    if config_modules:
        # in the config *.ini files we have some line continuation slashes,
        # which will result in ugly module names, but as they are followed by
        # \n they could be separated as single entries by the following two
        # lines
        lines = config_modules.splitlines()
        coco = ",".join(lines)
        for module in coco.split(','):
            if module.strip() != '\\':
                module_list.add(module.strip())

    return module_list


def get_resolver_module_list():
    '''
    return the list of the available resolver classes like passw, sql, ldap

    :return: list of resolver modules
    '''

    # def load_resolver_modules
    module_list = get_resolver_list()
    log.debug("using the module list: %s" % module_list)

    modules = []
    for mod_name in module_list:
        if mod_name == '\\' or len(mod_name.strip()) == 0:
            continue

        # load all resolver class implementations, if not already loaded
        if mod_name not in sys.modules:
            try:
                log.debug("import module: %s" % mod_name)
                __import__(mod_name)
            except Exception as exx:
                module = None
                log.warning('unable to load resolver module : %r (%r)'
                            % (mod_name, exx))

        module = sys.modules[mod_name]
        if module is not None:
            modules.append(module)
            log.debug('module %s loaded' % (mod_name))
        else:
            log.error('module %s failed to load!' % (mod_name))

    return modules


def get_resolver_class_list():
    '''
    return the dict of resolver class objects
    '''
    resolverclass_dict = {}
    resolverprefix_dict = {}

    modules = get_resolver_module_list()
    base_class_repr = "useridresolver.UserIdResolver.UserIdResolver"
    for module in modules:
        log.debug("[get_resolver_class_list] module: %s" % module)
        for name in dir(module):
            obj = getattr(module, name)
            if inspect.isclass(obj):
                try:
                    rtyp = repr(obj)
                    # check if this is a resolver class
                    if (issubclass(obj, UserIdResolver) and
                            base_class_repr not in rtyp):
                        # we index the resolver object under:
                        # useridresolver.PasswdIdResolver.IdResolver
                        # in the token.db the resolver refer to:
                        # useridresolver.PasswdIdResolver.IdResolver.myDefRes
                        class_name = "%s.%s" % (module.__name__, obj.__name__)
                        resolverclass_dict[class_name] = obj

                        prefix = class_name.split('.')[1]
                        if hasattr(obj, 'getResolverClassType'):
                            prefix = obj.getResolverClassType()

                        resolverprefix_dict[class_name] = prefix

                except Exception as e:
                    log.info("[get_token_class_list] error constructing" +
                             " resolverclass_list: %r" % e)

    log.debug("[get_resolver_class_list] the resolvernclass list: %r"
              % resolverclass_dict)

    return (resolverclass_dict, resolverprefix_dict)

###eof#########################################################################
