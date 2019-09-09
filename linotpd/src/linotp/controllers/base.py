# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
'''The Controller's Base class '''

from inspect import getargspec
import os
from types import FunctionType
import re

from flask import Blueprint, g as flask_g, Response

from linotp.flap import (
    _ as translate, set_lang, LanguageError,
    tmpl_context as c,
    config, request,
)

from linotp.lib.config import getLinotpConfig
from linotp.lib.context import request_context
from linotp.lib.resolver import initResolvers
from linotp.lib.resolver import setupResolvers
from linotp.lib.resolver import closeResolvers
from linotp.lib.resolver import getResolverList

from linotp.lib.user import getUserFromRequest
from linotp.lib.user import getUserFromParam
from linotp.lib.user import NoResolverFound

from linotp.lib.realm import getDefaultRealm
from linotp.lib.realm import getRealms

from linotp.lib.type_utils import boolean

from linotp.lib.config.db_api import _retrieveAllConfigDB
from linotp.lib.config.global_api import getGlobalObject
from linotp.lib.crypto.utils import init_key_partition


from linotp.model import meta
from linotp.lib.openid import SQLStorage

from linotp.lib.logs import init_logging_config
from linotp.lib.logs import log_request_timedelta

# this is a hack for the static code analyser, which
# would otherwise show session.close() as error
import linotp.model.meta

#
# manual schema migration
# - should become part of schema migration tool like alembic
from linotp.model.migrate import run_data_model_migration

from linotp.lib.config import getLinotpConfig
from linotp.lib.policy.util import parse_policies

from linotp.lib.util import get_client
from uuid import uuid4
from datetime import datetime

import logging
log = logging.getLogger(__name__)

Session = linotp.model.meta.Session


# HTTP-ACCEPT-LANGUAGE strings are in the form of i.e.
# de-DE, de; q=0.7, en; q=0.3
accept_language_regexp = re.compile(r'\s*([^\s;,]+)\s*[;\s*q=[0-9.]*]?\s*,?')


def setup_app(conf, conf_global=None, unitTest=False):
    '''
    setup_app is the hook, which is called, when the application is created

    :param conf: the application configuration

    :return: - nothing -
    '''

    init_logging_config()

    log.info("Successfully set up.")


class ControllerMetaClass(type):
    """This is used to determine the list of methods of a new
    controller that should be made available as API endpoints.
    Basically every method whose name does not start with an
    underscore has a Flask route to it added in the blueprint
    when a controller class is instantiated.
    """

    def __new__(meta, name, bases, dct):
        """When creating the new class, put a list of all its methods
        whose names do not start with `_` into the `_url_methods` class
        attribute. To support inheritance, we also add the content of
        the `_url_methods` attributes of any base classes.

        Note that we don't do this for the `BaseController` class. This
        is (a) because the `BaseController` does not actually contain
        routable API-endpoint methods, and (b) it contains so many
        utility methods that are not API endpoints that it would be
        a hassle to prefix all of their names with `_`.
        """

        cls = super(ControllerMetaClass, meta).__new__(meta, name, bases, dct)

        if name == 'BaseController':
            cls._url_methods = set()
        else:
            cls._url_methods = {
                m for b in bases for m in getattr(b, '_url_methods', [])
            }
            for key, value in dct.items():
                if key[0] != '_' and isinstance(value, FunctionType):
                    cls._url_methods.add(key)
        return cls


class BaseController(Blueprint):
    """
    BaseController class - will be called with every request
    """
    __metaclass__ = ControllerMetaClass

    def __init__(self, name, install_name='', **kwargs):
        super(BaseController, self).__init__(name, __name__, **kwargs)

        # Add routes for all the routeable endpoints in this "controller",
        # as well as base classes.

        for method_name in self._url_methods:
            url = '/' + method_name
            method = getattr(self, method_name)

            # We can't set attributes on instancemethod objects but we
            # can set attributes on the underlying function objects.
            if not hasattr(method.__func__, 'methods'):
                method.__func__.methods = ('GET', 'POST')

            # Add another route if the method has an optional second
            # parameter called `id` (and no parameters after that).
            args, _, _, defaults = getargspec(method)
            if ((len(args) == 2 and args[1] == 'id')
                and (defaults is not None and len(defaults) == 1
                     and defaults[0] is None)):
                self.add_url_rule(url, method_name, view_func=method)
                self.add_url_rule(url + '/<id>', method_name, view_func=method)
            else:
                # Otherwise, add any parameters of the method to the end
                # of the route, in order.
                for arg in args:
                    if arg != 'self':
                        url += '/<' + arg + '>'
                self.add_url_rule(url, method_name, view_func=method)

        # Add pre/post handlers
        self.before_request(self.run_setup)
        self.before_request(self.start_session)
        self.before_request(self.before_handler)
        if hasattr(self, '__after__'):
            self.after_request(self.__after__)
        self.teardown_request(self.finalise_request)

    def run_setup(self):
        """
        Set up the app and database context for a request. Some of this is
        intended to be done only once and could be refactored into a
        before_first_request function
        """

        self.sep = None
        # TODO - language
        #self.set_language(request.headers)

        # make the OpenID SQL Instance globally available
        openid_sql = config.get('openid_sql', None)
        if openid_sql is None:
            try:
                openid_storage = SQLStorage()
                config['openid_sql'] = openid_storage
            except Exception as exx:
                config['openid_sql'] = exx
                log.error("Failed to configure openid_sql: %r" % exx)

        first_run = False
        app_setup_done = config.get('app_setup_done', False)
        if app_setup_done is False:
            try:
                setup_app(config)
                config['app_setup_done'] = True
                first_run = True
            except Exception as exx:
                config['app_setup_done'] = False
                log.error("Failed to serve request: %r" % exx)
                raise exx

        # set the decryption device before loading linotp config,
        # so it contains the decrypted values as well
        glo = getGlobalObject()
        self.sep = glo.security_provider

        try:
            hsm = self.sep.getSecurityModule()
            self.hsm = hsm
            c.hsm = hsm
        except Exception as exx:
            log.exception('failed to assign hsm device: %r' % exx)
            raise exx

        l_config = getLinotpConfig()

        # initialize the elliptic curve secret + public key for the qrtoken
        self.secret_key = l_config.get('SecretKey.Partition.0', False)

        resolver_setup_done = config.get('resolver_setup_done', False)
        if resolver_setup_done is False:
            try:
                cache_dir = config.get("app_conf", {}).get("cache_dir", None)
                setupResolvers(config=l_config, cache_dir=cache_dir)
                config['resolver_setup_done'] = True
            except Exception as exx:
                config['resolver_setup_done'] = False
                log.error("Failed to setup resolver: %r", exx)
                raise exx

        # TODO: verify merge dropped
        # initResolvers()

        # if we are in the setup cycle, we check for the linotpLicenseFile
        if first_run:
            if "linotpLicenseFile" in config and 'license' not in l_config:
                license_str = ''
                filename = config.get("linotpLicenseFile", '')
                try:
                    with open(filename) as f:
                        license_str = f.read()
                except IOError:
                    log.error("could not open licence file: %s", filename)

                if not license_str:
                    log.error("empty license file: %s", filename)
                else:
                    request_context['translate'] = translate

                    import linotp.lib.support
                    res, msg = linotp.lib.support.setSupportLicense(
                        license_str)
                    if res is False:
                        log.error("failed to load license: %s: %s",
                                    license_str, msg)

                    else:
                        log.info("license successfully loaded")
            if 'provider.config_file' in config:
                from linotp.provider import load_provider_ini

                load_provider_ini(config['provider.config_file'])

    def start_session(self):
        self.base_auth_user = ''

        # we add a unique request id to the request enviroment
        # so we can trace individual requests in the logging

        request.environ['REQUEST_ID'] = str(uuid4())
        request.environ['REQUEST_START_TIMESTAMP'] = datetime.now()

        try:
            self._parse_request_params(request)
        except UnicodeDecodeError as exx:
            # we supress Exception here as it will be handled in the
            # controller which will return corresponding response
            log.warning('Failed to access request parameters: %r' % exx)

        self.create_context(request, request.environ)

        try:
            user_desc = getUserFromRequest(request)
            self.base_auth_user = user_desc.get('login', '')
        except UnicodeDecodeError as exx:
            # we supress Exception here as it will be handled in the
            # controller which will return corresponding response
            log.warning('Failed to identify user due to %r' % exx)

    def finalise_request(self, exc):
        meta.Session.remove()
        # free the lock on the scurityPovider if any
        if self.sep:
            self.sep.dropSecurityModule()
        closeResolvers()

        # hint for the garbage collector to make the dishes
        data_objects = ["resolvers_loaded",
                        "resolver_clazzes", "linotpConfig", "audit", "hsm"]
        for data_obj in data_objects:
            if hasattr(c, data_obj):
                data = getattr(c, data_obj)
                del data

        log_request_timedelta(log)

    def _parse_request_params(self, _request):
        """
        Parses the request params from the request objects body / params
        dependent on request content_type.
        """
        if _request.is_json:
            self.request_params = _request.json
        else:
            self.request_params = {}
            for key in _request.values:
                if(key.endswith('[]')):
                    self.request_params[key[:-2]] = _request.values.getall(key)
                else:
                    self.request_params[key] = _request.values.get(key)

    def set_language(self, headers):
        '''Invoke before everything else. And set the translation language'''
        languages = headers.get('Accept-Language', '')

        found_lang = False

        for match in accept_language_regexp.finditer(languages):
            # make sure we have a correct language code format
            language = match.group(1)
            if not language:
                continue
            language = language.replace('_', '-').lower()

            # en is the default language
            if language.split('-')[0] == 'en':
                found_lang = True
                break

            try:
                set_lang(language.split('-')[0])
                found_lang = True
                break
            except LanguageError:
                log.debug("Cannot set requested language: %s. Trying next"
                          " language if available.", language)

        if not found_lang and languages:
            log.warning("Cannot set preferred language: %r", languages)

        return

    def create_context(self, request, environment):
        """
        create the request context for all controllers
        """

        linotp_config = getLinotpConfig()

        # make the request id available in the request context
        request_context['RequestId'] = environment['REQUEST_ID']

        # a request local cache to get the user info from the resolver
        request_context['UserLookup'] = {}

        # a request local cache to get the resolver from user and realm
        request_context['UserRealmLookup'] = {}

        request_context['Config'] = linotp_config
        request_context['Policies'] = parse_policies(linotp_config)
        request_context['translate'] = translate

        # TODO: Port beaker.cache Middleware functionality
        # request_context['CacheManager'] = environment['beaker.cache']
        request_context['CacheManager'] = None

        request_context['Path'] = request.path

        # ------------------------------------------------------------------------

        # setup the knowlege where we are

        request_context['action'] = None
        request_context['controller'] = None

        path = request.path.strip().strip('/').split('/')

        if path[0]:
            request_context['controller'] = path[0]

        if path[1]:
            request_context['action'] = path[1]

        # ------------------------------------------------------------------------

        initResolvers()

        client = None
        try:
            client = get_client(request=request)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['Client'] = client

        Audit = config['audit']
        request_context['Audit'] = Audit
        request_context['audit'] = Audit.initialize(request, client=client)

        authUser = None
        try:
            authUser = getUserFromRequest(request)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['AuthUser'] = authUser
        request_context['UserLookup'] = {}

        # ------------------------------------------------------------------ --
        # get the current resolvers

        resolvers = []
        try:
            resolvers = getResolverList(config=linotp_config)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['Resolvers'] = resolvers

        # ------------------------------------------------------------------ --
        # get the current realms

        realms = {}
        try:
            realms = getRealms()
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['Realms'] = realms

        # ------------------------------------------------------------------ --

        defaultRealm = ""
        try:
            defaultRealm = getDefaultRealm(linotp_config)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['defaultRealm'] = defaultRealm

        # ------------------------------------------------------------------ --
        # load the requesting user

        from linotp.useridresolver.UserIdResolver import (
            ResolverNotAvailable)

        requestUser = None
        try:
            requestUser = getUserFromParam(self.request_params)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r", exx)
        except (ResolverNotAvailable, NoResolverFound) as exx:
            log.error("Failed to connect to server %r", exx)

        request_context['RequestUser'] = requestUser

        # ------------------------------------------------------------------ --
        # load the providers

        from linotp.provider import Provider_types
        from linotp.provider import getProvider

        provider = {}
        for provider_type in Provider_types.keys():
            provider[provider_type] = getProvider(provider_type)

        request_context['Provider'] = provider

        # ------------------------------------------------------------------ --

        # for the setup of encrypted data, we require the hsm is instatiated
        # and available in the request context

        if not self.secret_key:
            init_key_partition(linotp_config, partition=0)

        # ------------------------------------------------------------------ --

        # copy some system entries from pylons
        syskeys = {
            "radius.nas_identifier": "LinOTP",
            "radius.dictfile": "/etc/linotp2/dictionary"
        }

        sysconfig = {}
        for key, default in syskeys.items():
            sysconfig[key] = config.get(key, default)

        request_context['SystemConfig'] = sysconfig

    def before_handler(self):

        params = self.request_params

        if hasattr(self, '__before__'):

            response = self.__before__(**params)

            # in case of exceptions / errors the __before__ handling submits an sendError
            # flask.Response which has the special attribute _exception
            # which is set in the lib/reply.py

            if isinstance(response, Response) and hasattr(response, '_exception'):
                return response

def methods(mm=['GET']):
    """
    Decorator to specify the allowable HTTP methods for a
    controller/blueprint method. It turns out that `Flask.add_url_rule`
    looks at a function object's `methods` property when figuring out
    what HTTP methods should be allowed on a view, so that's where we're
    putting the methods list.
    """

    def inner(func):
        func.methods = mm[:]
        return func
    return inner

# eof ########################################################################

