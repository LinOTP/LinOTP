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
"""The Controller's Base class """

import functools
import logging
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from inspect import getfullargspec
from types import FunctionType
from warnings import warn

from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies,
)
from flask_jwt_extended.exceptions import CSRFError, NoAuthorizationError
from jwt import ExpiredSignatureError, InvalidSignatureError

from flask import Blueprint, after_this_request, current_app, g, jsonify

from linotp.flap import request
from linotp.lib import deprecated_methods, render_calling_path
from linotp.lib.context import request_context
from linotp.lib.realm import getRealms
from linotp.lib.reply import sendError, sendResult
from linotp.lib.resolver import getResolverObject
from linotp.lib.tools.flask_jwt_extended_migration import (
    get_jwt,
    verify_jwt_in_request,
)
from linotp.lib.user import (
    NoResolverFound,
    User,
    getUserFromParam,
    getUserFromRequest,
    getUserId,
)
from linotp.model import db

log = logging.getLogger(__name__)


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

        if name == "BaseController":
            cls._url_methods = set()
        else:
            cls._url_methods = {
                m for b in bases for m in getattr(b, "_url_methods", [])
            }
            for key, value in list(dct.items()):
                if key[0] != "_" and isinstance(value, FunctionType):
                    cls._url_methods.add(key)
        return cls


def add_hyphenated_url(f):
    """Decorator that sets the `hyphenated_url` attribute on a
    function. We could set the attribute directly after the function
    definition but this way it looks nicer, and the code in the other
    file doesn't need to know about the attribute.
    """

    f.hyphenated_url = True
    return f


class BaseController(Blueprint, metaclass=ControllerMetaClass):
    """
    BaseController class - will be called with every request
    """

    default_url_prefix = ""
    """Suggested URL to access this controller.

    The URL at which this controller will be available depends on a number of
    factors. These are, in order of priority:
    1. Any explicit path in the
        settings ENABLE_CONTROLLER or DISABLE_CONTROLLER = ControllerName:PATH
    2. The controller's `base_url_prefix` setting
    3. The name of the controller"""

    # Whether all methods in this controller should be JWT-exempt
    jwt_exempt = False

    def __init__(self, name, install_name="", **kwargs):
        super(BaseController, self).__init__(name, __name__, **kwargs)

        self.jwt_exempt_methods = set()

        # These methods will be called before each request
        self.before_request(self.jwt_check)
        self.before_request(self.parse_requesting_user)
        self.before_request(self.before_handler)

        if hasattr(self, "__after__"):
            self.after_request(
                self.__after__
            )  # noqa pylint: disable=no-member

        self.after_request(jwt_refresh)

        # Add routes for all the routeable endpoints in this "controller",
        # as well as base classes.

        for method_name in self._url_methods:
            # Route the method to a URL of the same name,
            # except for index, which is routed to
            # /<controller-name>/
            if method_name == "index":
                url = "/"
            else:
                url = "/" + method_name

            method = getattr(self, method_name)

            # We can't set attributes on instancemethod objects but we
            # can set attributes on the underlying function objects.
            if not hasattr(method.__func__, "methods"):
                method.__func__.methods = ("GET", "POST")

            if self.jwt_exempt or getattr(
                method.__func__, "jwt_exempt", False
            ):
                log.debug(f"JWT exempt: {method}")
                self.jwt_exempt_methods.add(method_name)

            # Add another route if the method has an optional second
            # parameter called `id` (and no parameters after that).
            args, _, _, defaults, _, _, _ = getfullargspec(method)
            if (len(args) == 2 and args[1] == "id") and (
                defaults is not None
                and len(defaults) == 1
                and defaults[0] is None
            ):
                self.add_url_rule(url, method_name, view_func=method)
                self.add_url_rule(url + "/<id>", method_name, view_func=method)
            else:
                # Otherwise, add any parameters of the method to the end
                # of the route, in order.
                for arg in args:
                    if arg != "self":
                        url += "/<" + arg + ">"
                self.add_url_rule(url, method_name, view_func=method)

                # Some URLs have historically been documented as
                # `foo-bar` rather than `foo_bar`. It would be easy to
                # enable this here for all methods by introducing
                # alternative routes, but in order to avoid possible
                # future maintenance issues we allow this on a
                # per-instance basis only, in order to stay
                # backwards-compatible. Since hard-coding the URLs in
                # question here would be icky, we introduce a
                # decorator so the methods in question can be defined
                # where they appear, like
                #
                #     @add_hyphenated_url
                #     def foo_bar(…)      # will also appear as `foo-bar`
                #         …
                #
                # (Just to be safe, we avoid introducing extra URL
                # routes if the URL in question doesn't contain an
                # underscore to begin with.)

                if "_" in url and getattr(
                    method.__func__, "hyphenated_url", False
                ):
                    self.add_url_rule(
                        url.replace("_", "-"), method_name, view_func=method
                    )

    def jwt_check(self):
        """Check whether the current request needs to be authenticated using
        JWT, and if so, whether it contains a valid JWT access token.
        The login name from the access token is stored in the
        g.authUser via quering the jwt identity with
        get_jwt_identiy for the benefit of `lib.user.getUserFromRequest()`.
        """

        method = request.url_rule.endpoint[
            request.url_rule.endpoint.rfind(".") + 1 :
        ]
        if method in self.jwt_exempt_methods:
            log.debug("jwt_check: operation is exempt from JWT check")
            return None

        try:
            verify_jwt_in_request()
        except (
            NoAuthorizationError,
            ExpiredSignatureError,
            InvalidSignatureError,
            CSRFError,
        ):
            log.error("jwt_check: Failed JWT authentication")
            response = sendError(None, "Not authenticated")
            response.status_code = 401
            return response

    def parse_requesting_user(self):
        """
        load the requesting user

        The result is placed into request_context['RequestUser']
        """
        from linotp.useridresolver.UserIdResolver import ResolverNotAvailable

        requestUser = None
        try:
            requestUser = getUserFromParam(self.request_params)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r", exx)
        except (ResolverNotAvailable, NoResolverFound) as exx:
            log.error("Failed to connect to server %r", exx)

        request_context["RequestUser"] = requestUser

    @property
    def request_params(self):
        return current_app.getRequestParams()

    def before_handler(self):
        """
        Call derived controller's legacy __before__ method if it exists

        This method is called before each request is processed.
        """
        params = self.request_params

        if hasattr(self, "__before__"):
            response = self.__before__(**params)  # pylint: disable=no-member
            if response == request:
                # Pylons style before handler
                warn(
                    "Returning Request is no longer necessary",
                    DeprecationWarning,
                )
                return None
            return response


def methods(mm=["GET"]):
    """
    Decorator to specify the allowable HTTP methods for a
    controller/blueprint method. It turns out that `Flask.add_url_rule`
    looks at a function object's `methods` property when figuring out
    what HTTP methods should be allowed on a view, so that's where we're
    putting the methods list.
    """

    def inner_func(func):
        func.methods = mm[:]

        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        # update the calling  docstring of the function
        wrapper.__doc__ = render_calling_path(func) + wrapper.__doc__

        return wrapper

    return inner_func


def jwt_exempt(f):
    """Decorator for methods that should be exempt from JWT validation."""

    f.jwt_exempt = True
    return f


def jwt_refresh(response):
    """
    Transparently refresh a JWT access token that is close to expiry.
    This is pretty much straight from the Flask-JWT-Extended docs,
    except we're making the refresh period configurable.
    """
    delta = current_app.config["JWT_ACCESS_TOKEN_REFRESH"]
    if delta == 0:
        return response
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(seconds=delta))
        if target_timestamp > exp_timestamp:
            log.debug("jwt_refresh: refreshing access token")
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Return original response if there is no JWT
        return response


class JWTMixin(object):
    """
    Provides `login` and `logout` methods that generate or dispose of
    JWT access tokens (and double-submit tokens for CSRF protection).

    This is a mixin class so we can keep all the JWT stuff closely
    together instead of spreading it out across various controllers.

    """

    @jwt_exempt
    @methods(["POST"])
    def login(self):
        """
        manage authentication

        Checks a user's credentials and issues them a JWT access
        token if their credentials are valid. We're using cookies to
        store the access token plus a double-submit token for CSRF
        protection, which makes it easy to refresh access tokens
        transparently if they are nearing expiry.

        :param username: the name of the user
        :param password: the password of the user

        :return:
            a json document and the jwt cookies are replied

        """

        username = self.request_params.get("username")
        password = self.request_params.get("password")

        # Search for the user in the admin realm and check the
        # given password.

        admin_realm_name = current_app.config["ADMIN_REALM_NAME"]
        admin_realm = getRealms(admin_realm_name)
        admin_resolvers = admin_realm[admin_realm_name]["useridresolver"]

        for resolver_specification in admin_resolvers:
            resolver = getResolverObject(resolver_specification)

            uid = resolver.getUserId(username)
            if not uid:
                continue

            if not resolver.checkPass(uid, password):
                continue

            response = sendResult(
                None,
                True,
                opt={"message": f"Login successful for {username}"},
            )

            access_token = create_access_token(
                identity={
                    "username": username,
                    "realm": current_app.config["ADMIN_REALM_NAME"],
                    "resolver": resolver_specification,
                },
            )

            set_access_cookies(response, access_token)

            return response

        response = sendResult(
            None,
            False,
            opt={"message": "Bad username or password"},
        )
        response.status_code = 401
        return response

    def logout(self):
        """Logs a user out by obliterating their JWT access token
        cookies.
        NOTE: We may wish to block further use of the access token
        in question in case the user has saved a copy somewhere.
        See the Flask-JWT-Extended docs for ideas about how to do this.
        """
        auth_user = getUserFromRequest()
        response = sendResult(
            None, True, opt={"message": f"Logout successful for {auth_user}"}
        )

        unset_jwt_cookies(response)

        # jti: jwt unique identifier
        raw_jwt = get_jwt()
        jti = raw_jwt["jti"]
        expires_at = get_jwt()["exp"]
        expires_in = int(expires_at - datetime.now().timestamp())

        current_app.jwt_blocklist.add_item(jti, expiry=expires_in)
        return response

    # We have to make our own `_url_methods` dictionary; it will not
    # be created automatically by the `ControllerMetaClass` because
    # `JWTMixin` is not a subclass of `BaseController`.
    # Without it, the `BaseController` will not be able to dispatch to
    # our methods.

    _url_methods = {
        "login": login,
        "logout": logout,
    }
