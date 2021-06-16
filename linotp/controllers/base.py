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
"""The Controller's Base class """

import functools
import logging
import secrets
from inspect import getfullargspec
from types import FunctionType
from warnings import warn

from flask import Blueprint, after_this_request, current_app

from linotp.flap import request
from linotp.lib.context import request_context
from linotp.lib.reply import sendError, sendResult
from linotp.lib.user import NoResolverFound, getUserFromParam
from linotp.lib.util import SESSION_KEY_LENGTH
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

    The URL at which this controller will be available depends on a number of factors. These are, in
    order of priority:
    1. Any explicit path in the settings CONTROLLERS=ControllerName:PATH
    2. The controller's `base_url_prefix` setting
    3. The name of the controller"""

    def __init__(self, name, install_name="", **kwargs):
        super(BaseController, self).__init__(name, __name__, **kwargs)

        # These methods will be called before each request
        self.before_request(self._parse_request_params)
        self.before_request(self.parse_requesting_user)
        self.before_request(self.before_handler)

        if hasattr(self, "__after__"):
            self.after_request(
                self.__after__
            )  # noqa pylint: disable=no-member

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

    def _parse_request_params(self):
        """
        Parses the request params from the request objects body / params
        dependent on request content_type.

        The resulting request parameters from the client are saved in
        the class instance variable `request_params`

        This method is called before each request is processed.
        """
        self.request_params = current_app.getRequestParams()

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

    def inner(func):
        func.methods = mm[:]
        return func

    return inner


class SessionCookieMixin(object):
    """
    Enables a controller to set and destroy session cookies. This is a
    mixin class because the functionality used to be implemented
    separately in several controllers, which violates the DRY principle.
    """

    session_cookie_name = "session"

    def getsession(self):
        """
        Generates a session key and sets it as a cookie. Should really
        be using Flask machinery.
        """

        @after_this_request
        def set_session_cookie(response):
            try:
                random_key = secrets.token_hex(SESSION_KEY_LENGTH)
                log.debug(
                    f"[getsession] adding session cookie {random_key} "
                    "to response."
                )

                params = {}
                if current_app.config["SESSION_COOKIE_SECURE"]:
                    params["secure"] = True

                response.set_cookie(
                    self.session_cookie_name, value=random_key, **params
                )
                return response
            except Exception as ex:
                log.error("[getsession] unable to create a session cookie")
                db.session.rollback()
                return sendError(response, ex)

        return sendResult(None, True)

    def dropsession(self):
        @after_this_request
        def drop_session_cookie(response):
            response.delete_cookie(self.session_cookie_name)
            return response

        return sendResult(None, True)

    # We have to make our own `_url_methods` dictionary; it will not
    # be created automatically by the `ControllerMetaClass` because
    # `SessionCookieMixin` is not a subclass of `BaseController`.
    # Without it, the `BaseController` will not be able to dispatch to
    # our methods.

    _url_methods = {
        "getsession": getsession,
        "dropsession": dropsession,
    }


# eof ########################################################################
