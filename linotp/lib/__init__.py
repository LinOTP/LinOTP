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
 This model contains the linotp processing logic
"""

import warnings
from functools import wraps


def render_calling_path(func):
    """
    return the api path inc HTTP methods

    - utility for sphimx rendering of api docs:
    """

    module = func.__module__
    module_name = module.rpartition(".")[-1]
    func_name = func.__name__

    try:
        methods = ", ".join(func.methods)
    except:
        methods = "GET, POST"
    return f"**{methods}** */{module_name}/{func_name}*\n "


def deprecated(func):
    """This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emmitted
    when the function is used."""

    def newFunc(*args, **kwargs):
        warnings.warn(
            "Call to deprecated function %s." % func.__name__,
            category=DeprecationWarning,
        )
        return func(*args, **kwargs)

    newFunc.__name__ = func.__name__
    newFunc.__doc__ = func.__doc__
    newFunc.__dict__.update(func.__dict__)
    return newFunc


def deprecated_methods(deprecated_methods_list):
    """
    deprecated_methods - decorator function

    mark linotp endpoints as deprecated when accessed with a http method
    in the provided list, eg.

    @deprecated_methods(['GET'])
    def check()

    1- A warning for the deprecation will be added to the docstring
    2- A warning should be written in case that the 'check' endpoint is
    accessed using a Http GET request. The warning log itself should be
    implemented in the controllers before calling the method(in progress TODO)

    Developer Note: the implementation is not completed: major shortcoming is that its
            not possible to access the request method the function is called
            with.

    :param deprecated_methods_list: a list of methods that are deprecated for the
    end point. E.g. ["GET"] or ["POST"] or ["GET", "POST"]

    """

    def is_get_deprecated():
        return "GET" in deprecated_methods_list

    def is_post_deprecated():
        return "POST" in deprecated_methods_list

    def doc_pretext():
        """Helper function
        This is the text that is gonna be prepended to the top of the docstring
        """

        if is_get_deprecated():
            doc_pretext = """
        .. deprecated:: 3.2
            Requests using HTTP **GET** method (because it is modifying data).
            This endpoint will only be available via HTTP **POST** method in
            the future.
            """

        if is_post_deprecated():
            doc_pretext = """
        .. deprecated:: 3.2
            Requests using HTTP **POST** method (because it is only reading data).
            This endpoint will only be available via HTTP **GET** method in
            the future.
            """

        return doc_pretext

    def doc_posttext():
        """Helper function: This is the text that is gonna be appended to the end of the docstring"""
        if is_get_deprecated():
            doc_posttext = """ """
        if is_post_deprecated():
            doc_posttext = doc_posttext = """ """

        return doc_posttext

    def get_conditional_deprecation_warnings(func_name):
        """Helper function: This is the message which is gonna be printed if the function is called
        with the wrong call method. e.g. a POST method(deprecated GET) being called
        by Get"""

        conditional_deprecation_warnings = []

        if is_get_deprecated():
            warning_message = (
                f"method: [{func_name}] should be called only by POST method"
            )
            conditional_deprecation_warnings.append(
                {"condition_method": "GET", "warning_message": warning_message}
            )
        if is_post_deprecated():
            warning_message = (
                f"method: [{func_name}] should be called only by GET method"
            )
            conditional_deprecation_warnings.append(
                {
                    "condition_method": "POST",
                    "warning_message": warning_message,
                }
            )

        return conditional_deprecation_warnings

    # the actuall decorator is here
    def inner_func(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        # update the docstring of the function
        wrapper.__doc__ = (
            render_calling_path(func)
            + doc_pretext()
            + wrapper.__doc__
            + doc_posttext()
        )
        # Further implementation: set a flag to log a warning in case of being called by the wrong method
        # wrapper.conditional_deprecation_warnings = (
        #     get_conditional_deprecation_warnings(func_name=wrapper.__name__)
        # )

        return wrapper

    return inner_func
