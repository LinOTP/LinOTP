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

'''
This is the controller module. The controllers provide the Web API to
communicate with LinOTP. You can use the following controllers:

account		- used for loggin in to the selfservice
admin		- API to manage the tokens
audit		- to search the audit trail
auth		- to do authentication tests
error		- to display errors
gettoken	- to retrieve OTP values
manage		- the Web UI
openid		- the openid interface
selfservice	- the selfservice UI
system		- to configure the system
testing		- for testing purposes
validate	- for authenticating/ OTP checking
maintenance     - for internal maintenance purposes

'''

from inspect import getargspec
from types import FunctionType

from flask import Blueprint

from linotp.controllers.base import BaseController as bc

class ControllerMetaClass(type):

    def __new__(meta, name, bases, dct):
        cls = super(ControllerMetaClass, meta).__new__(meta, name, bases, dct)
        cls._url_methods = {
            m for b in bases for m in getattr(b, '_url_methods', [])
        }
        for key, value in dct.items():
            if key[0] != '_' and isinstance(value, FunctionType):
                cls._url_methods.add(key)
        return cls


class BaseController(bc):
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
                method.__func__.methods = ['GET', 'POST']
            for arg in getargspec(method)[0]:
                if arg != 'self':
                    url += '/<' + arg + '>'
            self.add_url_rule(
                url, method_name, view_func=method, methods=['GET', 'POST'])


        # Add pre/post handlers
        self.before_request(self.first_run_setup)
        self.before_request(self.start_session)
        self.before_request(self.before_handler)
        if hasattr(self, '__after__'):
            self.after_request(self.__after__)
        self.teardown_request(self.finalise_request)

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
