# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
"""
 user entry comparison processing
"""

import re
import logging
log = logging.getLogger(__name__)


class UserDomainCompare(object):

    def __init__(self):
        self._compare = None

    def exists(self, userObj, user_def):
        """
        existance test is the same as the attribute search for userid
        """
        attr_comp = AttributeCompare()
        exists = attr_comp.compare(userObj, user_def + "#userid")
        return exists

    def compare(self, userObj, user_def):
        """
        comparison method - the single entry of this class

        :param userObj: the user Class object
        :param user_def: user definition from the policy entry 'user'

        :return: bool
        """
        self._parse(user_def)
        return self._compare(userObj, user_def)

    def _parse(self, user_def):
        '''
        parse the domain user string and distinguis if there
        is a user + domain or a sinple user only comparison required
        accordin to this the comparison method is adjusted

        :param user_def: user definition from the policy entry 'user'
        '''

        if '@' in user_def:
            self._compare = self._compareDomain
        elif ':' in user_def.strip()[-1]:
            self._compare = self._compareResolver
        else:
            self._compare = self._compareUser
        return

    def _compareDomain(self, userObj, user_def):
        """
        do the user name and domain comparison

        :params userObj: the comparison user class object
        :param user_def: the user pattern to compare against

        :return: bool

        """
        # first compare the domain case insensitiv
        def_domain = user_def.split('@')[-1]
        domain_pattern = re.compile(def_domain + '$', re.IGNORECASE)
        compare_result = re.match(domain_pattern, userObj.realm)
        if not compare_result:
            return False

        # remove the domain from the user and compare
        simple_user_def, _sep, _dom = user_def.rpartition('@')
        return self._compareUser(userObj, simple_user_def)

    def _compareUser(self, userObj, user_def):
        """
        do the user name only comparison

        :params userObj: the comparison user class object
        :param user_def: the user pattern to compare against

        :return: bool

        """
        # for wildcard, we can return immediatly
        if user_def == '*':
            return True

        # otherwise compare the username
        user_pattern = re.compile(user_def + '$')
        compare_result = re.match(user_pattern, userObj.login)
        return compare_result is not None

    def _compareResolver(self, userObj, user_def):
        """
        do the user name and resolver comparison -
            the user is separated by a '.' from the resolver

        Remark: the user must not be defined by the target resolver,
                its the ability to lookup in a different resolver for
                the user login

        :params userObj: the comparison user class object
        :param user_def: the user pattern to compare against

        :return: bool
        """

        def_resolver = user_def[:-1]

        # if there is a prefixed user, split it from
        if '.' in def_resolver:
            def_resolver = def_resolver.split('.')[-1]

        # check if the resolver is defined at all
        from linotp.lib.resolver import getResolverList
        resolvers = getResolverList()
        if def_resolver not in resolvers:
            return False

        # if we have no user part and came that far, we are done
        if def_resolver == user_def[:-1]:
            return True

        user_resolver = user_def[:-1]
        # remove the resolver from the user and compare
        simple_user_def, _sep, _res = user_resolver.rpartition(".")
        return self._compareUser(userObj, simple_user_def)


class AttributeCompare(object):
    """
    Policy Attribute Comparison to support user filter like

        pas.*@myDefReal#mobil ~= 1234

    support for comparrison operation like
    * exist:     has this attribute
    * equal:     user attribute is same as in policy defintion
    * not equal: negative of equal
    * is_in:     regex search of defintion in user attribute

    support for user format like
    * user@domain       user at domain
    * user.resolver:    user in resolver
    * user              simple username

    support for regex match in username

    """

    def __init__(self):
        self.userObj = None

    def _parse(self, user_def):
        """
        parse - analyse the left part of the attribute defintion
                establishes the function overloading

        :param user_def: the specification from the policy
        """
        # analyse the key + value comparison
        udef, key_val = user_def.split('#', 1)
        if '==' in key_val:
            key, val = key_val.split('==')
            op = 'equal'
            self.set_key_val_compare(key.strip(), val.strip(), op)
        elif '!=' in key_val:
            key, val = key_val.split('!=')
            op = 'not equal'
            self.set_key_val_compare(key.strip(), val.strip(), op)
        elif '~=' in key_val:
            key, val = key_val.split('~=')
            op = 'is in'
            self.set_key_val_compare(key.strip(), val.strip(), op)

        else:
            key = key_val.strip()
            val = None
            op = 'exist'
            self.set_key_val_compare(key, val, op)

        # analysed the user definition
        if not udef:
            # only attribute compare
            self.set_user_access(udef, 'attribute_only')
        else:
            if '@' in udef:
                self.set_user_access(udef, 'domain_compare')
            elif ':' == udef[-1]:
            # resolver match
                self.set_user_access(udef, 'get_resolver')
            elif len(udef) > 0:
            # simple username compare
                self.set_user_access(udef, 'simple_name')

    def _attr_equal(self, user_info):
        """
        compare the value of the user_info with the policy definition of key

        :param user_info: the user_info dictionary
        :return: boolean
        """
        if self.key not in user_info:
            return False
        uval = user_info.get(self.key, None)
        return uval.strip() == self.val.strip()

    def _attr_is_in(self, user_info):
        """
        regex compare for attribute values

        :param user_info: the user info dictionary
        """
        if self.key not in user_info:
            return False

        uval = user_info.get(self.key, None) or None
        if not uval:
            return False

        val_expression = re.compile(self.val.strip())
        exists = re.search(val_expression, uval)

        return exists is not None

    def _attr_not_equal(self, user_info):
        """
        compare on unequal of the value of the user_info with the
        user definition of key

        :param user_info: the user_info dictionary
        :return: boolean
        """

        return not(self._attr_equal(user_info))

    def _attr_exist(self, user_info):
        """
        check for the existance of an user definition of key

        :param user_info: the user_info dictionary
        :return: boolean
        """
        return self.key in user_info

    def set_key_val_compare(self, key, val, operator):
        """
        internal method to establish the function overloading for the
        comparison of key and value

        :param key: the, to be searched key
        :param val: the to be compared value definition
        :param operator: literal, which defines what comparison function
                         to be used
        :return: - nothing -
        """
        self.key = key
        self.val = val
        if operator == 'exist':
            self.operator = self._attr_exist
        elif operator == 'equal':
            self.operator = self._attr_equal
        elif operator == 'not equal':
            self.operator = self._attr_not_equal
        elif operator == 'is in':
            self.operator = self._attr_is_in

    def _userinfo_direct(self):
        """
        define the user lookup, which is here none

        :return: the user info as dict
        """

        user_info = self.userObj.getUserInfo()
        return user_info

    def _user_domain_compare(self):
        """
        define the user lookup, which is here user or use@domain

        :return: the user info as dict
        """

        udc = UserDomainCompare()
        compare_result = udc.compare(self.userObj, self.user_spec)
        if not compare_result:
            return False

        return self._userinfo_direct()

    def _resolver_compare(self):
        """
        define the user lookup, which is here use.resolver:

        Remark:
            resolver only like  resolver: is handled in the legacy method,
            while this might be supported here as well

        :return: the user info as dict
        """

        # lookup user.login in target resolver
        udc = UserDomainCompare()
        compare_result = udc.compare(self.userObj, self.user_spec)
        if not compare_result:
            return False

        # get the userspec resolver from the user_spec
        def_resolver = self.user_spec[:-1]
        if '.' in def_resolver:
            def_resolver = def_resolver.split('.')[-1]
        # get the user_info from the target resolver
        return self.userObj.getUserInfo(def_resolver)

    def set_user_access(self, user_spec, typ='attribute_only'):
        """
        setup, which user lookup should be made by function overloading

        called from the parser

        :param user_spec: the user secification from the policy
        :param typ: parameter from the parser to control, which function to use
        """

        self.user_spec = user_spec
        if typ == 'attribute_only':
            self.access_user = self._userinfo_direct
        elif typ == 'simple_name':
            self.access_user = self._user_domain_compare
        elif typ == 'domain_compare':
            self.access_user = self._user_domain_compare
        elif typ == 'get_resolver':
            self.access_user = self._resolver_compare

    def compare(self, userObj, user_def):
        """
        comparison method - the single entry of this class

        :param userObj: the user Class object
        :param user_def: user definition from the policy entry 'user'

        :return: bool
        """

        self.userObj = userObj
        self._parse(user_def)
        user_info = self.access_user()
        if not user_info:
            return False
        return self.operator(user_info)

# eof #########################################################################

