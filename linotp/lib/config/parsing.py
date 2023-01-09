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
    This module provides an interface to parse linotp config
    key-value pairs into a structured ConfigTree
"""

import json
from collections import defaultdict

# -------------------------------------------------------------------------- --


class ConfigNotRecognized(Exception):

    """
    This exception should be raised by config parser functions, when the
    parser isn't responsible for the supplied type of config entry.

    :param key: The config key that was supplied to the parser
    :param message: Custom message (optional, generic message on default)
    """

    def __init__(self, key, message=None):

        if message is None:
            message = "Unrecognized config key: %s" % key
        Exception.__init__(self, message)
        self.key = key


# -------------------------------------------------------------------------- --


def parse_system_config(composite_key, value):
    """
    Parses system config entries

    ::warning: does a very generic match. should be added last to the
        internal config tree parser list
    """

    if not composite_key.startswith("linotp."):
        raise ConfigNotRecognized(composite_key)

    return "system_config", {composite_key: value}


# -------------------------------------------------------------------------- --


def parse_deprecated_enc(composite_key, value):
    """
    Parses soon to be deprecated 'enclinotp' config entries

    ::warning: does a very generic match. should be added last to the
        internal config tree parser list
    """

    # XXX LEGACY DEPRECATED

    if not composite_key.startswith("enclinotp."):
        raise ConfigNotRecognized(composite_key)

    return "deprecated_enc", {composite_key: value}


# -------------------------------------------------------------------------- --


class ConfigTree(dict):

    """
    A dictionary-like object, that processes config key-value pairs with
    a series of parsers.

    Usage:

    >>> tree = ConfigTree
    >>> tree.add_parser('resolvers', parse_resolver)
    >>> for key, value in config_dict.items():
    >>>     tree.consume_entry(key, value)
    """

    # the list of parsers get initialized on startup
    # by the add_parser method.

    _parsers = [
        ("globals", parse_system_config),
        ("deprecated", parse_deprecated_enc),
    ]

    def __init__(self):

        # initialize config tree subspaces according to
        # parser definitions

        for target, __ in self._parsers:
            self[target] = defaultdict(dict)

    @classmethod
    def add_parser(cls, target, func):
        """
        Adds a parser function for the config tree.

        :param target: A string identifier for the first set of child
            nodes of this tree (e.g. 'resolvers', 'realms', etc)
            Multiple parsers for the same string identifier can
            exist.

        :param func: A parser function that asks for the composite
            key of the config entry and the value and returns a
            tuple (object_id, attr_updates) where object_id is a
            unique identifier inside the target scope (such as a
            resolver name) and attr_updates is a dictionary
            consisting of key-value-pairs where each keys is
            an attribute name and each value its value.

        .. warning:: The order in which the parsers are added
            is relevant. Later parsers have a higher priority
        """

        # the following is a hack.

        # we are facing the problem, that we need information
        # from different modules (such as the list of available
        # resolver types) in order to define the parsing function
        # for the module. we can't simply import this data in here
        # because it produces circular dependencies (most of the
        # modules use functions from the config module).

        # because of this, with this commit, we change this method
        # into a class method and delegate the calls to add_parser
        # to the different modules. add_parser will now be called
        # in the respective modules with the parser function defined
        # there as well.

        # however, we have 2 basic config types ('globals' and 'deprecated'),
        # that have no distinction criteria to the other config entries and
        # rely on the other parsers being processed first

        # because we cannot possibly control import order (at least not
        # at our current stage of insanity) we need to make sure that
        # the parsers for 'globals' and 'deprecated' always come last.

        # this problem is 'solved' by adding both 'globals' and
        # 'deprecated' parsers at the class level (see above) and
        # by PREPENDING every other parser that gets added from
        # outside, effectively reversing the order of priority.
        # (from later ^= lower_prio to later ^= higher prio)

        cls._parsers.insert(0, (target, func))

    def consume_entry(self, composite_key, value):
        """
        Integrates a config pair of a composite key and value
        into the tree.

        :param composite_key: A composite key from the config
            (such as 'linotp.Policy.mypolicy.scope')

        :param value: The associated value

        :raises ConfigNotRecognized: If none of the defined
            parsers recognized the config pair
        """

        for target, parser_func in self._parsers:

            try:

                object_id, attr_updates = parser_func(composite_key, value)
                self[target][object_id].update(attr_updates)
                break

            except ConfigNotRecognized:
                continue

        else:

            raise ConfigNotRecognized(composite_key)

    def pretty(self):
        """Returns a pretty print of the tree"""

        return json.dumps(self, indent=4)


# -------------------------------------------------------------------------- --


def parse_config(config_dict):
    """
    Translates a flat config_dict into a hierarchical ConfigTree

    :param config_dict: The config dictionary retrieved from
        the low-level typing API

    :return: ConfigTree object
    """

    tree = ConfigTree()

    # ---------------------------------------------------------------------- --

    for composite_key, value in list(config_dict.items()):
        tree.consume_entry(composite_key, value)

    return tree
