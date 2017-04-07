"""
This module provides an interface to parse linotp config key-value pairs into
a structured ConfigTree
"""

import json

from collections import defaultdict
from functools import partial
from linotp.lib.resolver import get_resolver_types
from linotp.provider import Provider_types
from linotp.provider import Legacy_Provider
from linotp.provider import Default_Provider_Key


# ------------------------------------------------------------------------------


class ConfigNotRecognized(Exception):

    """
    This exception should be raised by config parser functions, when the
    parser isn't responsible for the supplied type of config entry.

    :param key: The config key that was supplied to the parser
    :param message: Custom message (optional, generic message on default)
    """

    def __init__(self, key, message=None):

        if message is None:
            message = 'Unrecognized config key: %s' % key
        Exception.__init__(self, message)
        self.key = key


# ------------------------------------------------------------------------------


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

    def __init__(self):
        self.parsers = []

    def add_parser(self, target, func):

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
            is relevant. Earlier parsers have a higher priority
        """

        self[target] = defaultdict(dict)
        self.parsers.append((target, func))

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

        for target, parser_func in self.parsers:

            try:

                object_id, attr_updates = parser_func(composite_key, value)
                self[target][object_id].update(attr_updates)
                break

            except ConfigNotRecognized:
                continue

        else:

            raise ConfigNotRecognized(composite_key)

    def pretty(self):

        """ Returns a pretty print of the tree """

        return json.dumps(self, indent=4)


# ------------------------------------------------------------------------------


def parse_policy(composite_key, value):

    """ Parses policy data from a config entry """

    if not composite_key.startswith('linotp.Policy'):
        raise ConfigNotRecognized(composite_key)

    parts = composite_key.split('.')

    if len(parts) != 4:
        raise ConfigNotRecognized(composite_key)

    object_id = parts[2]
    attr_name = parts[3]

    return object_id, {attr_name: value}

# ------------------------------------------------------------------------------


def parse_resolver(composite_key, value):

    """ Parses resolver data from a config entry """

    attr_updates = {}

    # ------------------------------------------------------------------------ -

    # due to ambiguity of the second part in the config dot notation
    # we must check if the second part is a primary class identifier
    # of a resolver.

    cls_identifiers = get_resolver_types()  # ldapresolver, passwdresolver, etc

    for cls_identifier in cls_identifiers:
        if composite_key.startswith('linotp.%s.' % cls_identifier):
            break
    else:
        raise ConfigNotRecognized(composite_key)

    attr_updates['cls_identifier'] = cls_identifier

    # ------------------------------------------------------------------------ -

    parts = composite_key.split('.', 3)

    if len(parts) < 3:
        raise ConfigNotRecognized(composite_key, 'This legacy resolver '
                                  'description is not supported anymore.')
    # ------------------------------------------------------------------------ -

    attr_name = parts[2]
    attr_updates[attr_name] = value

    object_id = parts[3]  # the resolver name

    # ------------------------------------------------------------------------ -

    return object_id, attr_updates


# ------------------------------------------------------------------------------


def parse_realm(composite_key, value):

    """ Parses realm data from a config entry """

    if not composite_key.startswith('linotp.useridresolver.group.'):
        raise ConfigNotRecognized(composite_key)

    object_id = composite_key[len('linotp.useridresolver.group.'):]

    return object_id, {'resolvers': value}

# ------------------------------------------------------------------------------


def parse_default_realm(composite_key, value):

    """
    Sets the attribute pair {default: True} to the default realm
    in the tree.
    """

    if composite_key != 'linotp.DefaultRealm':
        raise ConfigNotRecognized(composite_key)

    # ------------------------------------------------------------------------ -

    return value, {'default': True}


# ------------------------------------------------------------------------------


def parse_provider(provider_type, composite_key, value):

    """
    Parses provider data from a config entry

    :param provider_prefix: A short provider prefix (such as 'SMSProvider',
        'PushProvider' - all without the leading 'linotp.')
    """

    attr_updates = {}

    # ------------------------------------------------------------------------ -

    long_prefix = Provider_types[provider_type]['prefix']
    provider_prefix = long_prefix[len('linotp.'):-1]

    # ------------------------------------------------------------------------ -

    # due to ambiguity of the second part in the config dot notation
    # we must check if the second part is the provider type

    if not composite_key.startswith('linotp.%s.' % provider_prefix):
        raise ConfigNotRecognized(composite_key)

    # ------------------------------------------------------------------------ -

    parts = composite_key.split('.')

    if len(parts) == 3:

        object_id = parts[2]
        attr_updates['class'] = value

    elif len(parts) == 4:

        object_id = parts[2]
        attr_name = parts[3]
        attr_updates[attr_name] = value

    else:

        raise ConfigNotRecognized(composite_key)

    # ------------------------------------------------------------------------ -

    return object_id, attr_updates


# ------------------------------------------------------------------------------

def parse_legacy_provider(provider_type, composite_key, value):

    """
    Parses legacy provider data from a config entry

    :param provider_prefix: A short provider prefix (such as 'SMSProvider',
        'PushProvider' - all without the leading 'linotp.')
    """

    # XXX LEGACY: providers had no names and composite attribute
    # names (such as EmailProviderConfig - note: without a dot)
    # the name in this case is set to 'imported_default'

    attr_updates = {}

    # ------------------------------------------------------------------------ -

    long_prefix = Provider_types[provider_type]['prefix']
    provider_prefix = long_prefix[len('linotp.'):-1]

    # ------------------------------------------------------------------------ -

    # due to ambiguity of the second part in the config dot notation
    # we must check if the second part is the provider type

    if not composite_key.startswith('linotp.%s' % provider_prefix):
        raise ConfigNotRecognized(composite_key)

    # ------------------------------------------------------------------------ -

    parts = composite_key.split('.')

    if len(parts) != 2:
        raise ConfigNotRecognized(composite_key)

    object_id = 'imported_default'
    composite_attr_name = parts[1]

    # ------------------------------------------------------------------------ -

    prefix_len = len(provider_prefix)
    attr_name = composite_attr_name[prefix_len:]

    if not attr_name:
        attr_name = 'class'

    attr_updates[attr_name] = value

    # ------------------------------------------------------------------------ -

    return object_id, attr_updates


# ------------------------------------------------------------------------------


def parse_default_provider(provider_type, composite_key, value):

    """
    Sets the attribute pair {default: True} to the default provider
    in the tree.

    :param provider_type: A string identifier (such as 'sms', 'email', etc)
    """

    # ------------------------------------------------------------------------ -

    default_key = Default_Provider_Key[provider_type]

    if composite_key != default_key:
        raise ConfigNotRecognized(composite_key)

    # ------------------------------------------------------------------------ -

    return value, {'default': True}

# ------------------------------------------------------------------------------


def parse_system_config(composite_key, value):

    """
    Parses system config entries

    ::warning: does a very generic match. should be added last to the
        config tree parser list
    """

    if not composite_key.startswith('linotp.'):
        raise ConfigNotRecognized(composite_key)

    return 'system_config', {composite_key: value}

# ------------------------------------------------------------------------------


def parse_deprecated_enc(composite_key, value):

    """
    Parses soon to be deprecated 'enclinotp' config entries

    ::warning: does a very generic match. should be added last to the
        config tree parser list
    """

    # XXX LEGACY DEPRECATED

    if not composite_key.startswith('enclinotp.'):
        raise ConfigNotRecognized(composite_key)

    return 'deprecated_enc', {composite_key: value}

# ------------------------------------------------------------------------------


def parse_config(config_dict):

    """
    Translates a flat config_dict into a hierarchical ConfigTree

    :param config_dict: The config dictionary retrieved from
        the low-level typing API

    :return: ConfigTree object
    """

    tree = ConfigTree()
    tree.add_parser('policies', parse_policy)
    tree.add_parser('resolvers', parse_resolver)
    tree.add_parser('realms', parse_realm)
    tree.add_parser('realms', parse_default_realm)

    # --------------------------------------------------------------------------

    for provider_type in Provider_types:

        parser_target = '%s_providers' % provider_type

        func = partial(parse_provider, provider_type)
        tree.add_parser(parser_target, func)

        default_func = partial(parse_default_provider, provider_type)
        tree.add_parser(parser_target, default_func)

        # XXX LEGACY

        if provider_type in Legacy_Provider:
            func = partial(parse_legacy_provider, provider_type)
            tree.add_parser(parser_target, func)

    # --------------------------------------------------------------------------

    tree.add_parser('globals', parse_system_config)
    tree.add_parser('deprecated', parse_deprecated_enc)

    # --------------------------------------------------------------------------

    for composite_key, value in config_dict.items():
        tree.consume_entry(composite_key, value)

    return tree
