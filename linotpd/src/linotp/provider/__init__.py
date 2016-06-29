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
"""
provider handling
"""

import json
import logging
from os import path
from os import listdir

from pylons.i18n.translation import _

from linotp.lib.config import storeConfig
from linotp.lib.config import getLinotpConfig
from linotp.lib.config import getFromConfig
from linotp.lib.config import updateConfig
from linotp.lib.config import removeFromConfig

from linotp.lib.policy import getPolicy
from linotp.lib.policy import getPolicyActionValue
from linotp.lib.context import request_context

from linotp.lib.registry import ClassRegistry

# ------------------------------------------------------------------------------

provider_registry = ClassRegistry()


def reload_classes():

    """ iterates through the modules in this package
    and import every single one of them """

    # Find out the path this file resides in
    abs_file = path.abspath(__file__)
    abs_dir = path.dirname(abs_file)

    # list files
    files_in_ext_path = listdir(abs_dir)

    for fn in files_in_ext_path:
        # filter python files
        if fn.endswith('.py') and not fn == '__init__.py':
            # translate them into module syntax
            # and import
            mod_rel = fn[0:-3]
            try:
                __import__(mod_rel, globals=globals())
            except Exception as exx:
                log.error('unable to load resolver module : %r (%r)'
                          % (mod_rel, exx))

reload_classes()

# ------------------------------------------------------------------------------

Provider_types = {
    'sms': {'prefix': 'linotp.SMSProvider.'},
    'email': {'prefix': 'linotp.EmailProvider.'},
    }

Legacy_Provider = {
    'sms': {'linotp.SMSProvider': 'Class',
            'linotp.SMSProviderTimeout': 'Timeout',
            'linotp.SMSProviderConfig': 'Config'},
    'email': {'linotp.EmailProvider': 'Class',
              # the timeout is not the same as we intent for the
              # provider timeout, but its a good start
              'linotp.EmailBlockingTimeout': 'Timeout',
              'linotp.EmailProviderConfig': 'Config'}
    }

Legacy_Provider_Name = 'imported_default'
Default_Provider_Key = {
    'email': 'linotp.Provider.Default.email_provider',
    'sms': 'linotp.Provider.Default.sms_provider'
    }

Policy_action_name = {
    'email': 'email_provider',
    'sms': 'sms_provider',
    }

# lookup definition to support legacy provider classes definitions
ProviderClass_lookup = {
    "emailprovider.HttpemailProvider.HttpSMSProvider":
        'linotp.provider.emailprovider.SMTPEmailProvider',
    'linotp.lib.emailprovider.SMTPEmailProvider':
        'linotp.provider.emailprovider.SMTPEmailProvider',
    }

log = logging.getLogger(__name__)


def get_legacy_provider(provider_type):
    """
    return a dict with legacy email or sms providers

    :param provider_type: either sms or email
    :return: dict with the provider
    """

    provider = {}
    config = getLinotpConfig()

    defintion = Legacy_Provider.get(provider_type, {})
    if not defintion:
        raise Exception('unknown provider type %r' % provider_type)

    for key, translation in defintion.items():
        if key in config:
            provider[translation] = config[key]
        if 'enc' + key in config:
            provider[translation] = config['enc' + key]

    # prepare for return
    legacy_provider = {}
    if "Config" in provider:
        provider['Default'] = False
        legacy_provider[Legacy_Provider_Name] = provider

    return legacy_provider


def get_all_new_providers(provider_type):
    """
    get all providers of the new format
    :param provider_type: the type of the provider
    :return: dict with all providers
    """

    providers = {}

    provider_names = {}

    # find out, which provider type we have, currently only sms or email
    prefix = Provider_types.get(provider_type, {}).get('prefix')
    if not prefix:
        raise Exception('unknown provider type %r' % provider_type)

    # find out, which providers we have
    config = getLinotpConfig()

    # first identify all providers by its name
    for key, value in config.items():
        if key[:len(prefix)] == prefix:
            parts = key.split('.')
            if len(parts) == 3:
                provider_names[key] = value

    for provider, provider_class in provider_names.items():

        defintion = {}
        defintion['Class'] = provider_class
        prefix = provider + '.'

        for key, value in config.items():
            if key[:len(prefix)] == prefix:
                if 'enc' + key in config:
                    value = config.get('enc' + key)
                entry = key.replace(prefix, '')
                defintion[entry] = value

        defintion['Default'] = False
        name = provider.split('.')[2]
        providers[name] = defintion

    return providers


def get_default_provider(provider_type):
    """
    find out, which provider is declared as default

    :param provider_type: sms or email
    :return: the name of the default provider
    """
    config = getLinotpConfig()

    # finally care for the default provider
    default_provider_key = Default_Provider_Key[provider_type]
    default_provider = config.get(default_provider_key, None)
    return default_provider


def getProvider(provider_type, provider_name=None):
    """
    return a dict with  providers, each with it's description as dict

    :param provider_type: either sms or email
    :param provider_name: name of the provider (optional)
    :return: the dict with all providers
    """
    providers = {}

    legacy_provider = get_legacy_provider(provider_type)
    providers.update(legacy_provider)

    new_providers = get_all_new_providers(provider_type)
    providers.update(new_providers)

    if not providers:
        return {}

    # is there already one provider registered as default?
    default_provider_name = get_default_provider(provider_type)
    if default_provider_name and default_provider_name in providers:
        provider = providers.get(default_provider_name)
        provider['Default'] = True
    else:
        # we take the first one in the list as the default
        firstone = providers.keys()[0]
        provider = providers[firstone]
        provider['Default'] = True
        default_provider_key = Default_Provider_Key[provider_type]
        storeConfig(default_provider_key, firstone)

    if provider_name:
        if provider_name in providers:
            return {provider_name: providers[provider_name]}
        else:
            return {}

    return providers


def delProvider(provider_type, provider_name):
    """
    delete a provider

    :param provider_type: the type of Provider: sms or email
    :param provider_name: the name of the provider

    :return: the number of deleted entries
    """
    detail = {}

    prefix = Provider_types.get(provider_type, {}).get('prefix')
    if not prefix:
        raise Exception('unknown provider type %r' % provider_type)

    # find out, which providers we have
    config = getLinotpConfig()

    # if the provider is the default one, we don't delete this one
    default_provider_key = Default_Provider_Key[provider_type]
    if default_provider_key in config:
        default_provider = config[default_provider_key]

        if provider_name == default_provider:
            detail = {'message': _('Default provider could not be deleted!')}
            ret = 0
            return ret, detail

    # check that there are no references left
    provider_policies = _lookup_provider_policies(provider_type)
    if provider_name in provider_policies:
        detail = {
            'message': (_('Unable to delete - provider used in '
                          'policies!\n[%s]') %
                        ','.join(provider_policies[provider_name]))
            }
        ret = 0
        return ret, detail

    del_entries = set()
    provider = prefix + provider_name

    # treat backward default legacy case
    if provider_name == Legacy_Provider_Name:
        entries = Legacy_Provider.get(provider_type, {})
        for entry in entries.keys():
            if entry in config:
                del_entries.add(entry)

    if not del_entries:
        # first delete the provider root entry
        if provider in config:
            del_entries.add(provider)

        # now lookup the all decent entries
        provider_prefix = provider + '.'
        for key in config.keys():
            if key[:len(provider_prefix)] == provider_prefix:
                del_entries.add(key)

    # when all entries are gathered, we can now delete them all
    for del_entry in del_entries:
        removeFromConfig(del_entry)

    ret = len(del_entries)

    return ret, detail


def setProvider(params):
    """
    save the provider info in linotp config

    :param params: generic parameter dictionary to support later more complex
                   provider definitions
                   in the dictionary currently required keys are
                   :param type: sms or email
                   :param name: the provider name
                   :param config: the provider config
                   :param timeout: the provider timeout
                   :param: default: boolean

    :return: success - boolean
    """

    provider_type = params['type']
    provider_name = params['name']

    if provider_name == Legacy_Provider_Name:
        save_legacy_provider(provider_type, params)
    else:
        save_new_provider(provider_type, provider_name, params)

    if 'default' in params:
        default_provider_key = Default_Provider_Key[provider_type]
        if params['default'] is True or params['default'].lower() == 'true':
            storeConfig(key=default_provider_key, val=provider_name)

    return True, {}


def save_legacy_provider(provider_type, params):
    """
    save the provider to the legacy format

    :param provider_type: sms or email provider
    :param params: the provider description dict with 'class', 'config' and
                   'timeout'

    """

    defintion = Legacy_Provider.get(provider_type, {})
    if not defintion:
        raise Exception('unknown provider type %r' % provider_type)

    for config_name, spec in defintion.items():
        if spec == 'Class' and 'class' in params:
            storeConfig(key=config_name, val=params['class'])
        if spec == 'Config' and 'config' in params:
            storeConfig(key=config_name, val=params['config'], typ='password')
        if spec == 'Timeout' and 'timeout' in params:
            storeConfig(key=config_name, val=params['timeout'])

    return


def save_new_provider(provider_type, provider_name, params):
    """
    save the provider in the new provider format

    remarks:
        alternative to storing the whole config in encrypted way, we
        might look if it's a json and store the next Config.  level
        and look for the reserved additional appended type: password

    :param provider_type: sms or email provider
    :param provider_name: the name of the provider
    :param params: the provider description dict with 'class', 'config',
                   and 'timeout'

    """

    prefix = Provider_types.get(provider_type, {}).get('prefix')
    if not prefix:
        raise Exception('unknown provider type %r' % provider_type)

    provider_prefix = prefix + provider_name

    storeConfig(key=provider_prefix, val=params['class'])
    storeConfig(key=provider_prefix + '.Timeout', val=params['timeout'])

    storeConfig(key=provider_prefix + '.Config', val=params['config'],
                typ='password')

    return True, {}


def setDefaultProvider(provider_type, provider_name):
    """
    interface to set the default provider wo. storing the provider

    :param provider_type: the type of the provider: sms or email
    :param provider_name: the name of the provider - must exist
    :return: boolean, success of storing default provider information
    """
    res = False
    detail = {}

    providers = getProvider(provider_type, provider_name)
    if provider_name in providers or provider_name == Legacy_Provider_Name:
        default_provider_key = Default_Provider_Key[provider_type]
        storeConfig(key=default_provider_key, val=provider_name)
        res = True
    else:
        detail = {'message': _('Unknown provider! %r') % provider_name}
    return res, detail


def loadProviderFromPolicy(provider_type, realm=None, user=None):
    """
    interface for the provider user like email token or sms token

    :param provider_type: 'email' or 'sms
    :param user: the user, who should receive the message, used for
                 the policy lookup
    :return: the instantiated provider with already loaded config
    """

    # check if the provider is defined in a policy
    provider_name = None

    # lookup the policy action name
    provider_action_name = Policy_action_name.get(provider_type)
    if not provider_action_name:
        raise Exception('unknown provider_type for policy lookup! %r'
                        % provider_type)

    if not user:
        raise Exception('unknown user for policy lookup! %r'
                        % user)

    params = {'scope': 'authentication',
              'action': provider_action_name
              }

    if realm:
        params['realm'] = realm

    if user and user.login:
        params["realm"] = user.realm
        params["user"] = user.login

    policies = getPolicy(params)

    if policies:
        provider_name = getPolicyActionValue(policies,
                                             provider_action_name,
                                             is_string=True)

    return loadProvider(provider_type, provider_name)


def _lookup_provider_policies(provider_type):
    """
    helper, to prevent deleting a provider while it is still used in a policy

    :param provider_type: the type of provider: sms or email
    :return: a dictionary with provider names as key and list of policy names
    """
    provider_policies = {}

    # lookup the policy action name
    provider_action_name = Policy_action_name.get(provider_type)
    if not provider_action_name:
        raise Exception('unknown provider_type for policy lookup! %r'
                        % provider_type)

    # now have a look at all authentication policies
    policies = getPolicy({'scope': 'authentication',
                          "action": provider_action_name,
                          })

    for policy in policies:
        provider_name = getPolicyActionValue(policies,
                                             provider_action_name,
                                             is_string=True)
        if provider_name not in provider_policies:
            provider_policies[provider_name] = []

        provider_policies[provider_name].append(policy)

    return provider_policies


def loadProvider(provider_type, provider_name=None):
    """
    interface for the provider user like email token or sms token

    :param provider_type: 'email' or 'sms
    :param provider_name: the name of the provider configuration

    :return: the instantiated provider with already loaded configuration
    """
    provider_info = {}

    config = getLinotpConfig()
    default_provider_key = Default_Provider_Key[provider_type]

    #
    # if no provider is given, we try to lookup the default
    #
    if default_provider_key in config and not provider_name:
        provider_name = config[default_provider_key]

    #
    # if there is no provider_name or the provider is a legacy one
    # try to load it the legacy way
    #
    if not provider_name or provider_name == Legacy_Provider_Name:
        provider_info = get_legacy_provider(provider_type=provider_type)
        provider_name = Legacy_Provider_Name

    #
    # in case of no provider_info the provider is
    # either a new one or or a legacy converted one
    #
    if not provider_info:
        providers = getProvider(provider_type, provider_name=provider_name)
        provider_info = providers.get(provider_name)

    if not provider_info:
        raise Exception('Unable to load provider: %r' % provider_name)

    provider_info = provider_info.get(provider_name, provider_info)
    provider_class = provider_info.get('Class')

    try:
        provider_class_obi = _load_provider_class(provider_class)
        provider = provider_class_obi()
    except Exception as exc:
        log.exception("Failed to load provider: %r", exc)
        raise exc

    provider_config = {}
    config = provider_info['Config']

    #
    # backward compatibility hack: fix the handling of multiline config entries
    #
    lconfig = []
    lines = config.splitlines()
    for line in lines:
        line = line.strip('\\')
        if len(line) > 0:
            lconfig.append(line)

    config = " ".join(lconfig)

    try:
        provider_config = json.loads(config)
    except ValueError as exx:
        log.exception('Failed to load provider config %r', config)
        raise ValueError('Failed to load provider config:%r %r'
                         % (config, exx))

    provider.loadConfig(provider_config)

    return provider


def _load_provider_class(provider_Class):
    """
    _loadProviderClass():

    helper method to load the EmailProvider class from config
    """
    if not provider_Class:
        raise Exception("No provider class defined.")

    provider_class = ProviderClass_lookup.get(provider_Class, provider_Class)
    provider_class_obj = provider_registry.get(provider_class)

    if provider_class_obj is None:

        if '.' not in provider_class:
            raise Exception("Unknown provider class: Identifier was %s" %
                            provider_class)

        # if there is no entry in the registry we try to fall back to
        # the old style of loading a module definition

        try:

            packageName, _, className = provider_class.rpartition('.')
            mod = __import__(packageName, globals(), locals(), [className])
            provider_class_obj = getattr(mod, className)

        except ImportError as err:
            raise Exception("Unknown provider class: Identifier was %s - %r" %
                            (provider_class, err))

        except AttributeError as err:
            raise Exception("Unknown provider class: Identifier was %s - %r" %
                            (provider_class, err))

    if not hasattr(provider_class_obj, "submitMessage"):
        raise NameError("Provider AttributeError: %s "
                        "Provider has no method 'submitMessage'" %
                        (provider_class_obj.__name__))

    return provider_class_obj

# eof ####################################################################
