# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
"""
provider handling
"""

import json
import logging
from os import path
from os import listdir
from os import walk

from pylons.i18n.translation import _

from linotp.lib.config import storeConfig
from linotp.lib.config import getLinotpConfig
from linotp.lib.config import getFromConfig
from linotp.lib.config import updateConfig
from linotp.lib.config import removeFromConfig

from linotp.lib.policy import getPolicy, get_client_policy
from linotp.lib.policy import getPolicyActionValue
from linotp.lib.context import request_context

from linotp.lib.registry import ClassRegistry
from linotp.lib.module_loader import import_submodules

log = logging.getLogger(__name__)

# -------------------------------------------------------------------------- --
# establish the global provider module registry

provider_registry = ClassRegistry()


def load_provider_classes():

    """ iterates through the modules in this package and import every single
    one of them. This will trigger the registration of the providers in
    the global provider_registry (s.o.), which registers all available
    provider classes

    :sideeffect: the classes in the submodules are registrated in the
                 provider registry
    """

    try:
        import_submodules(__name__)
        import_submodules("%s.%s" % (__name__, "pushprovider"))
        import_submodules("%s.%s" % (__name__, "emailprovider"))
    except ImportError as exx:
        log.error('unable to load provider module : %s (%r)', __name__, exx)
        raise Exception(exx)

    # the sms providers are optional, so we just log the error in case of an
    # import error
    try:
        import smsprovider
        import_submodules('smsprovider')
    except ImportError as exx:
        log.error('unable to load provider module : smsprovider (%r)', exx)


load_provider_classes()

# -------------------------------------------------------------------------- --
# some declarations for the loading and storing of provider configurations

# the storing prefixes
Provider_types = {
    'sms': {'prefix': 'linotp.SMSProvider.'},
    'email': {'prefix': 'linotp.EmailProvider.'},
    'push': {'prefix': 'linotp.PushProvider.'},
    }

# legacy keys used in the linotp config
Legacy_Provider = {
    'sms': {'linotp.SMSProvider': 'Class',
            'linotp.SMSProviderTimeout': 'Timeout',
            'linotp.SMSProviderConfig': 'Config'},
    'email': {'linotp.EmailProvider': 'Class',
              # the timeout is not the same as we intent for the
              # provider timeout, but its a good start
              'linotp.EmailBlockingTimeout': 'Timeout',
              'linotp.EmailProviderConfig': 'Config'},
    }

Legacy_Provider_Name = 'imported_default'

Default_Provider_Key = {
    'email': 'linotp.Provider.Default.email_provider',
    'sms': 'linotp.Provider.Default.sms_provider',
    'push': 'linotp.Provider.Default.push_provider'
    }

Policy_action_name = {
    'email': 'email_provider',
    'sms': 'sms_provider',
    'push': 'push_provider',
    }

# lookup definition to support legacy provider classes definitions
ProviderClass_lookup = {
    "emailprovider.HttpemailProvider.HttpSMSProvider":
        'linotp.provider.emailprovider.SMTPEmailProvider',
    'linotp.lib.emailprovider.SMTPEmailProvider':
        'linotp.provider.emailprovider.SMTPEmailProvider',
    }


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

    # find out, which provider type we have, currently only push, sms or email
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

        # in case of a managed provider, the configuration is not displayed
        if prefix + 'Managed' in config:
            defintion['Managed'] = config.get(prefix + 'Managed')
            del defintion['Config']

        name = provider.split('.')[2]
        providers[name] = defintion

    return providers


def get_default_provider(provider_type):
    """
    find out, which provider is declared as default

    :param provider_type: push, sms or email
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

    :param provider_type: either push, sms or email
    :param provider_name: name of the provider (optional)
    :return: the dict with all providers
    """
    providers = {}

    if provider_type in Legacy_Provider.keys():
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

    :param provider_type: the type of Provider: push, sms or email
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
                   :param type: push,sms or email
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

    :param provider_type: push, sms or email provider
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

    :param provider_type: push, sms or email provider
    :param provider_name: the name of the provider
    :param params: the provider description dict with 'class', 'config',
                   and 'timeout'

    """

    prefix = Provider_types.get(provider_type, {}).get('prefix')
    if not prefix:
        raise Exception('unknown provider type %r' % provider_type)

    provider_prefix = prefix + provider_name

    storeConfig(key=provider_prefix, val=params['class'])

    config_mapping = {
        'timeout': ('Timeout', None),
        'config': ('Config', 'password')}

    #
    # alternative config entries are supported by the the adjustable config
    # entries if the provider supports the 'getConfigMapping' interface:
    #
    try:
        provider_class = _load_provider_class(params['class'])
        config_mapping = provider_class.getConfigMapping()
    except AttributeError as exx:
        log.debug("provider %r does not support ConfigMapping: %r",
                  provider_name, exx)

    # add the extra parameter for each resolver that it could be a managed one

    config_mapping['managed'] = ('Managed', None)

    for config_entry in config_mapping.keys():

        if config_entry not in params:
            continue

        # get the mapping entry and split the config name and type
        mapping_entry = config_mapping[config_entry]
        config_key, config_type = mapping_entry

        # store the config entry
        storeConfig(key=provider_prefix + '.' + config_key,
                    val=params[config_entry],
                    typ=config_type)

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

    :param provider_type: 'push', 'email' or 'sms
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

    if user and user.login:
        realm = user.realm

    policies = get_client_policy(request_context['Client'],
                                 scope='authentication',
                                 action=provider_action_name, realm=realm,
                                 user=user.login)

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
                          "action": provider_action_name, })

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

    :param provider_type: 'push', 'email' or 'sms
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

    provider_config = _build_provider_config(provider_info)
    provider.loadConfig(provider_config)

    return provider


def _build_provider_config(provider_info):
    """
    internal function to build up dict with the provider config

    :param provider_info: loaded info for the provider (containing Config)
    :return: dictionary with the config of the provider
    """

    provider_config = {}

    line_config = provider_info['Config']
    line_config = _fix_config_contiuation(line_config)

    try:
        provider_config = json.loads(line_config)
    except ValueError as exx:
        log.exception('Failed to load provider config %r', provider_config)
        raise ValueError('Failed to load provider config:%r %r'
                         % (provider_config, exx))

    # we have to add the other, additional parameters like timeout
    for additional, value in provider_info.items():
        if additional not in ['Default', 'Config', 'Class']:
            if additional == 'Timeout':
                provider_config['timeout'] = value
            else:
                provider_config[additional] = value

    return provider_config


def _fix_config_contiuation(line_config):
    """
    backward compatibility hack: fix the handling of multiline config entries

    :param line_config: configuration as a string value
    :return: config as string value
    """
    lconfig = []
    lines = line_config.splitlines()
    for line in lines:
        line = line.strip('\\')
        if len(line) > 0:
            lconfig.append(line)

    return " ".join(lconfig)



def _load_provider_class(provider_slass_spec):
    """
    _loadProviderClass():

    helper method to load the EmailProvider class from config
    """
    if not provider_slass_spec:
        raise Exception("No provider class defined.")

    provider_class = ProviderClass_lookup.get(provider_slass_spec,
                                              provider_slass_spec)
    provider_class_obj = provider_registry.get(provider_class)

    if provider_class_obj is None:

        if '.' not in provider_class:
            raise Exception("Unknown provider class: Identifier was %s" %
                            provider_class)

        # if there is no entry in the registry we try to fall back to
        # the old style of loading a module definition

        try:

            packageName, _, className = str(provider_class).rpartition('.')
            mod = __import__(packageName, globals(), locals(), [className])
            provider_class_obj = getattr(mod, className)

        except ImportError as err:
            raise Exception("Unknown provider class: Identifier was %s - %r" %
                            (provider_class, err))

        except AttributeError as err:
            raise Exception("Unknown provider class: Identifier was %s - %r" %
                            (provider_class, err))

    #
    # as not all providers are inherited from a super provider,
    # we only can check for the existance of the required methods :-(
    #

    required_method = ['submitMessage', 'push_notification']
    is_provider = False
    for method in required_method:
        if hasattr(provider_class_obj, method):
            is_provider = True

    if not is_provider:
        raise NameError("Provider AttributeError: %s "
                        "Provider has no method %s" %
                        (provider_class_obj.__name__,
                         ' or '.join(required_method)))

    return provider_class_obj

# eof ####################################################################
