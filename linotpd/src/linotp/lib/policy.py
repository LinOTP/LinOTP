# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
""" policy processing """

import logging

import linotp.lib.token

from pylons import request, config, tmpl_context as c

from linotp.lib.config import getLinotpConfig
from linotp.lib.config import removeFromConfig
from linotp.lib.config import storeConfig

from linotp.lib.realm import getDefaultRealm
from linotp.lib.realm import getRealms

from linotp.lib.user import getUserRealms
from linotp.lib.user import User, getUserFromParam, getUserFromRequest
from linotp.lib.user import getResolversOfUser

from linotp.lib.util import get_client

from linotp.lib.error import ServerError, LinotpError

from netaddr import IPAddress
from netaddr import IPNetwork

from configobj import ConfigObj


# for loading XML file
import re
# for generating random passwords
from linotp.lib.crypt import urandom
import string

from linotp.lib.util import getParam, uniquify

log = logging.getLogger(__name__)


optional = True
required = False


REG_POLICY_C = config.get("linotpPolicy.pin_c", "[a-zA-Z]")
REG_POLICY_N = config.get("linotpPolicy.pin_n", "[0-9]")
REG_POLICY_S = config.get("linotpPolicy.pin_s", "[.:,;-_<>+*!/()=?$§%&#~\^]")


# This dictionary maps the token_types to actions in the scope gettoken,
# that define the maximum allowed otp valies in case of getotp/getmultiotp
MAP_TYPE_GETOTP_ACTION = {"dpw": "max_count_dpw",
                          "hmac": "max_count_hotp",
                          "totp": "max_count_totp"}


class PolicyException(LinotpError):
    def __init__(self, description="unspecified error!", id=410):
        LinotpError.__init__(self, description=description, id=id)


class AuthorizeException(LinotpError):
    def __init__(self, description="unspecified error!", id=510):
        LinotpError.__init__(self, description=description, id=id)


def getPolicyDefinitions(scope=""):
    '''
        returns the policy definitions of
          - allowed scopes
          - allowed actions in scopes
          - type of actions
    '''

    pol = {
        'admin': {
            'enable': {'type': 'bool'},
            'disable': {'type': 'bool'},
            'set': {'type': 'bool'},
            'setOTPPIN': {'type': 'bool'},
            'setMOTPPIN': {'type': 'bool'},
            'setSCPIN': {'type': 'bool'},
            'resync': {'type': 'bool'},
            'reset': {'type': 'bool'},
            'assign': {'type': 'bool'},
            'unassign': {'type': 'bool'},
            'import': {'type': 'bool'},
            'remove': {'type': 'bool'},
            'userlist': {'type': 'bool'},
            'checkstatus': {'type': 'bool'},
            'manageToken': {'type': 'bool'},
            'getserial': {'type': 'bool'},
            'copytokenpin': {'type': 'bool'},
            'copytokenuser': {'type': 'bool'},
            'losttoken': {'type': 'bool'},
            'getotp': {
                'type': 'bool',
                'desc': 'allow the administrator to retrieve '
                        'OTP values for tokens.'
                }
        },
        'gettoken': {
            'max_count_dpw': {'type': 'int'},
            'max_count_hotp': {'type': 'int'},
            'max_count_totp': {'type': 'int'},
        },
        'selfservice': {
            'assign': {
                'type': 'bool',
                'desc': "The user is allowed to assign an existing "
                        "token using the token serial number."},
            'disable': {'type': 'bool'},
            'enable': {'type': 'bool'},
            'delete': {'type': 'bool'},
            'unassign': {'type': 'bool'},
            'resync': {'type': 'bool'},
            'reset': {
                'type': 'bool',
                'desc': 'Allow to reset the failcounter of a token.'},
            'setOTPPIN': {'type': 'bool'},
            'setMOTPPIN': {'type': 'bool'},
            'getotp': {'type': 'bool'},
            'otp_pin_maxlength': {'type': 'int', 'value': range(0, 100)},
            'otp_pin_minlength': {'type': 'int', 'value': range(0, 100)},
            'otp_pin_contents': {'type': 'str'},
            'activateQR': {'type': 'bool'},
            'webprovisionOATH': {'type': 'bool'},
            'webprovisionGOOGLE': {'type': 'bool'},
            'webprovisionGOOGLEtime': {'type': 'bool'},
            'max_count_dpw': {'type': 'int'},
            'max_count_hotp': {'type': 'int'},
            'max_count_totp': {'type': 'int'},
            'history': {
                'type': 'bool',
                'desc': 'Allow the user to view his own token history'},
            'getserial': {
                'type': 'bool',
                'desc': 'Allow to search an unassigned token by OTP value.'}
            },
        'system': {
            'read': {'type': 'bool'},
            'write': {'type': 'bool'},
            },
        'enrollment': {
            'tokencount': {
                'type': 'int',
                'desc': 'Limit the number of tokens in a realm.'},
            'maxtoken': {
                'type': 'int',
                'desc': 'Limit the number of tokens a user in the realm may '
                        'have assigned.'},
            'otp_pin_random': {
                'type': 'int',
                'value': range(0, 100)},
            'otp_pin_encrypt': {
                'type': 'int',
                'value': [0, 1]},
            'tokenlabel': {
                'type': 'str',
                'desc': 'the label for the google authenticator.'},
            'autoassignment': {
                'type': 'int',
                'value': [6, 8],
                'desc': 'users can assign a token just by using the '
                        'unassigned token to authenticate.'},
            'autoassignment': {
				'type': 'int',
                'value': [6, 8, 32, 48],
                'desc' : 'users can assign a token just by using the unassigned token to authenticate.'},
            'ignore_autoassignment_pin': {
				'type': 'bool',
                'desc' : "Do not set password from auto assignment as token pin."},
            'lostTokenPWLen': {
                'type': 'int',
                'desc': 'The length of the password in case of '
                        'temporary token.'},
            'lostTokenPWContents': {
                'type': 'str',
                'desc': 'The contents of the temporary password, '
                        'described by the characters C, c, n, s.'},
            'lostTokenValid': {
                'type': 'int',
                'desc': 'The length of the validity for the temporary '
                        'token (in days).'},
            },
        'authentication': {
            'smstext': {
                'type': 'str',
                'desc': 'The text that will be send via SMS for an SMS token. '
                        'Use <otp> and <serial> as parameters.'},
            'otppin': {
                'type': 'int',
                'value': [0, 1, 2],
                'desc': 'either use the Token PIN (0), use the Userstore '
                        'Password (1) or use no fixed password '
                        'component (2).'},
            'autosms': {
                'type': 'bool',
                'desc': 'if set, a new SMS OTP will be sent after '
                        'successful authentication with one SMS OTP'},
            'passthru': {
                'type': 'bool',
                'desc': 'If set, the user in this realm will be authenticated '
                        'against the UserIdResolver, if the user has no '
                        'tokens assigned.'
                },
            'passOnNoToken': {
                'type': 'bool',
                'desc': 'if the user has no token, the authentication request '
                        'for this user will always be true.'
                },
            'qrtanurl': {
                'type': 'str',
                'desc': 'The URL for the half automatic mode that should be '
                        'used in a QR Token'
                },
            'challenge_response': {
                'type': 'str',
                'desc': 'A list of tokentypes for which challenge response '
                        'should be used.'
                }
            },
        'authorization': {
            'authorize': {
                'type': 'bool',
                'desc': 'The user/realm will be authorized to login '
                        'to the clients IPs.'},
            'tokentype': {
                'type': 'str',
                'desc': 'The user will only be authenticated with this '
                        'very tokentype.'},
            'serial': {
                'type': 'str',
                'desc': 'The user will only be authenticated if the serial '
                        'number of the token matches this regexp.'},
            'setrealm': {
                'type': 'str',
                'desc': 'The Realm of the user is set to this very realm. '
                        'This is important if the user is not contained in '
                        'the default realm and can not pass his realm.'},
            'detail_on_success': {
                'type': 'bool',
                'desc': 'In case of successful authentication additional '
                        'detail information will be returned.'},
            'detail_on_fail': {
                'type': 'bool',
                'desc': 'In case of failed authentication additional '
                        'detail information will be returned.'}
            },
        'audit': {
            'view': {
                'type': 'bool'}
        },
        'ocra': {
            'request': {
                'type': 'bool',
                'desc': 'Allow to do a ocra/request'},
            'status': {
                'type': 'bool',
                'desc': 'Allow to check the transaction status.'},
            'activationcode': {
                'type': 'bool',
                'desc': 'Allow to do an ocra/getActivationCode.'},
            'calcOTP': {
                'type': 'bool',
                'desc': 'Allow to do an ocra/calculateOtp.'}
        }
    }

    ## now add generic policies, which every token should provide:
    ## - init<TT>
    ## - enroll<TT>, but only, if there is a rendering section

    token_type_list = linotp.lib.token.get_token_type_list()

    for ttype in token_type_list:
        pol['admin']["init%s" % ttype.upper()] = {'type': 'bool'}

        ## TODO: action=initETNG
        ## Cornelius Kölbel        Apr 18 7: 31 PM
        ##
        ## Haben wir auch noch den die policy
        ##
        ## scope=admin, action=initETNG?
        ##
        ## Das ist nämlich eine spezialPolicy, die der HMAC-Token mitbringen
        ## muss.

        ## todo: if all tokens are dynamic, the token init must be only shown
        ## if there is a rendering section for:
        ## conf = linotp.lib.token.getTokenConfig(ttype, section='init')
        ## if len(conf) > 0:
        ##    pol['admin']["init%s" % ttype.upper()]={'type': 'bool'}

        conf = linotp.lib.token.getTokenConfig(ttype, section='selfservice')
        if 'enroll' in conf:
            pol['selfservice']["enroll%s" % ttype.upper()] = {
                'type': 'bool',
                'desc': "The user is allowed to enroll a %s token." % ttype}

        ## now merge the dynamic Token policy definition
        ## into the global definitions
        policy = linotp.lib.token.getTokenConfig(ttype, section='policy')

        ## get all policy sections like: admin, selfservice . . '''
        pol_keys = pol.keys()

        for pol_section in policy.keys():
            ## if we have a dyn token definition of this section type
            ## add this to this section - and make sure, that it is
            ## then token type prefixed
            if pol_section in pol_keys:
                pol_entry = policy.get(pol_section)
                for pol_def in pol_entry:
                    set_def = pol_def
                    if pol_def.startswith(ttype) is not True:
                        set_def = '%s_%s' % (ttype, pol_def)

                    pol[pol_section][set_def] = pol_entry.get(pol_def)

    ##return sub section, if scope is defined
    ##  make sure that scope is in the policy key
    ##  e.g. scope='_' is undefined and would break
    if scope and scope in pol:
        pol = pol[scope]

    return pol


def setPolicy(param):
    '''
    Function to set a policy. It expects a dict of with the following keys:

      * name
      * action
      * scope
      * realm
      * user
      * time
      * client
    '''
    ret = {}
    name = param.get('name')
    action = param.get('action')
    scope = param.get('scope')
    realm = param.get('realm')
    user = param.get('user')
    time = param.get('time')
    client = param.get('client')
    active = param.get('active', True)
    ret["action"] = storeConfig("Policy.%s.action" % name,
                                action, "", "a policy definition")
    ret["scope"] = storeConfig("Policy.%s.scope" % name,
                               scope, "", "a policy definition")
    ret["realm"] = storeConfig("Policy.%s.realm" % name,
                               realm, "", "a policy definition")
    ret["user"] = storeConfig("Policy.%s.user" % name,
                              user, "", "a policy definition")
    ret["time"] = storeConfig("Policy.%s.time" % name,
                              time, "", "a policy definition")
    ret["client"] = storeConfig("Policy.%s.client" % name,
                                client, "", "a policy definition")
    ret["active"] = storeConfig("Policy.%s.active" % name,
                                active, "", "a policy definition")

    return ret


def create_policy_export_file(policy, filename):
    '''
    This function takes a policy dictionary and creates an export file from it
    '''
    TMP_DIRECTORY = "/tmp"
    filename = "%s/%s" % (TMP_DIRECTORY, filename)
    if len(policy) == 0:
        f = open(filename, "w")
        f.write('')
        f.close()
    else:
        for value in policy.values():
            for k in value.keys():
                value[k] = value[k] or ""

        policy_file = ConfigObj(encoding="UTF-8")
        policy_file.filename = filename

        for name in policy.keys():
            policy_file[name] = policy[name]
            policy_file.write()

    return filename


def getPolicy(param, display_inactive=False):
    '''
    Function to retrieve the list of policies.

    attributes:
        name:   (optional) will only return the policy with the name
        user:   (optional) will only return the policies for this user
        realm:  (optional) will only return the policies of this realm
        scope:  (optional) will only return the policies within this scope
        action: (optional) will only return the policies with this action
                The action can also be something like "otppin" and will
                return policies containing "otppin = 2"

    returns:
         a dictionary with the policies. The name of the policy being the key
    '''
    Policies = {}

    #log.debug("[getPolicy] params %s" % str(param))

    # First we load ALL policies from the Config
    lConfig = getLinotpConfig()
    for entry in lConfig:
        if entry.startswith("linotp.Policy."):
            #log.debug("[getPolicy] entry: %s" % entry )
            policy = entry.split(".", 4)
            if len(policy) == 4:
                # check if we should return this named policy
                insert_this = True
                if param.get('name', None) is not None:
                    # If a named policy was requested, we do not want to add
                    # the policy if the name does not match!
                    insert_this = bool(param['name'].lower()
                                       == policy[2].lower())

                if insert_this:
                    name = policy[2]
                    key = policy[3]
                    value = lConfig.get(entry)
                    #log.debug("[getPolicy] found POL: %s, KEY: %s, VAL: %s"
                    #          %(name, key, value))

                    if name in Policies:
                        if key == "realm":
                            if value is not None:
                                value = value.lower()
                        Policies[name][key] = value
                    else:
                        Policies[name] = {key: value}
                    #log.debug( Policies )

    # Now we need to clean up policies, that are inactive
    if not display_inactive:
        pol2delete = []
        for polname, policy in Policies.items():
            pol_active = policy.get("active", "True")
            if pol_active == "False":
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    # Now we need to clean up realms, that were not requested
    pol2delete = []
    if param.get('realm', None) is not None:
        #log.debug("[getPolicy] cleanup acccording to realm %s"
        #          % param["realm"])
        for polname, policy in Policies.items():
            delete_it = True
            #log.debug("[getPolicy] evaluating policy %s: %s"
            #          % (polname, str(policy)))
            if policy.get("realm") is not None:
                pol_realms = [p.strip()
                              for p in policy['realm'].lower().split(',')]
                #log.debug("[getPolicy] realms in policy %s: %s"
                #          % (polname, str(pol_realms) ))
                for r in pol_realms:
                    #log.debug("[getPolicy] Realm: %s" % r)
                    if r == param['realm'].lower() or r == '*':
                        #log.debug( "[getPolicy] Setting delete_it to false.
                        # Se we are using policy: %s" % str(polname))
                        delete_it = False
            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('scope', None) is not None:
        #log.debug("[getPolicy] cleanup acccording to scope %s"
        #          % param["scope"])
        for polname, policy in Policies.items():
            if policy['scope'].lower() != param['scope'].lower():
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('action', None) is not None:
        #log.debug("[getPolicy] cleanup acccording to action %s"
        #          % param["action"])
        for polname, policy in Policies.items():
            delete_it = True
            #log.debug("[getPolicy] evaluating policy %s: %s"
            #          % (polname, str(policy)))
            if policy.get("action") is not None:
                pol_actions = [p.strip()
                               for p in policy.get('action', "").
                               lower().split(',')]
                #log.debug("[getPolicy] actions in policy %s: %s "
                #          % (polname, str(pol_actions) ))
                # so even if there is an action like otppin=XXX,
                # it will finde the action "otppin"
                for a in [pa.split("=")[0].strip() for pa in pol_actions]:
                    # if the action in the policy is '*' it fits all actions!
                    #log.debug( "[getPolicy] Action: %s" % a )
                    if a.lower() == param['action'].lower() or a == "*":
                        #log.debug( "[getPolicy] Setting delete_it to false.
                        #So we are using policy: %s" % str(polname))
                        delete_it = False
            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('user', None) is not None:
        #log.debug("[getPolicy] cleanup acccording to user %s" % param["user"])
        for polname, policy in Policies.items():
            pol_users = [p.strip()
                         for p in policy.get('user').lower().split(',')]
            #log.debug("[getPolicy] users in policy %s: %s"
            #          % (polname, str(pol_users) ))
            delete_it = True
            for u in pol_users:
                #log.debug("[getPolicy] User: %s" % u )
                if u == param['user'].lower():
                    #log.debug("[getPolicy] setting delete_it to false."
                    #          "We are using policy %s" % str(polname))
                    delete_it = False
            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    log.debug("[getPolicy] getting policies %s for "
              "params %s" % (Policies, param))
    return Policies


def deletePolicy(name):
    '''
    Function to delete one named policy

    attributes:
        name:   (required) will only return the policy with the name
    '''
    res = {}
    if not re.match('^[a-zA-Z0-9_]*$', name):
        raise ServerError("policy name may only contain the "
                          "characters a-zA-Z0-9_", id=8888)

    Config = getLinotpConfig()
    delEntries = []
    for entry in Config:
        if entry.startswith("linotp.Policy.%s." % name):
            delEntries.append(entry)

    for entry in delEntries:
        #delete this entry.
        log.debug("[deletePolicy] removing key: %s" % entry)
        ret = removeFromConfig(entry)
        res[entry] = ret

    return res


def getPolicyActionValue(policies, action, max=True, String=False):
    '''
    This function retrieves the int value of an action from a list of policies
    input
        policies: list of policies as returned from config.getPolicy
              This is a list of dictionaries
        action: an action, to be searched
        max: if True, it will return the highest value, if there are
              multiple policies
              if False, it will return the lowest value, if there
              are multiple policies
        String: if True, the value is a string and not an integer

            pol10: {
            * action: "maxtoken = 10"
            * scope: "enrollment"
            * realm: "realm1"
            * user: ""
            * time: ""
           }
    '''
    ret = -1
    if String:
        ret = ""
    for _polname, pol in policies.items():
        for a in [p.strip() for p in pol['action'].split(',')]:
            log.debug("[getPolicyActionValue] Investigating %s (string=%s)"
                      % (a, unicode(String)))
            split_action = [ca.strip() for ca in a.rsplit('=', 1)]
            if len(split_action) > 1:
                (name, value) = split_action
                log.debug("[getPolicyActionValue] splitting <<%s>> <<%s>>"
                          % (name, unicode(value)))
                if name == action:
                    if String:
                        ret = value
                    else:
                        if not String:
                            value = int(value)
                        if max:
                            if value > ret:
                                ret = value
                        else:
                            if value < ret or -1 == ret:
                                ret = value

    return ret


def getAdminPolicies(action, lowerRealms=False):
    """
    This internal function returns the admin policies (of scope=admin)
    for the currently authenticated administrativ user.__builtins__

    :param action: this is the action (like enable, disable, init...)
    :param lowerRealms: if set to True, the list of realms returned will
                      be lower case.

    :return: a dictionary with the following keys:
        active (if policies are used)
        realms (the realms, in which the admin is allowed to do this action)
        resolvers    (the resolvers in which the admin is allowed to perform
                     this action)
        admin      (the name of the authenticated admin user)
    """
    active = True
    # check if we got admin policies at all
    p_at_all = getPolicy({'scope': 'admin'})
    if len(p_at_all) == 0:
        log.info("[getAdminPolicies] No policies in scope admin found."
                 " Admin authorization will be disabled.")
        active = False

    # We may change this later to other authetnication schemes
    admin_user = getUserFromRequest(request)
    log.info("[getAdminPolicies] Evaluating policies for the "
             "user: %s" % admin_user['login'])
    pol_request = {'user': admin_user['login'], 'scope': 'admin'}
    if '' != action:
        pol_request['action'] = action
    policies = getPolicy(pol_request)
    log.debug("[getAdminPolicies] Found the following "
              "policies: %r" % policies)
    # get all the realms from the policies:
    realms = []
    for _pol, val in policies.items():
        ## the val.get('realm') could return None
        pol_realm = val.get('realm', '') or ''
        pol_realm = pol_realm.split(',')
        for r in pol_realm:
            if lowerRealms:
                realms.append(r.strip(" ").lower())
            else:
                realms.append(r.strip(" "))
    log.debug("[getAdminPolicies] Found the following realms in the "
              "policies: %r" % realms)
    # get resolvers from realms
    resolvers = []
    all_realms = getRealms()
    for realm, realm_conf in all_realms.items():
        if realm in realms:
            for r in realm_conf['useridresolver']:
                resolvers.append(r.strip(" "))
    log.debug("[getAdminPolicies] Found the following resolvers in the "
              "policy: %r" % resolvers)
    return {'active': active,
            'realms': realms,
            'resolvers': resolvers,
            'admin': admin_user['login']}


def getAuthorization(scope, action):
    """
    This internal function returns the Authrorizaition within some
    the scope=system. for the currently authenticated
    administrativ user. This does not take into account the REALMS!

    arguments:
        action  - this is the action
                    scope = system
                        read
                        write

    returns:
        a dictionary with the following keys:
        active     (if policies are used)
        admin      (the name of the authenticated admin user)
        auth       (True if admin is authorized for this action)
    """
    active = True
    auth = False

    p_at_all = getPolicy({'scope': scope})
    if len(p_at_all) == 0:
        log.info("[getAuthorization] No policies in scope %s found. Checking "
                 "of scope %s be disabled." % (scope, scope))
        active = False
        auth = True

    # TODO: We may change this later to other authentication schemes
    log.debug("[getAuthorization] now getting the admin user name")

    admin_user = getUserFromRequest(request)

    log.debug("[getAuthorization] Evaluating policies for the user: %s"
              % admin_user['login'])

    policies = getPolicy({'user': admin_user['login'],
                          'scope': scope,
                          'action': action})

    log.debug("[getAuthorization] Found the following policies: "
              "%r" % policies)

    if len(policies.keys()) > 0:
        auth = True

    return {'active': active, 'auth': auth, 'admin': admin_user['login']}


def checkAdminAuthorization(policies, serial, user, fitAllRealms=False):
    """
    This function checks if the token object defined by either "serial"
    or "user" is in the corresponding realm, where the admin has access to /
    fits to the given policy.

    fitAllRealms: If set to True, then the administrator must have rights
                    in all realms of the token. e.g. for deleting tokens.

    returns:
        True: if admin is allowed
        False: if admin is not allowed
    """
    log.info("[checkAdminAuthorization] policies: %r" % policies)
    # in case there are absolutely no policies
    if not policies['active']:
        return True

    # If the policy is valid for all realms
    if '*' in policies['realms']:
        return True

    # convert realms and resolvers to lowercase
    policies['realms'] = [x.lower() for x in policies['realms']]
    policies['resolvers'] = [x.lower() for x in policies['resolvers']]

    # in case we got a serial
    if serial != "" and serial is not None:
        realms = linotp.lib.token.getTokenRealms(serial)
        log.debug("[checkAdminAuthorization] the token %r is contained "
                  "in the realms: %r" % (serial, realms))
        log.debug("[checkAdminAuthorization] the policy contains "
                  "the realms: %r" % policies['realms'])
        for r in realms:
            if fitAllRealms:
                if r not in policies['realms']:
                    return False
            else:
                if r in policies['realms']:
                    return True

        return fitAllRealms

    # in case we got a user
    if user.login != "":
        # default realm user
        if user.realm == "" and user.conf == "":
            return getDefaultRealm() in policies['realms']
        if not user.realm and not user.conf:
            return getDefaultRealm() in policies['realms']
        # we got a realm:
        if user.realm != "":
            return user.realm.lower() in policies['realms']
        if user.conf != "":
            return user.conf.lower() in policies['resolvers']

    # catch all
    return False


def getSelfserviceActions(user):
    '''
    This function returns the allowed actions in the self service portal
    for the given user
    '''
    c.user = user.login
    c.realm = user.realm
    log.debug("[getSelfserviceActions] checking actions for scope=selfservice,"
              " realm=%r" % c.realm)
    client = get_client()
    policies = get_client_policy(client, scope="selfservice", realm=c.realm,
                                 user=c.user, userObj=user)
    # Now we got a dictionary of all policies within the scope selfservice for
    # this realm. as there can be more than one policy, we concatenate all
    # their actions to a list later we might want to change this
    all_actions = []
    for pol in policies:
        # remove whitespaces and split at the comma
        action_list = policies[pol].\
            get('action', '').\
            replace(' ', '').split(',')
        all_actions.extend(action_list)
    for act in all_actions:
        act.strip()

    # return the list with all actions
    return all_actions


def checkTokenNum(user=None, realm=None):
    '''
    This internal function checks if the number of the tokens is valid...
    for a certain realm...

    Therefor it checks the policy
        "scope = enrollment", action = "tokencount = <number>"
    '''

    # If there is an empty user, we need to set it to None
    if user:
        if "" == user.login:
            user = None

    if user is None and realm is None:
        # No user and realm given, so we check all the tokens
        ret = True
        tNum = linotp.lib.token.getTokenNumResolver()
        log.debug("[checkTokenNum] Number of tokens in DB: %i" % int(tNum))
        log.debug("[checkTokenNum] result of checking the token "
                  "number: %i" % ret)
        return ret

    else:
        #allRealms = getRealms()
        Realms = []

        if user:
            log.debug("[checkTokenNum] checking token num in realm: %s,"
                      " resolver: %s" % (user.realm, user.conf))
            # 1. alle resolver aus dem Realm holen.
            # 2. fuer jeden Resolver die tNum holen.
            # 3. die Policy holen und gegen die tNum checken.
            Realms = getUserRealms(user)
        elif realm:
            Realms = [realm]

        log.debug("[checkTokenNum] checking token num in realm: %r" % Realms)

        tokenInRealms = {}
        for R in Realms:
            tIR = linotp.lib.token.getTokenInRealm(R)
            tokenInRealms[R] = tIR
            log.debug("[checkTokenNum] There are %i tokens in realm %r"
                      % (tIR, R))

        # Now we are checking the policy for every Realm! (if there are more)
        policyFound = False
        maxToken = 0
        for R in Realms:
            pol = getPolicy({'scope': 'enrollment', 'realm': R})
            polTNum = getPolicyActionValue(pol, 'tokencount')
            if polTNum > -1:
                policyFound = True

                if int(polTNum) > int(maxToken):
                    maxToken = int(polTNum)

            log.info("[checkTokenNum] Realm: %r, max: %i, tokens in realm: "
                     " %i" % (R, int(maxToken), int(tokenInRealms[R])))
            if int(maxToken) > int(tokenInRealms[R]):
                return True

        if policyFound is False:
            log.debug("[checkTokenNum] there is no scope=enrollment, "
                      "action=tokencount policy for the realms %r" % Realms)
            return True

        log.info("[checkTokenNum] No policy available for realm %r, "
                 "where enough managable tokens were defined." % Realms)

    return False


def checkTokenAssigned(user):
    '''
    This internal function checks the number of assigned tokens to a user
    Therefor it checks the policy
        "scope = enrollment", action = "maxtoken = <number>"

    returns FALSE, if the user has to many tokens assigned
    returns TRUE, if more tokens may be assigned to the user
    '''
    if user is None:
        return True
    if user.login == "":
        return True

    Realms = getUserRealms(user)

    log.debug("[checkTokenAssigned] checking the already assigned tokens for"
              " user %s, realms %s" % (user.login, Realms))

    for R in Realms:
        pol = get_client_policy(get_client(), scope='enrollment', realm=R,
                                user=user.login, userObj=user)
        log.debug("[checkTokenAssigned] found policies %s" % pol)
        if len(pol) == 0:
            log.debug("[checkTokenAssigned] there is no scope=enrollment"
                      " policy for Realm %s" % R)
            return True

        maxTokenAssigned = getPolicyActionValue(pol, "maxtoken")

        # get the tokens of the user
        tokens = linotp.lib.token.getTokens4UserOrSerial(user, "")
        # If there is a policy, where the tokennumber exceeds the tokens in
        # the corresponding realm..
        log.debug("[checkTokenAssigned] the user %r has %r tokens assigned. "
                  "The policy says a maximum of %r tokens."
                  % (user.login, len(tokens), maxTokenAssigned))
        if (int(maxTokenAssigned) > int(len(tokens)) or
                maxTokenAssigned == -1):
            return True

    return False


def get_tokenlabel(user="", realm="", serial=""):
    '''
    This internal function returns the naming of the token as defined in policy
    scope = enrollment, action = tokenname = <string>
    The string can have the following varaibles:
        <u>: user
        <r>: realm
        <s>: token serial

    This function is used by the creation of googleauthenticator url
    '''
    tokenlabel = ""
    # TODO: What happens when we got no realms?
    #pol = getPolicy( {'scope': 'enrollment', 'realm': realm} )
    pol = get_client_policy(get_client(), scope="enrollment",
                            realm=realm, user=user)
    if len(pol) == 0:
        # No policy, so we use the serial number as label
        log.debug("[get_tokenlabel] there is no scope=enrollment policy "
                  "for realm %r" % realm)
        tokenlabel = serial

    else:
        string_label = getPolicyActionValue(pol, "tokenlabel", String=True)
        if "" == string_label:
            # empty label, so we use the serial
            tokenlabel = serial
        else:
            string_label = re.sub('<u>', user, string_label)
            string_label = re.sub('<r>', realm, string_label)
            string_label = re.sub('<s>', serial, string_label)
            tokenlabel = string_label

    return tokenlabel


def get_autoassignment(user):
    '''
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    '''
    ret = False
    otplen = 6

    pol = get_client_policy(get_client(), scope='enrollment',
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        otplen = getPolicyActionValue(pol, "autoassignment")
        log.debug("[get_autoassigmnet] got the otplen = %s" % str(otplen))
        if type(otplen) == int and otplen > 0:
            ret = True

    return ret, otplen

def ignore_autoassignment_pin(user):
    '''
    This function checks the policy
        scope=enrollment, action=ignore_autoassignment_pin
    This is a boolean policy.
    The function returns true, if the password used in the autoassignment
    should not be set as token pin.
    '''
    ret = False

    pol = get_client_policy(get_client(), scope='enrollment',
                            action="ignore_autoassignment_pin",
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        ret = True

    return ret


def getRandomOTPPINLength(user):
    '''
    This internal function returns the length of the random otp pin that is
    define in policy scope = enrollment, action = otp_pin_random = 111
    '''
    Realms = getUserRealms(user)
    maxOTPPINLength = -1

    for R in Realms:
        pol = get_client_policy(get_client(), scope='enrollment', realm=R,
                                user=user.login, userObj=user)
        if len(pol) == 0:
            log.debug("[getRandomOTPPINLength] there is no scope=enrollment "
                      "policy for Realm %r" % R)
            return -1

        OTPPINLength = getPolicyActionValue(pol, "otp_pin_random")

        # If there is a policy, with a higher random pin length
        log.debug("[getRandomOTPPINLength] found policy with "
                  "otp_pin_random = %r" % OTPPINLength)

        if (int(OTPPINLength) > int(maxOTPPINLength)):
            maxOTPPINLength = OTPPINLength

    return maxOTPPINLength


def getOTPPINEncrypt(serial=None, user=None):
    '''
    This function returns, if the otppin should be stored as
    an encrpyted value
    '''
    # do store as hashed value
    encrypt_pin = 0
    Realms = []
    if serial:
        Realms = linotp.lib.token.getTokenRealms(serial)
    elif user:
        Realms = getUserRealms(user)

    log.debug("[getOTPPINEncrypt] checking realms: %r" % Realms)
    for R in Realms:
        pol = getPolicy({'scope': 'enrollment', 'realm': R})
        log.debug("[getOTPPINEncrypt] realm: %r, pol: %r" % (R, pol))
        if 1 == getPolicyActionValue(pol, 'otp_pin_encrypt'):
            encrypt_pin = 1

    return encrypt_pin


def getOTPPINPolicies(user, scope="selfservice"):
    '''
    This internal function returns the PIN policies for a realm.
    These policies can either be in the scope "selfservice" or "admin"
    The policy define when resettng an OTP PIN:
     - what should be the length of the otp pin
     - what should be the contents of the otp pin
       by the actions:
            otp_pin_minlength =
            otp_pin_maxlength =
            otp_pin_contents = [cns] (character, number, special character)
    :return: dictionary like {contents: "cns", min: 7, max: 10}
    '''
    log.debug("[getOTPPINPolicies]")
    Realms = getUserRealms(user)
    ret = {'min':-1, 'max':-1, 'contents': ""}

    log.debug("[getOTPPINPolicies] searching for OTP PIN policies in "
              "scope=%r policies." % scope)
    for R in Realms:
        pol = get_client_policy(get_client(), scope=scope, realm=R,
                                user=user.login, userObj=user)
        if len(pol) == 0:
            log.debug("[getOTPPINPolicies] there is no "
                      "scope=%r policy for Realm %r" % (scope, R))
            return ret
        n_max = getPolicyActionValue(pol, "otp_pin_maxlength")
        n_min = getPolicyActionValue(pol, "otp_pin_minlength", max=False)
        n_contents = getPolicyActionValue(pol, "otp_pin_contents", String=True)

        # find the maximum length
        log.debug("[getOTPPINPolicies] find the maximum length for OTP PINs.")
        if (int(n_max) > ret['max']):
            ret['max'] = n_max

        # find the minimum length
        log.debug("[getOTPPINPolicies] find the minimum length for OTP_PINs")
        if (not n_min == -1):
            if (ret['min'] == -1):
                ret['min'] = n_min
            elif (n_min < ret['min']):
                ret['min'] = n_min

        # find all contents
        log.debug("[getOTPPINPolicies] find the allowed contents for OTP PINs")
        for k in n_contents:
            if k not in ret['contents']:
                ret['contents'] += k

    return ret


def checkOTPPINPolicy(pin, user):
    '''
    This function checks the given PIN (OTP PIN) against the policy
    returned by the function

    getOTPPINPolicy

    It returns a dictionary:
        {'success': True/False,
          'error': errortext}

    At the moment this works for the selfservice portal
    '''
    log.debug("[checkOTPPINPolicy]")

    pol = getOTPPINPolicies(user)
    log.debug("[checkOTPPINPolicy] checking for otp_pin_minlength")
    if pol['min'] != -1:
        if pol['min'] > len(pin):
            return {'success': False,
                    'error': 'The provided PIN is too short. It should be at '
                             'least %i characters.' % pol['min']}

    log.debug("[checkOTPPINPolicy] checking for otp_pin_maxlength")
    if pol['max'] != -1:
        if pol['max'] < len(pin):
            return {'success': False,
                    'error': ('The provided PIN is too long. It should not '
                              'be longer than %i characters.' % pol['max'])}

    log.debug("[checkOTPPINPolicy] checking for otp_pin_contents")
    if pol['contents']:
        policy_c = "c" in pol['contents']
        policy_n = "n" in pol['contents']
        policy_s = "s" in pol['contents']
        policy_o = "o" in pol['contents']

        contains_c = False
        contains_n = False
        contains_s = False
        contains_other = False

        for c in pin:
            if re.search(REG_POLICY_C, c):
                contains_c = True
            elif re.search(REG_POLICY_N, c):
                contains_n = True
            elif re.search(REG_POLICY_S, c):
                contains_s = True
            else:
                contains_other = True

        if "+" == pol['contents'][0]:
            log.debug("[checkOTPPINPolicy] checking for an additive character "
                      "group: %s" % pol['contents'])
            if ((not (
                    (policy_c and contains_c) or
                    (policy_s and contains_s) or
                    (policy_o and contains_other) or
                    (policy_n and contains_n)
                    )
                 ) or (
                    (not policy_c and contains_c) or
                    (not policy_s and contains_s) or
                    (not policy_n and contains_n) or
                    (not policy_o and contains_other))):
                return {'success': False,
                        'error': "The provided PIN does not contain characters"
                                 " of the group or it does contains "
                                 "characters that are not in the group %s"
                                 % pol['contents']}
        else:
            log.debug("[checkOTPPINPolicy] normal check: %s" % pol['contents'])
            if (policy_c and not contains_c):
                return {'success': False,
                        'error': 'The provided PIN does not contain any ' +
                                 'letters. Check policy otp_pin_contents.'}
            if (policy_n and not contains_n):
                return {'success': False,
                        'error': 'The provided PIN does not contain any ' +
                                 'numbers. Check policy otp_pin_contents.'}
            if (policy_s and not contains_s):
                return {'success': False,
                        'error': 'The provided PIN does not contain any '
                                 'special characters. It should contain '
                                 'some of these characters like '
                                 '.: ,;-_<>+*~!/()=?$. Check policy '
                                 'otp_pin_contents.'}
            if (policy_o and not contains_other):
                return {'success': False,
                        'error': 'The provided PIN does not contain any '
                                 'other characters. It should contain some of'
                                 ' these characters that are not contained '
                                 'in letters, digits and the defined special '
                                 'characters. Check policy otp_pin_contents.'}
            # Additionally: in case of -cn the PIN must not contain "s" or "o"
            if '-' == pol['contents'][0]:
                if (not policy_c and contains_c):
                    return {'success': False,
                            'error': "The PIN contains letters, although it "
                                     "should not! (%s)" % pol['contents']}
                if (not policy_n and contains_n):
                    return {'success':  False,
                            'error': "The PIN contains digits, although it "
                                     "should not! (%s)" % pol['contents']}
                if (not policy_s and contains_s):
                    return {'success': False,
                            'error': "The PIN contains special characters, "
                                     "although it should not! "
                                     "(%s)" % pol['contents']}
                if (not policy_o and contains_other):
                    return {'success': False,
                            'error': "The PIN contains other characters, "
                                     "although it should not! "
                                     "(%s)" % pol['contents']}

    return {'success': True,
            'error': ''}


def getRandomPin(randomPINLength):
    newpin = ""
    log.debug("[getRandomPin] creating a random otp pin of "
              "length %r" % randomPINLength)
    chars = string.letters + string.digits
    for _i in range(randomPINLength):
        newpin = newpin + urandom.choice(chars)

    return newpin


##### Pre and Post checks
def checkPolicyPre(controller, method, param={}, authUser=None, user=None):
    '''
    This function will check for all policy definition for a certain
    controller/method It is run directly before doing the action in the
    controller. I will raise an exception, if it fails.

    :param param: This is a dictionary with the necessary parameters.

    :return: dictionary with the necessary results. These depend on
             the controller.
    '''
    ret = {}

    log.debug("[checkPolicyPre] entering controller %s" % controller)
    log.debug("[checkPolicyPre] entering method %s" % method)

    if 'admin' == controller:

        serial = getParam(param, "serial", optional)
        if user is None:
            user = getUserFromParam(param, optional)
        realm = getParam(param, "realm", optional)
        if realm is None or len(realm) == 0:
            realm = getDefaultRealm()

        if 'show' == method:
            log.debug("[checkPolicyPre] entering method %s" % method)

            # get the realms for this administrator
            policies = getAdminPolicies('')
            log.debug("[checkPolicyPre] The admin >%s< may manage the "
                      "following realms: %s" % (policies['admin'],
                                                policies['realms']))
            if policies['active'] and 0 == len(policies['realms']):
                log.error("[checkPolicyPre] The admin >%s< has no rights in "
                          "any realms!" % policies['admin'])
                raise PolicyException("You do not have any rights in any "
                                      "realm! Check the policies.")
            return {'realms': policies['realms'], 'admin': policies['admin']}

        elif 'remove' == method:
            policies = getAdminPolicies("remove")
            # FIXME: A token that belongs to multiple realms should not be
            #        deleted. Should it? If an admin has the right on this
            #        token, he might be allowed to delete it,
            #        even if the token is in other realms.
            # We could use fitAllRealms=True
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[remove] the admin >%s< is not allowed to remove "
                            "token %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to remove token %s. Check the "
                                      "policies." % serial)

        elif 'enable' == method:
            policies = getAdminPolicies("enable")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[enable] the admin >%s< is not allowed to enable "
                            "token %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to enable token %s. Check the "
                                      "policies." % serial)

            if not checkTokenNum():
                log.error("[enable] The maximum token number "
                          "is reached!")
                raise PolicyException("You may not enable any more tokens. "
                                      "Your maximum token number is "
                                      "reached!")

            # We need to check which realm the token will be in.
            realmList = linotp.lib.token.getTokenRealms(serial)
            for r in realmList:
                if not checkTokenNum(realm=r):
                    log.warning("[enable] the maximum tokens for the realm "
                                "%s is exceeded." % r)
                    raise PolicyException("You may not enable any more tokens "
                                          "in realm %s. Check the policy "
                                          "'tokencount'" % r)

        elif 'disable' == method:
            policies = getAdminPolicies("disable")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[disable] the admin >%s< is not allowed to "
                            "disable token %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to disable token %s. Check the "
                                      "policies." % serial)

        elif 'copytokenpin' == method:
            policies = getAdminPolicies("copytokenpin")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[copytokenpin] the admin >%s< is not allowed to "
                            "copy token pin of token %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to copy pin of token %s. Check "
                                      "the policies." % serial)

        elif 'copytokenuser' == method:
            policies = getAdminPolicies("copytokenuser")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[copytokenuser] the admin >%s< is not allowed to "
                            "copy token user of token %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to copy user of token %s. Check "
                                      "the policies." % serial)

        elif 'losttoken' == method:
            policies = getAdminPolicies("losttoken")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[losttoken] the admin >%s< is not allowed to run "
                            "the losttoken workflow for token %s for "
                            "user %s@%s" % (policies['admin'], serial,
                                            user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to run the losttoken workflow "
                                      "for token %s. Check the "
                                      "policies." % serial)

        elif 'getotp' == method:
            policies = getAdminPolicies("getotp")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[getotp] the admin >%s< is not allowed to run "
                            "the getotp workflow for token %s for user %s@%s"
                            % (policies['admin'], serial, user.login,
                               user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to run the getotp workflow for "
                                      "token %s. Check the policies." % serial)

        elif 'getserial' == method:
            policies = getAdminPolicies("getserial")
            # check if we want to search the token in certain realms
            if realm is not None:
                dummy_user = User('dummy', realm, None)
            else:
                dummy_user = User('', '', '')
                # We need to allow this, as no realm was passed at all.
                policies['realms'] = '*'
            if (policies['active'] and not
                    checkAdminAuthorization(policies, None, dummy_user)):
                log.warning("[getserial] the admin >%s< is not allowed to get "
                            "serials for user %s@%s"
                            % (policies['admin'], user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to get serials by OTPs in "
                                      "this realm!")

        elif 'init' == method:
            ttype = getParam(param, "type", optional)
            # possible actions are:
            # initSPASS, 	initHMAC,	initETNG, initSMS, 	initMOTP
            policies = {}
            # default: we got HMAC / ETNG
            log.debug("[checkPolicyPre] checking init action")
            if ((not ttype) or
                    (ttype and (ttype.lower() == "hmac"))):
                p1 = getAdminPolicies("initHMAC")
                p2 = getAdminPolicies("initETNG")
                policies = {'active': p1['active'],
                            'admin': p1['admin'],
                            'realms': p1['realms'] + p2['realms'],
                            'resolvers': p1['resolvers'] + p2['resolvers']}
            else:
                # See if there is a policy like initSPASS or ....
                token_type_list = linotp.lib.token.get_token_type_list()
                token_type_found = False

                for tt in token_type_list:
                    if tt.lower() == ttype.lower():
                        policies = getAdminPolicies("init%s" % tt.upper())
                        token_type_found = True
                        break

                if not token_type_found:
                    policies = {}
                    log.error("[checkPolicyPre] Unknown token type:"
                              " %s" % ttype)
                    raise Exception("The tokentype '%s' could not be "
                                    "found." % ttype)

            """
            We need to assure, that an admin does not enroll a token into a
            realm were he has no ACCESS! : -(
            The admin may not enroll a token with a serial, that is already
            assigned to a user outside of his realm
            """
            # if a user is given, we need to check the realm of this user
            log.debug("[checkPolicyPre] checking realm of the user")
            if (policies['active'] and
                (user.login != "" and not
                 checkAdminAuthorization(policies, "", user))):
                log.warning("[init] the admin >%s< is not allowed to enroll "
                            "token %s of type %s to user %s@%s"
                            % (policies['admin'], serial, ttype,
                               user.login, user.realm))

                raise PolicyException("You do not have the administrative "
                                      "right to init token %s of type %s to "
                                      "user %s@%s. Check the policies."
                                      % (serial, ttype, user.login,
                                         user.realm))

            # no right to enroll token in any realm
            log.debug("[checkPolicyPre] checking enroll token at all")
            if policies['active'] and len(policies['realms']) == 0:
                log.warning("[init] the admin >%s< is not allowed to enroll "
                            "a token at all."
                            % (policies['admin']))
                raise PolicyException("You do not have the administrative "
                                      "right to enroll tokens. Check the "
                                      "policies.")

            # the token is assigned to a user, not in the realm of the admin!
            # we only need to check this, if the token already exists. If
            # this is a new token, we do not need to check this.
            log.debug("[checkPolicyPre] checking for token existens")
            if policies['active'] and linotp.lib.token.tokenExist(serial):
                if not checkAdminAuthorization(policies, serial, ""):
                    log.warning("[init] the admin >%s< is not allowed to "
                                "enroll token %s of type %s."
                                % (policies['admin'], serial, ttype))
                    raise PolicyException("You do not have the administrative "
                                          "right to init token %s of type %s."
                                          % (serial, ttype))

            # Here we check, if the tokennum exceeded
            log.debug("[checkPolicyPre] checking number of tokens")
            if not checkTokenNum():
                log.error("[init] The maximum token number "
                          "is reached!")
                raise PolicyException("You may not enroll any more tokens. "
                                      "Your maximum token number "
                                      "is reached!")

            # if a policy restricts the tokennumber for a realm
            log.debug("[checkPolicyPre] checking tokens in realms "
                      "%s" % policies['realms'])
            for R in policies['realms']:
                if not checkTokenNum(realm=R):
                    log.warning("[init] the admin >%s< is not allowed to "
                                "enroll any more tokens for the realm %s"
                                % (policies['admin'], R))
                    raise PolicyException("The maximum allowed number of "
                                          "tokens for the realm %s was "
                                          "reached. You can not init any more "
                                          "tokens. Check the policies "
                                          "scope=enrollment, "
                                          "action=tokencount." % R)

            log.debug("[checkPolicyPre] checking tokens in realm for "
                      "user %s" % user)
            if not checkTokenNum(user=user):
                log.warning("[init] the admin >%s< is not allowed to enroll "
                            "any more tokens for the realm %s"
                            % (policies['admin'], user.realm))
                raise PolicyException("The maximum allowed number of tokens "
                                      "for the realm %s was reached. You can "
                                      "not init any more tokens. Check the "
                                      "policies scope=enrollment, "
                                      "action=tokencount." % user.realm)

            log.debug("[checkPolicyPre] checking tokens of user")
            # if a policy restricts the tokennumber for the user in a realm
            if not checkTokenAssigned(user):
                log.warning("[init] the maximum number of allowed tokens per "
                            "user is exceeded. Check the policies")
                raise PolicyException("the maximum number of allowed tokens "
                                      "per user is exceeded. Check the "
                                      "policies scope=enrollment, "
                                      "action=maxtoken")
            # ==== End of policy check 'init' ======
            ret['realms'] = policies['realms']

        elif 'unassign' == method:
            policies = getAdminPolicies("unassign")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[unassign] the admin >%s< is not allowed to "
                            "unassign token %s for user %s@%s"
                            % (policies['admin'], serial, user.login,
                               user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to unassign token %s. Check the "
                                      "policies." % serial)

        elif 'assign' == method:
            policies = getAdminPolicies("assign")

            # the token is assigned to a user, not in the realm of the admin!
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, "")):
                log.warning("[assign] the admin >%s< is not allowed to assign "
                            "token %s. " % (policies['admin'], serial))
                raise PolicyException("You do not have the administrative "
                                      "right to assign token %s. "
                                      "Check the policies." % (serial))

            # The user, the token should be assigned to,
            # is not in the admins realm
            if (policies['active'] and not
                    checkAdminAuthorization(policies, "", user)):
                log.warning("[assign] the admin >%s< is not allowed to assign "
                            "token %s for user %s@%s" % (policies['admin'],
                                                         serial, user.login,
                                                         user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to assign token %s. Check the "
                                      "policies." % serial)

            # if a policy restricts the tokennumber for the realm/user
            if not checkTokenNum(user):
                log.warning("[init] the admin >%s< is not allowed to assign "
                            "any more tokens for the realm %s(%s)"
                            % (policies['admin'], user.realm, user.conf))
                raise PolicyException("The maximum allowed number of tokens "
                                      "for the realm %s (%s) was reached. You "
                                      "can not assign any more tokens. Check "
                                      "the policies."
                                      % (user.realm, user.conf))

            # check the number of assigned tokens
            if not checkTokenAssigned(user):
                log.warning("[assign] the maximum number of allowed tokens "
                            "is exceeded. Check the policies")
                raise PolicyException("the maximum number of allowed tokens "
                                      "is exceeded. Check the policies")

        elif 'setPin' == method:

            if "userpin" in param:
                getParam(param, "userpin", required)
                # check admin authorization
                policies1 = getAdminPolicies("setSCPIN")
                policies2 = getAdminPolicies("setMOTPPIN")
                if ((policies1['active'] and not
                        (checkAdminAuthorization(policies1, serial,
                                                 User("", "", ""))))
                        or (policies2['active'] and not
                        (checkAdminAuthorization(policies2, serial,
                                                 User("", "", ""))))):
                    log.warning("[setPin] the admin >%s< is not allowed to "
                                "set MOTP PIN/SC UserPIN for token %s."
                                % (policies['admin'], serial))
                    raise PolicyException("You do not have the administrative "
                                          "right to set MOTP PIN/ SC UserPIN "
                                          "for token %s. Check the policies."
                                          % serial)

            if "sopin" in param:
                getParam(param, "sopin", required)
                # check admin authorization
                policies = getAdminPolicies("setSCPIN")
                if (policies['active'] and not
                        checkAdminAuthorization(policies, serial,
                                                User("", "", ""))):
                    log.warning("[setPin] the admin >%s< is not allowed to "
                                "setPIN for token %s."
                                % (policies['admin'], serial))
                    raise PolicyException("You do not have the administrative "
                                          "right to set Smartcard PIN for "
                                          "token %s. Check the policies."
                                          % serial)

        elif 'set' == method:

            if "pin" in param:
                policies = getAdminPolicies("setOTPPIN")
                if (policies['active'] and not
                        checkAdminAuthorization(policies, serial, user)):
                    log.warning("[set] the admin >%s< is not allowed to set "
                                "OTP PIN for token %s for user %s@%s"
                                % (policies['admin'], serial, user.login,
                                   user.realm))
                    raise PolicyException("You do not have the administrative "
                                          "right to set OTP PIN for token %s. "
                                          "Check the policies." % serial)

            if ("MaxFailCount".lower() in param or
                    "SyncWindow".lower() in param or
                    "CounterWindow".lower() in param or
                    "OtpLen".lower() in param):
                policies = getAdminPolicies("set")
                if (policies['active'] and not
                        checkAdminAuthorization(policies, serial, user)):
                    log.warning("[set] the admin >%s< is not allowed to set "
                                "token properites for %s for user %s@%s"
                                % (policies['admin'], serial,
                                   user.login, user.realm))
                    raise PolicyException("You do not have the administrative "
                                          "right to set token properties for "
                                          "%s. Check the policies." % serial)

        elif 'resync' == method:

            policies = getAdminPolicies("resync")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[resync] the admin >%s< is not allowed to resync "
                            "token %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to resync token %s. Check the "
                                      "policies." % serial)

        elif 'userlist' == method:
            policies = getAdminPolicies("userlist")
            # check if the admin may view the users in this realm
            if (policies['active'] and
                    not checkAdminAuthorization(policies, "", user)):
                log.warning("[userlist] the admin >%s< is not allowed to list"
                            " users in realm %s(%s)!"
                            % (policies['admin'], user.realm, user.conf))
                raise PolicyException("You do not have the administrative"
                                      " right to list users in realm %s(%s)."
                                      % (user.realm, user.conf))

        elif 'checkstatus' == method:
            policies = getAdminPolicies("checkstatus")
            # check if the admin may view the users in this realm
            if (policies['active'] and not
                    checkAdminAuthorization(policies, "", user)):
                log.warning("[checkstatus] the admin >%s< is not allowed to "
                            "show status of token challenges in realm %s(%s)!"
                            % (policies['admin'], user.realm, user.conf))
                raise PolicyException("You do not have the administrative "
                                      "right to show status of token "
                                      "challenges in realm "
                                      "%s(%s)." % (user.realm, user.conf))

        elif 'tokenrealm' == method:
            log.debug("[checkPolicyPre] entering method %s" % method)
            # The admin needs to have the right "manageToken" for all realms,
            # the token is currently in and all realm the Token should go into.
            policies = getAdminPolicies("manageToken")

            realms = getParam(param, "realms", required)
            # List of the new realms
            realmNewList = realms.split(',')
            # List of existing realms
            realmExistList = linotp.lib.token.getTokenRealms(serial)

            for r in realmExistList:
                if (policies['active'] and not
                    checkAdminAuthorization(policies, None,
                                            User("dummy", r, None))):
                    log.warning("[tokenrealm] the admin >%s< is not allowed "
                                "to manage tokens in realm %s"
                                % (policies['admin'], r))
                    raise PolicyException("You do not have the administrative "
                                          "right to remove tokens from realm "
                                          "%s. Check the policies." % r)

            for r in realmNewList:
                if (policies['active'] and not
                    checkAdminAuthorization(policies, None,
                                            User("dummy", r, None))):
                    log.warning("[tokenrealm] the admin >%s< is not allowed "
                                "to manage tokens in realm %s"
                                % (policies['admin'], r))
                    raise PolicyException("You do not have the administrative "
                                          "right to add tokens to realm %s. "
                                          "Check the policies." % r)

                if not checkTokenNum(realm=r):
                    log.warning("[tokenrealm] the maximum tokens for the "
                                "realm %s is exceeded." % r)
                    raise PolicyException("You may not put any more tokens in "
                                          "realm %s. Check the policy "
                                          "'tokencount'" % r)

        elif 'reset' == method:

            policies = getAdminPolicies("reset")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("[reset] the admin >%s< is not allowed to reset "
                            "token %s for user %s@%s" % (policies['admin'],
                                                         serial, user.login,
                                                         user.realm))
                raise PolicyException("You do not have the administrative "
                                      "right to reset token %s. Check the "
                                      "policies." % serial)

        elif 'import' == method:
            policies = getAdminPolicies("import")
            # no right to import token in any realm
            log.debug("[checkPolicyPre] checking import token at all")
            if policies['active'] and len(policies['realms']) == 0:
                log.warning("[import] the admin >%s< is not allowed "
                            "to import a token at all."
                            % (policies['admin']))

                raise PolicyException("You do not have the administrative "
                                      "right to import tokens. Check the "
                                      "policies.")
            ret['realms'] = policies['realms']

        elif 'loadtokens' == method:
            tokenrealm = param.get('tokenrealm')
            policies = getAdminPolicies("import")
            if policies['active'] and tokenrealm not in policies['realms']:
                log.warning("[loadtokens] the admin >%s< is not allowed to "
                            "import token files to realm %s: %s"
                            % (policies['admin'], tokenrealm, policies))
                raise PolicyException("You do not have the administrative "
                                      "right to import token files to realm %s"
                                      ". Check the policies." % tokenrealm)

            if not checkTokenNum(realm=tokenrealm):
                log.warning("[loadtokens] the maximum tokens for the realm "
                            "%s is exceeded." % tokenrealm)
                raise PolicyException("The maximum number of allowed tokens "
                                      "in realm %s is exceeded. Check policy "
                                      "tokencount!" % tokenrealm)

        else:
            # unknown method
            log.error("[checkPolicyPre] an unknown method "
                      "<<%s>> was passed." % method)
            raise PolicyException("Failed to run checkPolicyPre. "
                                  "Unknown method: %s" % method)

    elif 'gettoken' == controller:
        if 'max_count' == method[0: len('max_count')]:
            ret = 0
            serial = getParam(param, "serial", optional)
            ttype = linotp.lib.token.getTokenType(serial).lower()
            trealms = linotp.lib.token.getTokenRealms(serial)
            pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")
            admin_user = getUserFromRequest(request)
            if pol_action == "":
                raise PolicyException("There is no policy gettoken/"
                                      "max_count definable for the "
                                      "tokentype %r" % ttype)

            policies = {}
            for realm in trealms:
                pol = getPolicy({'scope': 'gettoken', 'realm': realm,
                                 'user': admin_user['login']})
                log.error("[checkPolicyPre][gettoken] got a policy: "
                          " %r" % policies)

                policies.update(pol)

            value = getPolicyActionValue(policies, pol_action)
            log.debug("[checkPolicyPre][gettoken] got all "
                      "policies: %r: %r" % (policies, value))
            ret = value

    elif 'audit' == controller:
        if 'view' == method:
            auth = getAuthorization("audit", "view")
            if auth['active'] and not auth['auth']:
                log.warning("[audit view] the admin >%r< is not allowed to "
                            "view the audit trail" % auth['admin'])

                ret = ("You do not have the administrative right to view the "
                       "audit trail. You are missing a policy "
                       "scope=audit, action=view")
                raise PolicyException(ret)
        else:
            log.error("[checkPolicyPre] an unknown method was passed in :"
                      " %s" % method)
            raise PolicyException("Failed to run checkPolicyPre. Unknown "
                                  "method: %s" % method)

    elif 'manage' == controller:
        log.debug("[checkPolicyPre] entering controller %s" % controller)

    elif 'selfservice' == controller:
        log.debug("[checkPolicyPre] entering controller %s" % controller)

        if 'max_count' == method[0: len('max_count')]:
            ret = 0
            serial = getParam(param, "serial", optional)
            ttype = linotp.lib.token.getTokenType(serial).lower()
            urealm = authUser.realm
            pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")
            if pol_action == "":
                raise PolicyException("There is no policy selfservice/"
                                      "max_count definable for the token "
                                      "type %s." % ttype)

            policies = get_client_policy(get_client(), scope='selfservice',
                                         realm=urealm, user=authUser.login,
                                         userObj=authUser)
            log.debug("[checkPolicyPre][seflservice][max_count] got a policy: "
                      " %r" % policies)
            if policies == {}:
                raise PolicyException("There is no policy selfservice/"
                                      "max_count defined for the tokentype "
                                      "%s in realm %s." % (ttype, urealm))

            value = getPolicyActionValue(policies, pol_action)
            log.debug("[checkPolicyPre][seflservice][max_count] "
                      "got all policies: %r: %r" % (policies, value))
            ret = value

        elif 'usersetpin' == method:

            if not 'setOTPPIN' in getSelfserviceActions(authUser):
                log.warning("[usersetpin] user %s@%s is not allowed to call "
                            "this function!" % (authUser.login,
                                                authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'userreset' == method:

            if not 'reset' in getSelfserviceActions(authUser):
                log.warning("[userreset] user %s@%s is not allowed to call "
                            "this function!" % (authUser.login,
                                                authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'userresync' == method:

            if not 'resync' in getSelfserviceActions(authUser):
                log.warning("[userresync] user %s@%s is not allowed to call "
                            "this function!" % (authUser.login,
                                                authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'usersetmpin' == method:

            if not 'setMOTPPIN' in getSelfserviceActions(authUser):
                log.warning("[usersetmpin] user %r@%r is not allowed to call "
                            "this function!" % (authUser.login,
                                                authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'useractivateocratoken' == method:
            user_selfservice_actions = getSelfserviceActions(authUser)
            typ = param.get('type').lower()
            if (typ == 'ocra'
                    and 'activateQR' not in user_selfservice_actions):
                log.warning("[activateQR] user %r@%r is not allowed to call "
                            "this function!" % (authUser.login,
                                                authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'useractivateocra2token' == method:
            user_selfservice_actions = getSelfserviceActions(authUser)
            typ = param.get('type').lower()
            if (typ == 'ocra2'
                    and 'activateQR2' not in user_selfservice_actions):
                log.warning("[activateQR2 user %r@%r is not allowed to call "
                            "this function!" % (authUser.login,
                                                authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'userassign' == method:

            if not 'assign' in getSelfserviceActions(authUser):
                log.warning("[userassign] user %r@%r is not allowed to call "
                            "this function!" % (authUser.login,
                                                authUser.realm))
                raise PolicyException('The policy settings do not allow '
                                      'you to issue this request!')

            # Here we check, if the tokennum exceeds the tokens
            if not checkTokenNum():
                log.error("[init] The maximum token number "
                          "is reached!")
                raise PolicyException("You may not enroll any more tokens. "
                                      "Your maximum token number "
                                      "is reached!")

            if not checkTokenAssigned(authUser):
                log.warning("[assign] the maximum number of allowed tokens is"
                            " exceeded. Check the policies")
                raise PolicyException("The maximum number of allowed tokens "
                                      "is exceeded. Check the policies")

        elif 'usergetserialbyotp' == method:

            if not 'getserial' in getSelfserviceActions(authUser):
                log.warning("[usergetserialbyotp] user %s@%s is not allowed to"
                            " call this function!" % (authUser.login,
                                                      authUser.realm))
                raise PolicyException('The policy settings do not allow you to'
                                      ' request a serial by OTP!')

        elif 'userdisable' == method:

            if not 'disable' in getSelfserviceActions(authUser):
                log.warning("[userdisable] user %r@%r is not allowed to call "
                            "this function!"
                            % (authUser.login, authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'userenable' == method:

            if not 'enable' in getSelfserviceActions(authUser):
                log.warning("[userenable] user %s@%s is not allowed to call "
                            "this function!"
                            % (authUser.login, authUser.realm))
                raise PolicyException('The policy settings do not allow you to'
                                      ' issue this request!')

        elif 'userunassign' == method:

            if not 'unassign' in getSelfserviceActions(authUser):
                log.warning("[userunassign] user %r@%r is not allowed to call "
                            "this function!"
                            % (authUser.login, authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'userdelete' == method:

            if not 'delete' in getSelfserviceActions(authUser):
                log.warning("[userdelete] user %r@%r is not allowed to call "
                            "this function!"
                            % (authUser.login, authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'userwebprovision' == method:
            user_selfservice_actions = getSelfserviceActions(authUser)
            typ = param.get('type').lower()
            if ((typ == 'oathtoken'
                    and 'webprovisionOATH' not in user_selfservice_actions)
                or (typ == 'googleauthenticator_time'and
                    'webprovisionGOOGLEtime' not in user_selfservice_actions)
                or (typ == 'googleauthenticator'
                    and 'webprovisionGOOGLE' not in user_selfservice_actions)):
                log.warning("[userwebprovision] user %r@%r is not allowed to "
                            "call this function!" % (authUser.login,
                                                     authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

            # Here we check, if the tokennum exceeds the allowed tokens
            if not checkTokenNum():
                log.error("[userwebprovision] The maximum token "
                          "number is reached!")
                raise PolicyException("You may not enroll any more tokens. "
                                      "Your maximum token number "
                                      "is reached!")

            if not checkTokenAssigned(authUser):
                log.warning("[userwebprovision] the maximum number of allowed "
                            "tokens is exceeded. Check the policies")
                raise PolicyException("The maximum number of allowed tokens "
                                      "is exceeded. Check the policies")

        elif 'userhistory' == method:
            if not 'history' in getSelfserviceActions(authUser):
                log.warning("[userhistory] user %r@%r is not allowed to call "
                            "this function!"
                            % (authUser.login, authUser.realm))
                raise PolicyException('The policy settings do not allow you '
                                      'to issue this request!')

        elif 'userinit' == method:

            allowed_actions = getSelfserviceActions(authUser)
            typ = param['type'].lower()
            meth = 'enroll' + typ.upper()

            if meth not in allowed_actions:
                log.warning("[userinit] user %r@%r is not allowed to "
                            "enroll %s!" % (authUser.login,
                                            authUser.realm, typ))
                raise PolicyException('The policy settings do not allow '
                                      'you to issue this request!')

            # Here we check, if the tokennum exceeds the allowed tokens
            if not checkTokenNum():
                log.error("[userinit] The maximum token "
                          "number is reached!")
                raise PolicyException("You may not enroll any more tokens. "
                                      "Your maximum token number "
                                      "is reached!")

            if not checkTokenAssigned(authUser):
                log.warning("[userinit] the maximum number of allowed tokens "
                            "is exceeded. Check the policies")
                raise PolicyException("The maximum number of allowed tokens "
                                      "is exceeded. Check the policies")

        else:
            log.error("[checkPolicyPre] Unknown method in "
                      "selfservice: %s" % method)
            raise PolicyException("Unknown method in selfservice: %s" % method)

    elif 'system' == controller:
        actions = {
            'setDefault': 'write',
            'setConfig': 'write',
            'delConfig': 'write',
            'getConfig': 'read',
            'getRealms': 'read',
            'delResolver': 'write',
            'getResolver': 'read',
            'setResolver': 'write',
            'getResolvers': 'read',
            'setDefaultRealm': 'write',
            'getDefaultRealm': 'read',
            'setRealm': 'write',
            'delRealm': 'write',
            'setPolicy': 'write',
            'importPolicy': 'write',
            'policies_flexi': 'read',
            'getPolicy': 'read',
            'getPolicyDef': 'read',
            'checkPolicy': "read",
            'delPolicy': 'write',
            'setSupport': 'write',
            }

        if not method in actions:
            log.error("[checkPolicyPre] an unknown method was passed "
                      "in system: %s" % method)
            raise PolicyException("Failed to run checkPolicyPre. "
                                  "Unknown method: %s" % method)

        auth = getAuthorization('system', actions[method])

        if auth['active'] and not auth['auth']:
            log.warning("[checkPolicyPre] admin >%s< is not authorited to %s."
                        " Missing policy scope=system, action=%s"
                        % (auth['admin'], method, actions[method]))

            raise PolicyException("Policy check failed. You are not allowed "
                                  "to %s system config." % actions[method])

    elif controller == 'ocra':

        method_map = {'request': 'request', 'status': 'checkstatus',
                      'activationcode': 'getActivationCode',
                      'calcOTP': 'calculateOtp'}

        admin_user = getUserFromRequest(request)
        policies = getPolicy({'user': admin_user.get('login'), 'scope': 'ocra',
                              'action': method, 'client': get_client()})

        if len(policies) == 0:
            log.warning("[request] the admin >%r< is not allowed to do an ocra"
                        "/%r" % (admin_user.get('login'),
                                 method_map.get(method)))
            raise PolicyException("You do not have the administrative right to"
                                  " do an ocra/%s" % method_map.get(method))

    else:
        # unknown controller
        log.error("[checkPolicyPre] an unknown controller "
                  "<<%r>> was passed." % controller)
        raise PolicyException("Failed to run getPolicyPre. Unknown "
                              "controller: %s" % controller)

    return ret


def checkPolicyPost(controller, method, param=None, user=None):
    '''
    This function will check policies after a successful action in a
    controller. E.g. this can be setting a random PIN after successfully
    enrolling a token.

    :param controller: the controller context
    :param method: the calling action
    :param param: This is a dictionary with the necessary parameters.
    :param auth_user: This is the authenticated user. For the selfservice this
                      will be the user in the selfservice portal, for admin or
                      manage it will be the administrator


    :return: It returns a dictionary with the necessary results. These depend
             on the controller.
    '''
    ret = {}

    if param is None:
        param = {}

    if 'admin' == controller:
        log.debug("[checkPolicyPost] entering controller %s" % controller)
        log.debug("[checkPolicyPost] entering method %s" % method)
        log.debug("[checkPolicyPost] using params %s" % param)
        serial = getParam(param, "serial", optional)
        if user is None:
            user = getUserFromParam(param, optional)

        if 'init' == method:
            # check if we are supposed to genereate a random OTP PIN
            randomPINLength = getRandomOTPPINLength(user)
            if randomPINLength > 0:
                newpin = getRandomPin(randomPINLength)
                log.debug("[init] setting random pin for token with serial "
                          "%s and user: %s" % (serial, user))
                linotp.lib.token.setPin(newpin, None, serial)
                log.debug("[init] pin set")
                # TODO: This random PIN could be processed and
                # printed in a PIN letter
        elif 'getserial' == method:
            # check if the serial/token, that was returned is in
            # the realms of the admin!
            policies = getAdminPolicies("getserial")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial,
                                            User('', '', ''))):
                log.warning("[getserial] the admin >%s< is not allowed to get "
                            "serial of token %s" % (policies['admin'], serial))
                raise PolicyException("You do not have the administrative "
                                      "right to get serials from this realm!")
        else:
            # unknown method
            log.error("[checkPolicyPost] an unknown method <<%s>>"
                      " was passed." % method)
            raise PolicyException("Failed to run getPolicyPost. "
                                  "Unknown method: %s" % method)

    elif 'system' == controller:
        log.debug("[cehckPolicyPost] entering controller %s" % controller)

        if 'getRealms' == method:
            systemReadRights = False
            res = param['realms']
            auth = getAuthorization('system', 'read')
            if auth['auth']:
                systemReadRights = True

            if not systemReadRights:
                # If the admin is not allowed to see all realms,
                # (policy scope=system, action=read)
                # the realms, where he has no administrative rights need,
                # to be stripped.
                pol = getAdminPolicies('')
                if pol['active']:
                    log.debug("[getRealms] the admin has policies "
                              "in these realms: %r" % pol['realms'])

                    lowerRealms = uniquify(pol['realms'])
                    for realm, _v in res.items():
                        if ((not realm.lower() in lowerRealms)
                                and (not '*' in lowerRealms)):
                            log.debug("[getRealms] the admin has no policy in "
                                      "realm %r. Deleting "
                                      "it: %r" % (realm, res))
                            del res[realm]
                else:
                    log.error("[checkPolicyPost] system: : getRealms: "
                              "The admin >%s< is not allowed to read system "
                              "config and has not realm administrative rights!"
                              % auth['admin'])
                    raise PolicyException("You do not have system config read "
                                          "rights and not realm admin "
                                          "policies.")
            ret['realms'] = res

    else:
        # unknown controller
        log.error("[checkPolicyPost] an unknown constroller <<%s>> "
                  "was passed." % controller)
        raise PolicyException("Failed to run getPolicyPost. "
                              "Unknown controller: %s" % controller)
    return ret


###############################################################################
#
# Client Policies
#
def get_client_policy(client, scope=None, action=None, realm=None, user=None,
                      find_resolver=True, userObj=None):
    '''
    This function returns the dictionary of policies for the given client.

    1. First it searches for all policies matching (scope, action, realm) and
    checks, whether the given client is contained in the policy field client.
    If no policy for the given client is found it takes the policy without
    a client

    2. Then it strips down the returnable policies to those, that only contain
    the username - UNLESS - none of the above policies contains a username

    3. then we try to find resolvers in the username (OPTIONAL)
    '''
    Policies = {}

    param = {}

    if scope:
        param["scope"] = scope
    if action:
        param["action"] = action
    if realm:
        param["realm"] = realm

    log.debug("[get_client_policy] with params %r, "
              "client %r and user %r" % (param, client, user))
    Pols = getPolicy(param)
    log.debug("[get_client_policy] got policies %s " % Pols)

    def get_array(policy, attribute="client", marks=False):
        ## This function returns the parameter "client" or
        ## "user" in a policy as an array
        attrs = policy.get(attribute, "")
        if attrs == "None" or attrs is None:
            attrs = ""
        log.debug("[get_array] splitting <%s>" % attrs)
        attrs_array = []
        if marks:
            attrs_array = [co.strip()[:-1] for co in attrs.split(',')
                           if len(co.strip()) and co.strip()[-1] == ":"]
        else:
            attrs_array = [co.strip()
                           for co in attrs.split(',')
                           if len(co.strip()) and co.strip()[-1] != ":"]
        # if for some reason the first element is empty, delete it.
        if len(attrs_array) and attrs_array[0] == "":
            del attrs_array[0]
        return attrs_array

    ## 1. Find a policy with this client
    for pol, policy in Pols.items():
        log.debug("[get_client_policy] checking policy %s" % pol)
        clients_array = get_array(policy, attribute="client")
        log.debug("[get_client_policy] the policy %s has these clients: %s. "
                  "checking against %s." % (pol, clients_array, client))
        client_found = False
        client_excluded = False
        for cl in clients_array:
            try:
                if cl[0] in ['-', '!']:
                    if IPAddress(client) in IPNetwork(cl[1:]):
                        log.debug("[get_client_policy] the client %s is "
                                  "excluded by %s in policy "
                                  "%s" % (client, cl, pol))
                        client_excluded = True
                if IPAddress(client) in IPNetwork(cl):
                    client_found = True
            except Exception as e:
                log.warning("[get_client_policy] authorization policy %s with "
                            "invalid client: %r" % (pol, e))

        if client_found and not client_excluded:
            Policies[pol] = policy

    # No policy for this client was found, but maybe
    # there is one without clients
    if len(Policies) == 0:
        log.debug("[get_client_policy] looking for policy without any client")
        for pol, policy in Pols.items():
            if len(get_array(policy, attribute="client")) == 0:
                Policies[pol] = policy

    ## 2. Within those policies select the policy with the user.
    ##     if there is a policy with this very user, return only
    ##     these policies, otherwise return all policies
    if user:
        user_policy_found = False
        own_policies = {}
        default_policies = {}
        for polname, pol in Policies.items():
            users = get_array(pol, attribute="user")
            log.debug("[get_client_policy] search user %s in users %s "
                      "of policy %s" % (user, users, polname))
            if user in users or '*' in users:
                log.debug("[get_client_policy] adding %s to "
                          "own_policies" % polname)
                own_policies[polname] = pol
            elif len(users) == 0:
                log.debug("[get_client_policy] adding %s to "
                          "default_policies" % polname)

                default_policies[polname] = pol
            else:
                log.debug("[get_client_policy] policy %s contains only users "
                          "(%s) other than %s" % (polname, users, user))

        if len(own_policies):
            Policies = own_policies
            user_policy_found = True
        else:
            Policies = default_policies

        ##3. If no user specific policy was found, we now take a look,
        ##   if we find a policy with the matching resolver.
        if not user_policy_found and realm and find_resolver:
            ## get the resolver of the user in the realm and search for this
            ## resolver in the policies
            if userObj is not None:
                resolvers = getResolversOfUser(userObj)
            else:
                resolvers = getResolversOfUser(User(login=user, realm=realm))
            own_policies = {}
            default_policies = {}
            for polname, pol in Policies.items():
                resolvs = get_array(pol, attribute="user", marks=True)
                for r in resolvers:
                    # trim the resolver useridresolver.LDAPIdResolver.\
                    # IdResolver.local to its name
                    r = r[r.rfind('.') + 1:]
                    if r in resolvs:
                        log.debug("[get_client_policy] adding %s to "
                                  "own_policies" % polname)
                        own_policies[polname] = pol
                    elif len(resolvs) == 0:
                        log.debug("[get_client_policy] adding %s (no "
                                  "resolvers) to default_policies" % polname)
                        default_policies[polname] = pol
                    else:
                        log.debug("[get_client_policy] policy %s contains "
                                  "only resolvers (%s) other than %s" %
                                  (polname, resolvs, r))
            if len(own_policies):
                Policies = own_policies
            else:
                Policies = default_policies

    return Policies


def set_realm(login, realm, exception=False):
    '''
    this function reads the policy scope: authorization, client: x.y.z,
    action: setrealm=new_realm and overwrites the existing realm of the user
    with the new_realm.
    This can be used, if the client is not able to pass a realm and the users
    are not be located in the default realm.

    returns:
        realm    - name of the new realm taken from the policy
    '''
    client = get_client()
    log.debug("[set_realm] got the client %s" % client)
    log.debug("[set_realm] users %s original realm is %s" % (login, realm))
    policies = get_client_policy(client, scope="authorization",
                                 action="setrealm", realm=realm,
                                 user=login, find_resolver=False)

    if len(policies):
        realm = getPolicyActionValue(policies, "setrealm", String=True)

    log.debug("[set_realm] users %s new realm is %s" % (login, realm))
    return realm


def check_user_authorization(login, realm, exception=False):
    '''
    check if the given user/realm is in the given policy.
    The realm may contain the wildcard '*', then the policy holds for
    all realms. If no username or '*' is given, the policy holds for all users.

    attributes:
        login    - loginname of the user
        realm    - realm of the user
        exception    - wether it should return True/False or raise an Exception
    '''
    res = False

    # if there is absolutely NO policy in scope authorization,
    # we return immediately
    if len(getPolicy({"scope": "authorization", "action": "authorize"})) == 0:
        log.debug("[check_user_authorization] absolutely "
                  "no authorization policy.")
        return True

    client = get_client()
    log.debug("[check_user_authorization] got the client %s" % client)
    policies = get_client_policy(client, scope="authorization",
                                 action="authorize", realm=realm, user=login)
    log.debug("[check_user_authorization] got policies %s for "
              "user %s" % (policies, login))

    if len(policies):
        res = True

    if res is False and exception:
        raise AuthorizeException("Authorization on client %s failed "
                                 "for %s@%s." % (client, login, realm))

    return res


###############################################################################
#
#  Authentication stuff
#
def get_auth_passthru(user):
    '''
    returns True, if the user in this realm should be authenticated against
    the UserIdResolver in case the user has no tokens assigned.
    '''
    ret = False
    client = get_client()
    pol = get_client_policy(client, scope="authentication",
                            action="passthru", realm=user.realm,
                            user=user.login, userObj=user)
    if len(pol) > 0:
        ret = True
    return ret


def get_auth_passOnNoToken(user):
    '''
    returns True, if the user in this realm should be always authenticated
    in case the user has no tokens assigned.
    '''
    ret = False
    client = get_client()
    pol = get_client_policy(client, scope="authentication",
                            action="passOnNoToken", realm=user.realm,
                            user=user.login, userObj=user)
    if len(pol) > 0:
        ret = True
    return ret


def get_auth_AutoSMSPolicy(realms=None):
    '''
    Returns true, if the autosms policy is set in one of the realms

    return:
        True or False

    input:
        list of realms
    '''
    log.debug("[get_auth_AutoSMSPolicy] checking realms %r " % realms)

    client = get_client()
    user = getUserFromParam(request.params, optional)
    login = user.login
    if realms is None:
        realm = user.realm or getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = get_client_policy(client, scope="authentication",
                                action="autosms", realm=realm,
                                user=login, userObj=user)

        if len(pol) > 0:
            log.debug("[get_auth_AutoSMSPolicy] found policy in "
                      "realm %s" % realm)
            ret = True

    return ret


def get_auth_challenge_response(user, ttype):
    """
    returns True, if the user in this realm with this token type should be
    authenticated via Challenge Response

    :param user: the user object
    :param ttype: the type of the token

    :return: bool
    """

    ret = False
    p_user = None
    p_realm = None

    if user is not None:
        p_user = user.login
        p_realm = user.realm

    client = get_client()

    pol = get_client_policy(client, scope="authentication",
                            action="challenge_response",
                            realm=p_realm,
                            user=p_user, userObj=user)
    log.debug("[get_auth_challenge_response] got policy %r for user "
              "%r@%r from client %r" % (pol, p_user, p_realm, client))

    Token_Types = getPolicyActionValue(pol, "challenge_response", String=True)
    token_types = [t.lower() for t in Token_Types.split()]

    if ttype.lower() in token_types or '*' in token_types:
        log.debug("[get_auth_challenge_response] found matching "
                  "token type %s" % ttype)
        ret = True

    return ret


def get_auth_PinPolicy(realm=None, user=None):
    '''
    Returns the PIN policy, that defines, how the OTP PIN is to be verified
    within the given realm

    return:
        0    - verify against fixed OTP PIN
        1    - verify the password component against the
                      UserResolver (LPAP Password etc.)
        2    - verify no OTP PIN at all! Only OTP value!

    The policy is defined via
        scope : authentication
        realm : ....
        action: otppin=0/1/2
        client: IP
        user  : some user
    '''
    log.debug("[get_auth_PinPolicy]")

    client = get_client()
    if user is None:
        user = getUserFromParam(request.params, optional)
    login = user.login
    if realm is None:
        realm = user.realm or getDefaultRealm()

    pol = get_client_policy(client, scope="authentication", action="otppin",
                            realm=realm, user=login, userObj=user)

    log.debug("[get_auth_PinPolicy] got policy %s"
              "  for user %s@%s  client %s" % (pol, login, realm, client))
    pin_check = getPolicyActionValue(pol, "otppin", max=False)

    if pin_check in [1, 2]:
        return pin_check

    return 0


def get_qrtan_url(realm):
    '''
    Returns the URL for the half automatic mode for the QR TAN token
    for the given realm

    :return: url string

    '''
    log.debug("[get_qrtan_url] getting url for realm %s" % realm)

    pol = getPolicy({"scope": "authentication", "realm": realm})

    url = getPolicyActionValue(pol, "qrtanurl", String=True)
    log.debug("[get_qrtan_url] using url %s for realm %s" % (url, realm))
    return url


###############################################################################
#
#  Authorization
#
def check_auth_tokentype(serial, exception=False, user=None):
    '''
    Checks if the token type of the given serial matches the tokentype policy

    :return: True/False - returns true or false or raises an exception
                          if exception=True
    '''
    log.debug("[check_auth_tokentype]")
    if serial is None:
        # if no serial is given, we return True right away
        log.debug("[check_auth_tokentype] We have got no serial. "
                  "Obviously doing passthru.")
        return True

    client = get_client()
    if user is None:
        user = getUserFromParam(request.params, optional)
    login = user.login
    realm = user.realm or getDefaultRealm()
    tokentypes = []
    tokentype = ""
    res = False

    pol = get_client_policy(client, scope="authorization", action="tokentype",
                            realm=realm, user=login, userObj=user)

    log.debug("[check_auth_tokentype] got policy %s"
              "  for user %s@%s  client %s" % (pol, login, realm, client))

    t_type = getPolicyActionValue(pol, "tokentype", max=False, String=True)
    if len(t_type) > 0:
        tokentypes = [t.strip() for t in t_type.lower().split(" ")]

    log.debug("[check_auth_tokentype] found these "
              "tokentypes: <%s>" % tokentypes)

    toks = linotp.lib.token.getTokens4UserOrSerial(None, serial)
    if len(toks) > 1:
        log.error("[check_auth_tokentype] multiple tokens with serial %s found"
                  " - cannot get OTP!" % serial)
        raise PolicyException("multiple tokens found - "
                              "cannot determine tokentype!")
    elif len(toks) == 1:
        log.debug("[check_auth_tokentype] found one token with "
                  "serial %s" % serial)
        tokentype = toks[0].getType().lower()
        log.debug("[check_auth_tokentype] got the type %s for "
                  "token %s" % (tokentype, serial))

        if (tokentype in tokentypes or '*' in tokentypes
                or len(tokentypes) == 0):
            res = True
    elif len(toks) == 0:
        ## TODO if the user does not exis or does have no token
        ## ---- WHAT DO WE DO? ---
        ## At the moment we pass through: This is the old behaviour...
        res = True

    if res is False and exception:
        c.audit["action_detail"] = \
            "failed due to authorization/tokentype policy"
        raise AuthorizeException("Authorization for token %s with type %s "
                                 "failed on client %s" % (serial, tokentype,
                                                          client))

    return res


def check_auth_serial(serial, exception=False, user=None):
    '''
    Checks if the token with the serial number matches the serial
    authorize policy scope=authoriztaion, action=serial

    :param serial: The serial number of the token to check
    :type serial: string
    :param exception: If "True" an exception is raised instead of
                      returning False
    :type exception: boolean
    :param user: User to narrow down the policy
    :type user: User object

    :return: result
    :rtype: boolean
    '''
    log.debug("[check_auth_serial]")
    if serial is None:
        # if no serial is given, we return True right away
        log.debug("[check_auth_serial] We have got no serial. "
                  "Obviously doing passthru.")
        return True

    client = get_client()
    if user is None:
        user = getUserFromParam(request.params, optional)
    login = user.login
    realm = user.realm or getDefaultRealm()
    res = False

    pol = get_client_policy(client, scope="authorization", action="serial",
                            realm=realm, user=login, userObj=user)
    if len(pol) == 0:
        # No policy found, so we skip the rest
        log.debug("[check_auth_serial] No policy scope=authorize,"
                  "action=serial for user %r, realm %r, client %r"
                  % (login, realm, client))
        return True

    log.debug("[check_auth_serial] got policy %s"
              "  for user %s@%s  client %s" % (pol, login, realm, client))

    # extract the value from the policy
    serial_regexp = getPolicyActionValue(pol, "serial", max=False, String=True)
    log.debug("[check_auth_serial] found this regexp /%r/ for the serial %r"
              % (serial_regexp, serial))

    if re.search(serial_regexp, serial):
        log.debug("[check_auth_serial] regexp matches.")
        res = True

    if res is False and exception:
        c.audit["action_detail"] = "failed due to authorization/serial policy"
        raise AuthorizeException("Authorization for token %s failed on "
                                 "client %s" % (serial, client))

    return res


def is_auth_return(success=True, user=None):
    '''
    returns True if the policy
        scope = authorization
        action = detail_on_success/detail_on_fail
        is set.

    :param success: Defines if we should check of the policy
                    detaul_on_success (True) or detail_on_fail (False)
    :type success: bool
    '''
    ret = False

    client = get_client()
    if user is None:
        user = getUserFromParam(request.params, optional)
    login = user.login
    realm = user.realm or getDefaultRealm()
    if success:
        pol = get_client_policy(client, scope="authorization",
                                action="detail_on_success", realm=realm,
                                user=login, userObj=user)
    else:
        pol = get_client_policy(client, scope="authorization",
                                action="detail_on_fail", realm=realm,
                                user=login, userObj=user)

    if len(pol):
        ret = True

    return ret


### helper ################################
def get_pin_policies(user):
    '''
    lookup for the pin policies - the list of policies
    is preserved for repeated lookups

    : raises: exception, if more then one pin policies are matching

    :param user: the policies which are applicable to the user
    :return: list of otppin id's
    '''
    pin_policies = []

    pin_policies.append(get_auth_PinPolicy(user=user))
    pin_policies = list(set(pin_policies))

    if len(pin_policies) > 1:
        msg = ("conflicting authentication polices. "
               "Check scope=authentication. policies: %r" % pin_policies)

        log.error("[__checkToken] %r" % msg)
        #self.context.audit['action_detail'] = msg
        raise Exception('multiple pin policies found')
        ## former return -2

    return pin_policies

#eof###########################################################################
