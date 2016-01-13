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
""" policy processing """

import logging
# for loading XML file
import string
import re

from copy import deepcopy

from netaddr import IPAddress
from netaddr import IPNetwork


import linotp.lib.token
from linotp.lib.user import getUserRealms
from linotp.lib.user import User
from linotp.lib.user import getResolversOfUser

from linotp.lib.error import LinotpError
from linotp.lib.error import ParameterError

# for generating random passwords
from linotp.lib.crypt import urandom
from linotp.lib.util import uniquify


log = logging.getLogger(__name__)

# This dictionary maps the token_types to actions in the scope gettoken,
# that define the maximum allowed otp valies in case of getotp/getmultiotp
MAP_TYPE_GETOTP_ACTION = {"dpw": "max_count_dpw",
                          "hmac": "max_count_hotp",
                          "totp": "max_count_totp",
                          }


class PolicyException(LinotpError):
    def __init__(self, description="unspecified error!", id=410):
        LinotpError.__init__(self, description=description, id=id)


class AuthorizeException(LinotpError):
    def __init__(self, description="unspecified error!", id=510):
        LinotpError.__init__(self, description=description, id=id)


def _get_pin_values(config):
    REG_POLICY_C = config.get("linotpPolicy.pin_c", "[a-zA-Z]")
    REG_POLICY_N = config.get("linotpPolicy.pin_n", "[0-9]")
    REG_POLICY_S = config.get("linotpPolicy.pin_s",
                              "[.:,;-_<>+*!/()=?$§%&#~\^]")

    return REG_POLICY_C, REG_POLICY_N, REG_POLICY_S


def _getAuthenticatedUser(context=None):
    """
    replace the 'getUserFromRequest
    """
    auth_user = context['AuthUser']
    return auth_user


def _getLinotpConfig(config=None):

    lConfig = config
    return lConfig


def _getPolicies(context=None):

    lPolicies = deepcopy(context['Policies'])
    return lPolicies


def _get_client(context):
    client = context['Client']
    return client


def _getUserFromParam(context):
    user = context['RequestUser']
    return user


def _getDefaultRealm(context):
    return context['defaultRealm']


def _getRealms(context):
    return context['Realms']


def _getUserRealms(user, context):
    return getUserRealms(user, allRealms=context['Realms'],
                  defaultRealm=context['defaultRealm'])


def getPolicies(config=None):
    # First we load ALL policies from the Config
    lConfig = _getLinotpConfig(config)

    Policies = {}
    for entry in lConfig:
        if entry.startswith("linotp.Policy."):
            # log.debug("[getPolicy] entry: %s" % entry )
            policy = entry.split(".", 4)
            if len(policy) == 4:
                name = policy[2]
                key = policy[3]
                value = lConfig.get(entry)

                # prepare the value to be at least an empty string
                if value is None and key in ('user', 'client', 'realm'):
                    value = ''
                if key == "realm":
                    value = value.lower()

                if name in Policies:
                    Policies[name][key] = value
                else:
                    Policies[name] = {key: value}

    return Policies


def getPolicy(param, display_inactive=False, context=None):
    '''
    Function to retrieve the list of policies.

    attributes:

    - name:   (optional) will only return the policy with the name
    - user:   (optional) will only return the policies for this user
    - realm:  (optional) will only return the policies of this realm
    - scope:  (optional) will only return the policies within this scope
    - action: (optional) will only return the policies with this action
         The action can also be something like "otppin" and will
         return policies containing "otppin = 2"

    :return: a dictionary with the policies. The name of the policy being
             the key
    '''
    # log.debug("[getPolicy] params %s" % str(param))
    Policies = {}

    # First we load ALL policies from the Config
    lPolicies = _getPolicies(context)

    if param.get('name', None):
        # If a named policy was requested, we add
        # the policy if the name does match case insensitiv
        p_name = param['name'].lower()
        for pol_name in lPolicies:
            if pol_name.lower() == p_name:
                Policies[pol_name] = lPolicies[pol_name]
    else:
        Policies = lPolicies

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
        # log.debug("[getPolicy] cleanup acccording to realm %s"
        #          % param["realm"])
        for polname, policy in Policies.items():
            delete_it = True
            # log.debug("[getPolicy] evaluating policy %s: %s"
            #          % (polname, str(policy)))
            if policy.get("realm") is not None:
                pol_realms = [p.strip()
                              for p in policy['realm'].lower().split(',')]
                # log.debug("[getPolicy] realms in policy %s: %s"
                #          % (polname, str(pol_realms) ))
                for r in pol_realms:
                    # log.debug("[getPolicy] Realm: %s" % r)
                    if r == param['realm'].lower() or r == '*':
                        # log.debug( "[getPolicy] Setting delete_it to false.
                        # Se we are using policy: %s" % str(polname))
                        delete_it = False
            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('scope', None) is not None:
        # log.debug("[getPolicy] cleanup acccording to scope %s"
        #          % param["scope"])
        for polname, policy in Policies.items():
            if policy['scope'].lower() != param['scope'].lower():
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('action', None) is not None:
        # log.debug("[getPolicy] cleanup acccording to action %s"
        #          % param["action"])
        param_action = param['action'].strip().lower()
        for polname, policy in Policies.items():
            delete_it = True
            # log.debug("[getPolicy] evaluating policy %s: %s"
            #          % (polname, str(policy)))
            if policy.get("action") is not None:
                pol_actions = [p.strip()
                               for p in policy.get('action', "").
                               lower().split(',')]
                # log.debug("[getPolicy] actions in policy %s: %s "
                #          % (polname, str(pol_actions) ))
                for policy_action in pol_actions:
                    if policy_action == '*' or policy_action == param_action:
                        # If any action (*) or the exact action we are looking
                        # for matches, then keep the policy
                        # e.g. otppin=1 matches when we search for 'otppin=1'
                        delete_it = False
                    elif policy_action.split('=')[0].strip() == param_action:
                        # If the first part of the action matches then keep the
                        # policy
                        # e.g. otppin=1 matches when we search for 'otppin'
                        delete_it = False
                    else:
                        # No match, delete_it = True
                        pass
            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('user', None) is not None:
        # log.debug("cleanup acccording to user %s" % param["user"])
        for polname, policy in Policies.items():
            if policy.get('user'):
                pol_users = [p.strip()
                             for p in policy.get('user').lower().split(',')]
                # log.debug("[getPolicy] users in policy %s: %s"
                #          % (polname, str(pol_users) ))
            else:
                log.error("Empty userlist in policy '%s' not supported!"
                          % polname)
                raise Exception("Empty userlist in policy '%s' not supported!"
                                % polname)

            delete_it = True
            for u in pol_users:
                # log.debug("[getPolicy] User: %s" % u )
                if u == param['user'].lower() or u == '*':
                    # log.debug("[getPolicy] setting delete_it to false."
                    #          "We are using policy %s" % str(polname))
                    delete_it = False
                    break

            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    log.debug("getting policies %s for params %s" % (Policies, param))
    return Policies


def parse_action_value(action_value):
    """
    parsing the policy action value by an regular expression
    """
    params = {}
    key_vals = action_value.split(',')
    for ke_val in key_vals:
        res = ke_val.split('=', 1)

        # if we have a boolean value, there is only one arg
        if len(res) == 1:
            key = res[0].strip()
            if key:
                params[key] = True
        else:
            key = res[0].strip()
            val = res[1].strip()
            params[key] = val

    return params


def getPolicyActionValue(policies, action, max=True, is_string=False, subkey=None):
    """
    This function retrieves the int value of an action from a list of policies
    input

    :param policies: list of policies as returned from config.getPolicy
        This is a list of dictionaries
    :param action: an action, to be searched
    :param max: if True, it will return the highest value, if there are
        multiple policies if False, it will return the lowest value, if there
        are multiple policies
    :param is_string: if True, the value is a string and not an integer

    Example policy::

        pol10: {
            action: "maxtoken = 10",
            scope: "enrollment",
            realm: "realm1",
            user: "",
            time: ""
           }
    """
    results = {}

    for _polname, pol in policies.items():
        action_key = action
        action_value = pol['action'].strip()
        # the regex requires a trailing ','
        if action_value[-1:] != ',':
            action_value = action_value + ','
        values = parse_action_value(action_value)

        if subkey:
            action_key = "%s.%s" % (action, subkey)

        ret = values.get(action_key, None)

        # the parameter String=False enforces a conversion into an int
        if type(ret) in [str, unicode] and is_string == False:
            try:
                ret = int(ret)
            except ValueError:
                pass

        if ret:
            results[_polname] = ret

    if len(results) > 1:
        for val in results.values():
            if val != results.values()[0]:
                log. error("multiple different action value matches exists %r"
                           % results)

    ret = -1
    if is_string:
        ret = ""

    if results:
        ret = results.values()[0]

    return ret

def getAdminPolicies(action, lowerRealms=False, context=None):
    """
    This internal function returns the admin policies (of scope=admin)
    for the currently authenticated administrativ user.__builtins__

    :param action: this is the action (like enable, disable, init...)
    :param lowerRealms: if set to True, the list of realms returned will
                      be lower case.

    :return: a dictionary with the following keys:

        - active (if policies are used)
        - realms (the realms, in which the admin is allowed to do this action)
        - resolvers (the resolvers in which the admin is allowed to perform
          this action)
        - admin (the name of the authenticated admin user)
    """
    active = True
    # check if we got admin policies at all
    p_at_all = getPolicy({'scope': 'admin'}, context=context)
    if len(p_at_all) == 0:
        log.info("No policies in scope admin found."
                 " Admin authorization will be disabled.")
        active = False

    # We may change this later to other authetnication schemes
    admin_user = _getAuthenticatedUser(context)
    log.info("Evaluating policies for the "
             "user: %s" % admin_user['login'])
    pol_request = {'user': admin_user['login'], 'scope': 'admin'}
    if '' != action:
        pol_request['action'] = action
    policies = getPolicy(pol_request, context=context)
    log.debug("Found the following "
              "policies: %r" % policies)
    # get all the realms from the policies:
    realms = []
    for _pol, val in policies.items():
        # # the val.get('realm') could return None
        pol_realm = val.get('realm', '') or ''
        pol_realm = pol_realm.split(',')
        for r in pol_realm:
            if lowerRealms:
                realms.append(r.strip(" ").lower())
            else:
                realms.append(r.strip(" "))
    log.debug("Found the following realms in the "
              "policies: %r" % realms)
    # get resolvers from realms
    resolvers = []
    all_realms = _getRealms(context=context)
    for realm, realm_conf in all_realms.items():
        if realm in realms:
            for r in realm_conf['useridresolver']:
                resolvers.append(r.strip(" "))
    log.debug("Found the following resolvers in the policy: %r" % resolvers)
    return {'active': active,
            'realms': realms,
            'resolvers': resolvers,
            'admin': admin_user['login']}


def _getAuthorization(scope, action, context=None):
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

    p_at_all = getPolicy({'scope': scope}, context=context)
    if len(p_at_all) == 0:
        log.info("No policies in scope %s found. Checking "
                 "of scope %s be disabled." % (scope, scope))
        active = False
        auth = True

    # TODO: We may change this later to other authentication schemes
    log.debug("[getAuthorization] now getting the admin user name")

    admin_user = _getAuthenticatedUser(context)

    log.debug("Evaluating policies for the user: %s" % admin_user['login'])

    policies = getPolicy({'user': admin_user['login'],
                          'scope': scope,
                          'action': action},
                         context=context)

    log.debug("Found the following policies: %r" % policies)

    if len(policies.keys()) > 0:
        auth = True

    return {'active': active, 'auth': auth, 'admin': admin_user['login']}


def checkAdminAuthorization(policies, serial, user, fitAllRealms=False,
                            context=None):
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
    log.info("policies: %r" % policies)
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
        log.debug("the token %r is contained in the realms: %r"
                  % (serial, realms))
        log.debug("the policy contains the realms: %r" % policies['realms'])
        for r in realms:
            if fitAllRealms:
                if r not in policies['realms']:
                    return False
            else:
                if r in policies['realms']:
                    return True

        return fitAllRealms

    # in case of the admin policies - no user name is verified:
    # the username could be empty (not dummy) which prevents an
    # unnecessar resolver lookup
    if user.realm:
        # default realm user
        if user.realm == "" and user.conf == "":
            return _getDefaultRealm(context=context) in policies['realms']
        if not user.realm and not user.conf:
            return _getDefaultRealm(context=context) in policies['realms']
        # we got a realm:
        if user.realm != "":
            return user.realm.lower() in policies['realms']
        if user.conf != "":
            return user.conf.lower() in policies['resolvers']

    # catch all
    return False


def getSelfserviceActions(user, context=None):
    '''
    This function returns the allowed actions in the self service portal
    for the given user
    '''
    login = user.login
    realm = user.realm
    client = _get_client(context)

    log.debug("checking actions for scope=selfservice,"
              " realm=%r" % realm)

    policies = get_client_policy(client, scope="selfservice", realm=realm,
                                 user=login, userObj=user, context=context)

    # Now we got a dictionary of all policies within the scope selfservice for
    # this realm. as there can be more than one policy, we concatenate all
    # their actions to a list later we might want to change this

    all_actions = []
    for pol in policies:
        # remove whitespaces and split at the comma
        actions = policies[pol].get('action', '')
        action_list = actions.split(',')
        all_actions.extend(action_list)

    acts = set()
    for act in all_actions:
        acts.add(act.strip())

    # return the list with all actions
    return list(acts)


def _checkTokenNum(user=None, realm=None, context=None):
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
        log.debug("Number of tokens in DB: %i" % int(tNum))
        log.debug("result of checking the token "
                  "number: %i" % ret)
        return ret

    else:
        # allRealms = getRealms()
        Realms = []

        if user:
            log.debug("checking token num in realm: %s, resolver: %s" %
                      (user.realm, user.conf))
            # 1. alle resolver aus dem Realm holen.
            # 2. fuer jeden Resolver die tNum holen.
            # 3. die Policy holen und gegen die tNum checken.
            Realms = _getUserRealms(user, context=context)
        elif realm:
            Realms = [realm]

        log.debug("checking token num in realm: %r" % Realms)

        tokenInRealms = {}
        for R in Realms:
            tIR = linotp.lib.token.getTokenInRealm(R)
            tokenInRealms[R] = tIR
            log.debug("There are %i tokens in realm %r" % (tIR, R))

        # Now we are checking the policy for every Realm! (if there are more)
        policyFound = False
        maxToken = 0
        for R in Realms:
            pol = getPolicy({'scope': 'enrollment', 'realm': R},
                            context=context)
            polTNum = getPolicyActionValue(pol, 'tokencount')
            if polTNum > -1:
                policyFound = True

                if int(polTNum) > int(maxToken):
                    maxToken = int(polTNum)

            log.info("Realm: %r, max: %i, tokens in realm: %i"
                     % (R, int(maxToken), int(tokenInRealms[R])))
            if int(maxToken) > int(tokenInRealms[R]):
                return True

        if policyFound is False:
            log.debug("there is no scope=enrollment, action=tokencount policy "
                      "for the realms %r" % Realms)
            return True

        log.info("No policy available for realm %r, where enough managable "
                 "tokens were defined." % Realms)

    return False


def _checkTokenAssigned(user, context=None):
    '''
    This internal function checks the number of assigned tokens to a user
    Therefore it checks the policy::

        "scope = enrollment", action = "maxtoken = <number>"

    :return: False, if the user has to many tokens assigned True, if more
        tokens may be assigned to the user
    :rtype: bool
    '''
    if user is None:
        return True
    if user.login == "":
        return True

    client = _get_client(context)
    Realms = _getUserRealms(user, context=context)

    log.debug("checking the already assigned tokens for user %s, realms %s"
              % (user.login, Realms))

    for R in Realms:
        pol = get_client_policy(client, scope='enrollment', realm=R,
                                user=user.login, userObj=user,
                                context=context)
        log.debug("found policies %s" % pol)
        if len(pol) == 0:
            log.debug("there is no scope=enrollment policy for Realm %s" % R)
            return True

        maxTokenAssigned = getPolicyActionValue(pol, "maxtoken")

        # get the tokens of the user
        tokens = linotp.lib.token.getTokens4UserOrSerial(user, "",
                                                         context=context)
        # If there is a policy, where the tokennumber exceeds the tokens in
        # the corresponding realm..
        log.debug("the user %r has %r tokens assigned. The policy says a "
                  "maximum of %r tokens." % (user.login, len(tokens),
                                             maxTokenAssigned))
        if (int(maxTokenAssigned) > int(len(tokens)) or
                maxTokenAssigned == -1):
            return True

    return False


def get_tokenissuer(user="", realm="", serial="", context=None):
    '''
    This internal function returns the issuer of the token as defined in policy
    scope = enrollment, action = tokenissuer = <string>
    The string can have the following variables:
        <u>: user
        <r>: realm
        <s>: token serial

    This function is used to create 'otpauth' tokens
    '''
    tokenissuer = ""
    client = _get_client(context)
    pol = get_client_policy(client, scope="enrollment",
                            realm=realm, user=user,
                            context=context)
    if len(pol) != 0:
        string_issuer = getPolicyActionValue(pol, "tokenissuer", is_string=True)
        if string_issuer:
            string_issuer = re.sub('<u>', user, string_issuer)
            string_issuer = re.sub('<r>', realm, string_issuer)
            string_issuer = re.sub('<s>', serial, string_issuer)
            tokenissuer = string_issuer

    log.debug("[get_tokenissuer] providing tokenissuer = %s" % str(tokenissuer))
    return tokenissuer


def get_tokenlabel(user="", realm="", serial="", context=None):
    '''
    This internal function returns the naming of the token as defined in policy
    scope = enrollment, action = tokenname = <string>
    The string can have the following variables:

    - <u>: user
    - <r>: realm
    - <s>: token serial

    This function is used by the creation of googleauthenticator url
    '''
    tokenlabel = ""
    client = _get_client(context)

    # TODO: What happens when we got no realms?
    # pol = getPolicy( {'scope': 'enrollment', 'realm': realm} )
    pol = get_client_policy(client, scope="enrollment",
                            realm=realm, user=user,
                            context=context)
    if len(pol) == 0:
        # No policy, so we use the serial number as label
        log.debug("there is no scope=enrollment policy for realm %r" % realm)
        tokenlabel = serial

    else:
        string_label = getPolicyActionValue(pol, "tokenlabel", is_string=True)
        if "" == string_label:
            # empty label, so we use the serial
            tokenlabel = serial
        else:
            string_label = re.sub('<u>', user, string_label)
            string_label = re.sub('<r>', realm, string_label)
            string_label = re.sub('<s>', serial, string_label)
            tokenlabel = string_label

    return tokenlabel


def get_autoassignment(user, context=None):
    '''
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    '''
    ret = False
    client = _get_client(context)

    pol = get_client_policy(client, scope='enrollment',
                            realm=user.realm, user=user.login, userObj=user,
                            context=context)

    if len(pol) > 0:
        val = getPolicyActionValue(pol, "autoassignment")
        # with  LinOTP 2.7 the autassign policy is treated as boolean
        if val == True:
            ret = True
        # for backwar compatibility, we accept any values
        # other than -1, which indicates an error
        elif val != -1:
            ret = True

    log.debug("got the autoassignement %r", ret)
    return ret


def get_auto_enrollment(user, context=None):
    '''
    this function checks the policy scope=enrollment, action=autoenrollment
    This policy policy returns the tokentyp: sms or email
    The function returns true, if autoenrollment is defined.
    '''
    ret = False
    token_typ = ''

    client = _get_client(context)

    pol = get_client_policy(client, scope='enrollment',
                            realm=user.realm, user=user.login, userObj=user,
                            context=context)

    if len(pol) > 0:
        t_typ = getPolicyActionValue(pol, "autoenrollment", is_string=True)
        log.debug("got the token type = %s" % t_typ)
        if type(t_typ) in [str, unicode] and t_typ.lower() in ['sms', 'email']:
            ret = True
            token_typ = t_typ.lower()

    return ret, token_typ


def autoassignment_forward(user, context=None):
    '''
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    '''
    ret = False
    client = _get_client(context)

    pol = get_client_policy(client, scope='enrollment',
                            action="autoassignment_forward",
                            realm=user.realm, user=user.login, userObj=user,
                            context=context)

    if len(pol) > 0:
        ret = True

    return ret


def ignore_autoassignment_pin(user, context=None):
    '''
    This function checks the policy
        scope=enrollment, action=ignore_autoassignment_pin
    This is a boolean policy.
    The function returns true, if the password used in the autoassignment
    should not be set as token pin.
    '''
    ret = False
    client = _get_client(context)

    pol = get_client_policy(client, scope='enrollment',
                            action="ignore_autoassignment_pin",
                            realm=user.realm, user=user.login, userObj=user,
                            context=context)

    if len(pol) > 0:
        ret = True

    return ret


def _getRandomOTPPINLength(user, context=None):
    '''
    This internal function returns the length of the random otp pin that is
    define in policy scope = enrollment, action = otp_pin_random = 111
    '''
    Realms = _getUserRealms(user, context=context)
    maxOTPPINLength = -1
    client = _get_client(context)

    for R in Realms:
        pol = get_client_policy(client,
                                scope='enrollment', action='otp_pin_random',
                                realm=R, user=user.login, userObj=user,
                                context=context)
        if len(pol) == 0:
            log.debug("there is no scope=enrollment policy for Realm %r" % R)
            return -1

        OTPPINLength = getPolicyActionValue(pol, "otp_pin_random")

        # If there is a policy, with a higher random pin length
        log.debug("found policy with otp_pin_random = %r" % OTPPINLength)

        if (int(OTPPINLength) > int(maxOTPPINLength)):
            maxOTPPINLength = OTPPINLength

    return maxOTPPINLength


def getOTPPINEncrypt(serial=None, user=None, context=None):
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
        Realms = _getUserRealms(user, context=context)

    log.debug("checking realms: %r" % Realms)
    for R in Realms:
        pol = getPolicy({'scope': 'enrollment', 'realm': R},
                        context=context)
        log.debug("realm: %r, pol: %r" % (R, pol))
        if 1 == getPolicyActionValue(pol, 'otp_pin_encrypt'):
            encrypt_pin = 1

    return encrypt_pin


def _getOTPPINPolicies(user, scope="selfservice", context=None):
    '''
    This internal function returns the PIN policies for a realm.
    These policies can either be in the scope "selfservice" or "admin"
    The policy define when resettng an OTP PIN:

    - what should be the length of the otp pin
    - what should be the contents of the otp pin by the actions:

      - otp_pin_minlength =
      - otp_pin_maxlength =
      - otp_pin_contents = [cns] (character, number, special character)

    :return: dictionary like {contents: "cns", min: 7, max: 10}
    '''
    log.debug("[getOTPPINPolicies]")
    client = _get_client(context)

    Realms = _getUserRealms(user, context=context)
    ret = {'min':-1, 'max':-1, 'contents': ""}

    log.debug("searching for OTP PIN policies in scope=%r policies." % scope)
    for R in Realms:
        pol = get_client_policy(client, scope=scope, realm=R,
                                user=user.login, userObj=user,
                                context=context)
        if len(pol) == 0:
            log.debug("there is no scope=%r policy for Realm %r" % (scope, R))
            return ret
        n_max = getPolicyActionValue(pol, "otp_pin_maxlength")
        n_min = getPolicyActionValue(pol, "otp_pin_minlength", max=False)
        n_contents = getPolicyActionValue(pol, "otp_pin_contents", is_string=True)

        # find the maximum length
        log.debug("find the maximum length for OTP PINs.")
        if (int(n_max) > ret['max']):
            ret['max'] = n_max

        # find the minimum length
        log.debug("find the minimum length for OTP_PINs")
        if (not n_min == -1):
            if (ret['min'] == -1):
                ret['min'] = n_min
            elif (n_min < ret['min']):
                ret['min'] = n_min

        # find all contents
        log.debug("find the allowed contents for OTP PINs")
        for k in n_contents:
            if k not in ret['contents']:
                ret['contents'] += k

    return ret


def checkOTPPINPolicy(pin, user, context=None):
    '''
    This function checks the given PIN (OTP PIN) against the policy
    returned by the function

    getOTPPINPolicy

    It returns a dictionary:
        {'success': True/False,
          'error': errortext}

    At the moment this works for the selfservice portal
    '''
    _ = context['translate']

    log.debug("[checkOTPPINPolicy]")

    pol = _getOTPPINPolicies(user, context=context)
    log.debug("checking for otp_pin_minlength")
    if pol['min'] != -1:
        if pol['min'] > len(pin):
            return {'success': False,
                    'error': _('The provided PIN is too short. It should be '
                               'at least %i characters.') % pol['min']}

    log.debug("checking for otp_pin_maxlength")
    if pol['max'] != -1:
        if pol['max'] < len(pin):
            return {'success': False,
                    'error': (_('The provided PIN is too long. It should not '
                              'be longer than %i characters.') % pol['max'])}

    log.debug("checking for otp_pin_contents")
    if pol['contents']:
        policy_c = "c" in pol['contents']
        policy_n = "n" in pol['contents']
        policy_s = "s" in pol['contents']
        policy_o = "o" in pol['contents']

        contains_c = False
        contains_n = False
        contains_s = False
        contains_other = False

        REG_POLICY_C, REG_POLICY_N, REG_POLICY_S = \
                                    _get_pin_values(context['Config'])

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
            log.debug("checking for an additive character "
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
                        'error': _("The provided PIN does not contain "
                                   "characters of the group or it does "
                                   "contains characters that are not in the "
                                   "group %s")
                                 % pol['contents']}
        else:
            log.debug("[checkOTPPINPolicy] normal check: %s" % pol['contents'])
            if (policy_c and not contains_c):
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                 'letters. Check policy otp_pin_contents.')}
            if (policy_n and not contains_n):
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                 'numbers. Check policy otp_pin_contents.')}
            if (policy_s and not contains_s):
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                 'special characters. It should contain '
                                 'some of these characters like '
                                 '.: ,;-_<>+*~!/()=?$. Check policy '
                                 'otp_pin_contents.')}
            if (policy_o and not contains_other):
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                 'other characters. It should contain some of'
                                 ' these characters that are not contained '
                                 'in letters, digits and the defined special '
                                 'characters. Check policy otp_pin_contents.')}
            # Additionally: in case of -cn the PIN must not contain "s" or "o"
            if '-' == pol['contents'][0]:
                if (not policy_c and contains_c):
                    return {'success': False,
                            'error': _("The PIN contains letters, although it "
                                     "should not! (%s)") % pol['contents']}
                if (not policy_n and contains_n):
                    return {'success':  False,
                            'error': _("The PIN contains digits, although it "
                                     "should not! (%s)") % pol['contents']}
                if (not policy_s and contains_s):
                    return {'success': False,
                            'error': _("The PIN contains special characters, "
                                     "although it should not! "
                                     "(%s)") % pol['contents']}
                if (not policy_o and contains_other):
                    return {'success': False,
                            'error': _("The PIN contains other characters, "
                                     "although it should not! "
                                     "(%s)") % pol['contents']}

    return {'success': True,
            'error': ''}


def _getRandomPin(randomPINLength, context=None):
    newpin = ""
    log.debug("creating a random otp pin of length %r" % randomPINLength)
    chars = string.letters + string.digits
    for _i in range(randomPINLength):
        newpin = newpin + urandom.choice(chars)

    return newpin


def _checkAdminPolicyPre(method, param={}, authUser=None, user=None,
                        context=None):
    ret = {}
    _ = context['translate']

    serial = param.get("serial")
    if user is None:
        user = _getUserFromParam(context=context)

    realm = param.get("realm")
    if realm is None or len(realm) == 0:
        realm = _getDefaultRealm(context=context)

    if 'show' == method:
        log.debug("entering method %s" % method)

        # get the realms for this administrator
        policies = getAdminPolicies('', context=context)
        log.debug("The admin >%s< may manage the following realms: %s" %
                  (policies['admin'], policies['realms']))
        if policies['active'] and 0 == len(policies['realms']):
            log.error("The admin >%s< has no rights in any realms!" %
                      policies['admin'])
            raise PolicyException(_("You do not have any rights in any "
                                  "realm! Check the policies."))
        return {'realms': policies['realms'], 'admin': policies['admin']}

    elif 'remove' == method:
        policies = getAdminPolicies("remove", context=context)
        # FIXME: A token that belongs to multiple realms should not be
        #        deleted. Should it? If an admin has the right on this
        #        token, he might be allowed to delete it,
        #        even if the token is in other realms.
        # We could use fitAllRealms=True
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to remove token %s for "
                        "user %s@%s" % (policies['admin'], serial, user.login,
                                        user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to remove token %s. Check the "
                                  "policies.") % serial)

    elif 'enable' == method:
        policies = getAdminPolicies("enable", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("[enable] the admin >%s< is not allowed to enable "
                        "token %s for user %s@%s"
                        % (policies['admin'], serial,
                           user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to enable token %s. Check the "
                                  "policies.") % serial)

        if not _checkTokenNum(context=context):
            log.error("The maximum token number is reached!")
            raise PolicyException(_("You may not enable any more tokens. "
                                  "Your maximum token number is "
                                  "reached!"))

        # We need to check which realm the token will be in.
        realmList = linotp.lib.token.getTokenRealms(serial)
        for r in realmList:
            if not _checkTokenNum(realm=r, context=context):
                log.warning("the maximum tokens for the realm %s is "
                            "exceeded." % r)
                raise PolicyException(_("You may not enable any more tokens "
                                      "in realm %s. Check the policy "
                                      "'tokencount'") % r)

    elif 'disable' == method:
        policies = getAdminPolicies("disable", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to disable token %s for"
                        " user %s@%s" % (policies['admin'], serial, user.login,
                                         user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to disable token %s. Check the "
                                  "policies.") % serial)

    elif 'copytokenpin' == method:
        policies = getAdminPolicies("copytokenpin", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to copy token pin of "
                        "token %s for user %s@%s" % (policies['admin'], serial,
                           user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to copy PIN of token %s. Check "
                                  "the policies.") % serial)

    elif 'copytokenuser' == method:
        policies = getAdminPolicies("copytokenuser", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to copy token user of "
                        "token %s for user %s@%s" % (policies['admin'], serial,
                           user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to copy user of token %s. Check "
                                  "the policies.") % serial)

    elif 'losttoken' == method:
        policies = getAdminPolicies("losttoken", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to run "
                        "the losttoken workflow for token %s for "
                        "user %s@%s" % (policies['admin'], serial,
                                        user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to run the losttoken workflow "
                                  "for token %s. Check the "
                                  "policies.") % serial)

    elif 'getotp' == method:
        policies = getAdminPolicies("getotp", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to run the getotp "
                        "workflow for token %s for user %s@%s"
                        % (policies['admin'], serial, user.login,
                           user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to run the getotp workflow for "
                                  "token %s. Check the policies.") % serial)

    elif 'getserial' == method:
        policies = getAdminPolicies("getserial", context=context)
        # check if we want to search the token in certain realms
        if realm is not None:
            dummy_user = User('dummy', realm, None)
        else:
            dummy_user = User('', '', '')
            # We need to allow this, as no realm was passed at all.
            policies['realms'] = '*'
        if (policies['active'] and not
                checkAdminAuthorization(policies, None, dummy_user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to get serials for user"
                        " %s@%s" % (policies['admin'], user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to get serials by OTPs in "
                                  "this realm!"))

    elif 'init' == method:
        ttype = param.get("type")
        # possible actions are:
        # initSPASS,     initHMAC,    initETNG, initSMS,     initMOTP
        policies = {}
        # default: we got HMAC / ETNG
        log.debug("checking init action")
        if ((not ttype) or
                (ttype and (ttype.lower() == "hmac"))):
            p1 = getAdminPolicies("initHMAC", context=context)
            p2 = getAdminPolicies("initETNG", context=context)
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
                    policies = getAdminPolicies("init%s" % tt.upper(),
                                                context=context)
                    token_type_found = True
                    break

            if not token_type_found:
                policies = {}
                log.error("Unknown token type: %s" % ttype)
                raise Exception(_("The tokentype '%s' could not be "
                                "found.") % ttype)

        # We need to assure, that an admin does not enroll a token into a
        # realm were he has no ACCESS! : -(
        # The admin may not enroll a token with a serial, that is already
        # assigned to a user outside of his realm

        # if a user is given, we need to check the realm of this user
        log.debug("checking realm of the user")
        if (policies['active'] and
            (user.login != "" and not
             checkAdminAuthorization(policies, "", user, context=context))):
            log.warning("the admin >%s< is not allowed to enroll token %s of "
                        "type %s to user %s@%s" % (policies['admin'], serial,
                                                ttype, user.login, user.realm))

            raise PolicyException(_("You do not have the administrative "
                                  "right to init token %s of type %s to "
                                  "user %s@%s. Check the policies.")
                                  % (serial, ttype, user.login,
                                     user.realm))

        # no right to enroll token in any realm
        log.debug("checking enroll token at all")
        if policies['active'] and len(policies['realms']) == 0:
            log.warning("the admin >%s< is not allowed to enroll "
                        "a token at all." % (policies['admin']))
            raise PolicyException(_("You do not have the administrative "
                                  "right to enroll tokens. Check the "
                                  "policies."))

        # the token is assigned to a user, not in the realm of the admin!
        # we only need to check this, if the token already exists. If
        # this is a new token, we do not need to check this.
        log.debug("checking for token existens")
        if policies['active'] and linotp.lib.token.tokenExist(serial,
                                                              context=context):
            if not checkAdminAuthorization(policies, serial, "",
                                           context=context):
                log.warning("the admin >%s< is not allowed to enroll token %s "
                            "of type %s." % (policies['admin'], serial, ttype))
                raise PolicyException(_("You do not have the administrative "
                                      "right to init token %s of type %s.")
                                      % (serial, ttype))

        # Here we check, if the tokennum exceeded
        log.debug("checking number of tokens")
        if not _checkTokenNum(context=context):
            log.error("The maximum token number is reached!")
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        # if a policy restricts the tokennumber for a realm
        log.debug("checking tokens in realms %s" % policies['realms'])
        for R in policies['realms']:
            if not _checkTokenNum(realm=R, context=context):
                log.warning("the admin >%s< is not allowed to enroll any more "
                            "tokens for the realm %s" % (policies['admin'], R))
                raise PolicyException(_("The maximum allowed number of "
                                      "tokens for the realm %s was "
                                      "reached. You can not init any more "
                                      "tokens. Check the policies "
                                      "scope=enrollment, "
                                      "action=tokencount.") % R)

        log.debug("checking tokens in realm for user %s" % user)
        if not _checkTokenNum(user=user, context=context):
            log.warning("the admin >%s< is not allowed to enroll any more "
                        "tokens for the realm %s" %
                        (policies['admin'], user.realm))
            raise PolicyException(_("The maximum allowed number of tokens "
                                  "for the realm %s was reached. You can "
                                  "not init any more tokens. Check the "
                                  "policies scope=enrollment, "
                                  "action=tokencount.") % user.realm)

        log.debug("checking tokens of user")
        # if a policy restricts the tokennumber for the user in a realm
        if not _checkTokenAssigned(user, context=context):
            log.warning("the maximum number of allowed tokens per user is "
                        "exceeded. Check the policies")
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "per user is exceeded. Check the "
                                  "policies scope=enrollment, "
                                  "action=maxtoken"))
        # ==== End of policy check 'init' ======
        ret['realms'] = policies['realms']

    elif 'unassign' == method:
        policies = getAdminPolicies("unassign", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to unassign token %s "
                        "for user %s@%s" % (policies['admin'], serial,
                                            user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to unassign token %s. Check the "
                                  "policies.") % serial)

    elif 'assign' == method:
        policies = getAdminPolicies("assign", context=context)

        # the token is assigned to a user, not in the realm of the admin!
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, "",
                                        context=context)):
            log.warning("the admin >%s< is not allowed to assign token %s. "
                        % (policies['admin'], serial))
            raise PolicyException(_("You do not have the administrative "
                                  "right to assign token %s. "
                                  "Check the policies.") % (serial))

        # The user, the token should be assigned to,
        # is not in the admins realm
        if (policies['active'] and not
                checkAdminAuthorization(policies, "", user, context=context)):
            log.warning("the admin >%s< is not allowed to assign "
                        "token %s for user %s@%s" % (policies['admin'],
                                                     serial, user.login,
                                                     user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to assign token %s. Check the "
                                  "policies.") % serial)

        # if a policy restricts the tokennumber for the realm/user
        if not _checkTokenNum(user, context=context):
            log.warning("the admin >%s< is not allowed to assign "
                        "any more tokens for the realm %s(%s)"
                        % (policies['admin'], user.realm, user.conf))
            raise PolicyException(_("The maximum allowed number of tokens "
                                  "for the realm %s (%s) was reached. You "
                                  "can not assign any more tokens. Check "
                                  "the policies.")
                                  % (user.realm, user.conf))

        # check the number of assigned tokens
        if not _checkTokenAssigned(user, context=context):
            log.warning("the maximum number of allowed tokens is exceeded. "
                        "Check the policies")
            raise PolicyException(_("the maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    elif 'setPin' == method:

        if "userpin" in param:
            if "userpin" not in param:
                raise ParameterError(_("Missing parameter: %r")
                                     % "userpin", id=905)

            # check admin authorization
            policies1 = getAdminPolicies("setSCPIN", context=context)
            policies2 = getAdminPolicies("setMOTPPIN", context=context)
            if ((policies1['active'] and not
                    (checkAdminAuthorization(policies1, serial,
                                             User("", "", ""),
                                             context=context)))
                    or (policies2['active'] and not
                    (checkAdminAuthorization(policies2, serial,
                                             User("", "", ""),
                                             context=context)))):
                log.warning("the admin >%s< is not allowed to set MOTP PIN/SC "
                            "UserPIN for token %s." %
                            (policies1['admin'], serial))
                raise PolicyException(_("You do not have the administrative "
                                      "right to set MOTP PIN/ SC UserPIN "
                                      "for token %s. Check the policies.")
                                      % serial)

        if "sopin" in param:
            if "sopin" not in param:
                raise ParameterError(_("Missing parameter: %r")
                                     % "sopin", id=905)

            # check admin authorization
            policies = getAdminPolicies("setSCPIN", context=context)
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial,
                                            User("", "", ""),
                                            context=context)):
                log.warning("the admin >%s< is not allowed to setPIN for "
                            "token %s." % (policies['admin'], serial))
                raise PolicyException(_("You do not have the administrative "
                                      "right to set Smartcard PIN for "
                                      "token %s. Check the policies.")
                                      % serial)

    elif 'set' == method:

        if "pin" in param:
            policies = getAdminPolicies("setOTPPIN", context=context)
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user,
                                            context=context)):
                log.warning("the admin >%s< is not allowed to set "
                            "OTP PIN for token %s for user %s@%s"
                            % (policies['admin'], serial, user.login,
                               user.realm))
                raise PolicyException(_("You do not have the administrative "
                                      "right to set OTP PIN for token %s. "
                                      "Check the policies.") % serial)

        if ("MaxFailCount".lower() in param or
                "SyncWindow".lower() in param or
                "CounterWindow".lower() in param or
                "OtpLen".lower() in param):
            policies = getAdminPolicies("set", context=context)
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user,
                                            context=context)):
                log.warning("the admin >%s< is not allowed to set "
                            "token properites for %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException(_("You do not have the administrative "
                                      "right to set token properties for "
                                      "%s. Check the policies.") % serial)

    elif 'resync' == method:

        policies = getAdminPolicies("resync", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to resync token %s for "
                        "user %s@%s" % (policies['admin'], serial,
                                        user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to resync token %s. Check the "
                                  "policies.") % serial)

    elif 'userlist' == method:
        policies = getAdminPolicies("userlist", context=context)
        # check if the admin may view the users in this realm
        if (policies['active'] and
                not checkAdminAuthorization(policies, "", user,
                                            context=context)):
            log.warning("the admin >%s< is not allowed to list"
                        " users in realm %s(%s)!"
                        % (policies['admin'], user.realm, user.conf))
            raise PolicyException(_("You do not have the administrative"
                                  " right to list users in realm %s(%s).")
                                  % (user.realm, user.conf))

    elif 'tokenowner' == method:
        policies = getAdminPolicies("tokenowner", context=context)
        # check if the admin may view the users in this realm
        if (policies['active'] and
                not checkAdminAuthorization(policies, "", user,
                                            context=context)):
            log.warning("the admin >%s< is not allowed to get"
                        " the token owner in realm %s(%s)!"
                        % (policies['admin'], user.realm, user.conf))
            raise PolicyException(_("You do not have the administrative"
                                  " right to get the token owner in realm"
                                  " %s(%s).") % (user.realm, user.conf))

    elif 'checkstatus' == method:
        policies = getAdminPolicies("checkstatus", context=context)
        # check if the admin may view the users in this realm
        if (policies['active'] and not
                checkAdminAuthorization(policies, "", user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to show status of token"
                        " challenges in realm %s(%s)!"
                        % (policies['admin'], user.realm, user.conf))
            raise PolicyException(_("You do not have the administrative "
                                  "right to show status of token "
                                  "challenges in realm "
                                  "%s(%s).") % (user.realm, user.conf))

    elif 'tokenrealm' == method:
        log.debug("entering method %s" % method)
        # The admin needs to have the right "manageToken" for all realms,
        # the token is currently in and all realm the Token should go into.
        policies = getAdminPolicies("manageToken", context=context)

        if "realms" not in param:
            raise ParameterError(_("Missing parameter: %r")
                                     % "realms", id=905)

        realms = param["realms"]

        # List of the new realms
        realmNewList = realms.split(',')
        # List of existing realms
        realmExistList = linotp.lib.token.getTokenRealms(serial)

        for r in realmExistList:
            if (policies['active'] and not
                checkAdminAuthorization(policies, None,
                                        User("dummy", r, None),
                                        context=context)):
                log.warning("the admin >%s< is not allowed "
                            "to manage tokens in realm %s"
                            % (policies['admin'], r))
                raise PolicyException(_("You do not have the administrative "
                                      "right to remove tokens from realm "
                                      "%s. Check the policies.") % r)

        for r in realmNewList:
            if (policies['active'] and not
                checkAdminAuthorization(policies, None,
                                        User("dummy", r, None),
                                        context=context)):
                log.warning("the admin >%s< is not allowed "
                            "to manage tokens in realm %s"
                            % (policies['admin'], r))
                raise PolicyException(_("You do not have the administrative "
                                      "right to add tokens to realm %s. "
                                      "Check the policies.") % r)

            if not _checkTokenNum(realm=r, context=context):
                log.warning("the maximum tokens for the "
                            "realm %s is exceeded." % r)
                raise PolicyException(_("You may not put any more tokens in "
                                      "realm %s. Check the policy "
                                      "'tokencount'") % r)

    elif 'reset' == method:

        policies = getAdminPolicies("reset", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user,
                                        context=context)):
            log.warning("the admin >%s< is not allowed to reset "
                        "token %s for user %s@%s" % (policies['admin'],
                                                     serial, user.login,
                                                     user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to reset token %s. Check the "
                                  "policies.") % serial)

    elif 'import' == method:
        policies = getAdminPolicies("import", context=context)
        # no right to import token in any realm
        log.debug("checking import token at all")
        if policies['active'] and len(policies['realms']) == 0:
            log.warning("the admin >%s< is not allowed "
                        "to import a token at all."
                        % (policies['admin']))

            raise PolicyException(_("You do not have the administrative "
                                  "right to import tokens. Check the "
                                  "policies."))
        ret['realms'] = policies['realms']

    elif 'loadtokens' == method:
        tokenrealm = param.get('tokenrealm')
        policies = getAdminPolicies("import", context=context)
        if policies['active'] and tokenrealm not in policies['realms']:
            log.warning("the admin >%s< is not allowed to "
                        "import token files to realm %s: %s"
                        % (policies['admin'], tokenrealm, policies))
            raise PolicyException(_("You do not have the administrative "
                                  "right to import token files to realm %s"
                                  ". Check the policies.") % tokenrealm)

        if not _checkTokenNum(realm=tokenrealm, context=context):
            log.warning("the maximum tokens for the realm "
                        "%s is exceeded." % tokenrealm)
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "in realm %s is exceeded. Check policy "
                                  "tokencount!") % tokenrealm)

    else:
        # unknown method
        log.error("an unknown method <<%s>> was passed." % method)
        raise PolicyException(_("Failed to run checkPolicyPre. "
                              "Unknown method: %s") % method)

    return ret


def _checkGetTokenPolicyPre(method, param={}, authUser=None, user=None,
                            context=None):
    ret = {}
    _ = context['translate']

    if 'max_count' == method[0: len('max_count')]:
        ret = 0
        serial = param.get("serial")
        ttype = linotp.lib.token.getTokenType(serial).lower()
        trealms = linotp.lib.token.getTokenRealms(serial)
        pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")
        admin_user = _getAuthenticatedUser(context)
        if pol_action == "":
            raise PolicyException(_("There is no policy gettoken/"
                                  "max_count definable for the "
                                  "tokentype %r") % ttype)

        policies = {}
        for realm in trealms:
            pol = getPolicy({'scope': 'gettoken', 'realm': realm,
                             'user': admin_user['login']},
                            context=context)
            log.error("got a policy: %r" % policies)

            policies.update(pol)

        value = getPolicyActionValue(policies, pol_action)
        log.debug("got all policies: %r: %r" % (policies, value))
        ret = value

    return ret


def _checkAuditPolicyPre(method, param={}, authUser=None, user=None,
                        context=None):

    ret = {}
    _ = context['translate']

    if 'view' == method:
        auth = _getAuthorization("audit", "view", context=context)
        if auth['active'] and not auth['auth']:
            log.warning("the admin >%r< is not allowed to "
                        "view the audit trail" % auth['admin'])

            ret = _("You do not have the administrative right to view the "
                   "audit trail. You are missing a policy "
                   "scope=audit, action=view")
            raise PolicyException(ret)
    else:
        log.error("an unknown method was passed in : %s" % method)
        raise PolicyException(_("Failed to run checkPolicyPre. Unknown "
                              "method: %s") % method)

    return ret


def _checkManagePolicyPre(method, param={}, authUser=None, user=None,
                        context=None):
    controller = 'manage'
    ret = {}
    log.debug("entering controller %s" % controller)
    return ret


def checkToolsAuthorisation(method, param={}, context=None):
    # TODO: fix the semantic of the realm in the policy!

    ret = {}
    _ = context['translate']

    auth = _getAuthorization("tools", method, context=context)
    if auth['active'] and not auth['auth']:
        log.warning("the admin >%r< is not allowed to "
                    "view the audit trail" % auth['admin'])

        ret = _("You do not have the administrative right to manage tools. "
               "You are missing a policy scope=tools, action=%s") % method

        raise PolicyException(ret)


def _checkSelfservicePolicyPre(method, param={}, authUser=None, user=None,
                        context=None):

    ret = {}
    _ = context['translate']
    controller = 'selfservice'
    client = _get_client(context)

    log.debug("entering controller %s" % controller)

    if 'max_count' == method[0: len('max_count')]:
        ret = 0
        serial = param.get("serial")
        ttype = linotp.lib.token.getTokenType(serial).lower()
        urealm = authUser.realm
        pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")
        if pol_action == "":
            raise PolicyException(_("There is no policy selfservice/"
                                  "max_count definable for the token "
                                  "type %s.") % ttype)

        policies = get_client_policy(client, scope='selfservice',
                                     realm=urealm, user=authUser.login,
                                     userObj=authUser, context=context)
        log.debug("[max_count] got a policy: %r" % policies)
        if policies == {}:
            raise PolicyException(_("There is no policy selfservice/"
                                  "max_count defined for the tokentype "
                                  "%s in realm %s.") % (ttype, urealm))

        value = getPolicyActionValue(policies, pol_action)
        log.debug("[max_count] got all policies: %r: %r" % (policies, value))
        ret = value

    elif 'usersetpin' == method:

        if not 'setOTPPIN' in getSelfserviceActions(authUser, context=context):
            log.warning("user %s@%s is not allowed to call this function!" %
                        (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userreset' == method:

        if not 'reset' in getSelfserviceActions(authUser, context=context):
            log.warning("user %s@%s is not allowed to call this function!" %
                        (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userresync' == method:

        if not 'resync' in getSelfserviceActions(authUser, context=context):
            log.warning("user %s@%s is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'usersetmpin' == method:

        if not 'setMOTPPIN' in getSelfserviceActions(authUser,
                                                     context=context):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'useractivateocratoken' == method:
        user_selfservice_actions = getSelfserviceActions(authUser,
                                                         context=context)
        typ = param.get('type').lower()
        if (typ == 'ocra'
                and 'activateQR' not in user_selfservice_actions):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'useractivateocra2token' == method:
        user_selfservice_actions = getSelfserviceActions(authUser,
                                                         context=context)
        typ = param.get('type').lower()
        if (typ == 'ocra2'
                and 'activateQR2' not in user_selfservice_actions):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userassign' == method:

        if not 'assign' in getSelfserviceActions(authUser, context=context):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow '
                                  'you to issue this request!'))

        # Here we check, if the tokennum exceeds the tokens
        if not _checkTokenNum(context=context):
            log.error("The maximum token number "
                      "is reached!")
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        if not _checkTokenAssigned(authUser, context=context):
            log.warning("the maximum number of allowed tokens is"
                        " exceeded. Check the policies")
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    elif 'usergetserialbyotp' == method:

        if not 'getserial' in getSelfserviceActions(authUser, context=context):
            log.warning("user %s@%s is not allowed to call this function!" %
                        (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you to'
                                  ' request a serial by OTP!'))

    elif 'userdisable' == method:

        if not 'disable' in getSelfserviceActions(authUser, context=context):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userenable' == method:

        if not 'enable' in getSelfserviceActions(authUser, context=context):
            log.warning("user %s@%s is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you to'
                                  ' issue this request!'))

    elif 'userunassign' == method:

        if not 'unassign' in getSelfserviceActions(authUser, context=context):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userdelete' == method:

        if not 'delete' in getSelfserviceActions(authUser, context=context):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userwebprovision' == method:
        user_selfservice_actions = getSelfserviceActions(authUser,
                                                         context=context)
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
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _checkTokenNum(context=context):
            log.error("The maximum token number is reached!")
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        if not _checkTokenAssigned(authUser, context=context):
            log.warning("the maximum number of allowed tokens is exceeded. "
                        "Check the policies")
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    elif 'userhistory' == method:
        if not 'history' in getSelfserviceActions(authUser, context=context):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userinit' == method:

        allowed_actions = getSelfserviceActions(authUser, context=context)
        typ = param['type'].lower()
        meth = 'enroll' + typ.upper()

        if meth not in allowed_actions:
            log.warning("user %r@%r is not allowed to enroll %s!"
                        % (authUser.login, authUser.realm, typ))
            raise PolicyException(_('The policy settings do not allow '
                                  'you to issue this request!'))

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _checkTokenNum(context=context):
            log.error("The maximum token number is reached!")
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        if not _checkTokenAssigned(authUser, context=context):
            log.warning("the maximum number of allowed tokens is exceeded. "
                        "Check the policies")
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    else:
        log.error("Unknown method in selfservice: %s" % method)
        raise PolicyException(_("Unknown method in selfservice: %s") % method)

    return ret


def _checkSystemPolicyPre(method, param={}, authUser=None, user=None,
                   context=None):
    ret = {}
    _ = context['translate']

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
        log.error("an unknown method was passed in system: %s" % method)
        raise PolicyException(_("Failed to run checkPolicyPre. "
                              "Unknown method: %s") % method)

    auth = _getAuthorization('system', actions[method], context=context)

    if auth['active'] and not auth['auth']:
        log.warning("admin >%s< is not authorited to %s."
                    " Missing policy scope=system, action=%s"
                    % (auth['admin'], method, actions[method]))

        raise PolicyException(_("Policy check failed. You are not allowed "
                              "to %s system config.") % actions[method])

    return ret


def _checkOcraPolicyPre(method, param={}, authUser=None, user=None,
                       context=None):

    ret = {}
    _ = context['translate']
    client = _get_client(context)

    method_map = {'request': 'request', 'status': 'checkstatus',
                  'activationcode': 'getActivationCode',
                  'calcOTP': 'calculateOtp'}

    admin_user = _getAuthenticatedUser(context)
    policies = getPolicy({'user': admin_user.get('login'), 'scope': 'ocra',
                          'action': method, 'client': client},
                         context=context)

    if len(policies) == 0:
        log.warning("the admin >%r< is not allowed to do an ocra/%r"
                    % (admin_user.get('login'), method_map.get(method)))
        raise PolicyException(_("You do not have the administrative right to"
                              " do an ocra/%s") % method_map.get(method))

    return ret


def checkPolicyPre(controller, method, param={}, authUser=None, user=None,
                   context=None):
    '''
    This function will check for all policy definition for a certain
    controller/method It is run directly before doing the action in the
    controller. I will raise an exception, if it fails.

    :param param: This is a dictionary with the necessary parameters.

    :return: dictionary with the necessary results. These depend on
             the controller.
    '''
    ret = {}
    _ = context["translate"]

    log.debug("entering controller %s" % controller)
    log.debug("entering method %s" % method)

    if 'admin' == controller:
        ret = _checkAdminPolicyPre(method=method, param=param,
                                  authUser=authUser, user=user,
                                  context=context)

    elif 'gettoken' == controller:
        ret = _checkGetTokenPolicyPre(method=method, param=param,
                                     authUser=authUser, user=user,
                                     context=context)
    elif 'audit' == controller:
        ret = _checkAuditPolicyPre(method=method, param=param,
                                     authUser=authUser, user=user,
                                     context=context)

    elif 'manage' == controller:
        ret = _checkManagePolicyPre(method=method, param=param,
                                     authUser=authUser, user=user,
                                     context=context)

    elif controller in ['tools']:
        ret = _checkToolsPolicyPre(method=method, param=param,
                                     authUser=authUser, user=user,
                                     context=context)

    elif 'selfservice' == controller:
        ret = _checkSelfservicePolicyPre(method=method, param=param,
                                     authUser=authUser, user=user,
                                     context=context)

    elif 'system' == controller:
        ret = _checkSystemPolicyPre(method=method, param=param,
                                     authUser=authUser, user=user,
                                     context=context)

    elif controller == 'ocra':
        ret = _checkOcraPolicyPre(method=method, param=param,
                                     authUser=authUser, user=user,
                                     context=context)

    else:
        # unknown controller
        log.error("an unknown controller <<%r>> was passed." % controller)
        raise PolicyException(_("Failed to run getPolicyPre. Unknown "
                              "controller: %s") % controller)

    return ret


##############################################################################
def _checkAdminPolicyPost(method, param=None, user=None, context=None):
    ret = {}
    controller = 'admin'
    _ = context['translate']

    log.debug("entering controller %s" % controller)
    log.debug("entering method %s" % method)
    log.debug("using params %s" % param)
    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam(context=context)

    if method in ['init', 'assign', 'setPin', 'loadtokens']:
        # check if we are supposed to genereate a random OTP PIN
        randomPINLength = _getRandomOTPPINLength(user, context=context)
        if randomPINLength > 0:
            newpin = _getRandomPin(randomPINLength, context=context)
            log.debug("setting random pin for token with serial %s and user: "
                      "%s" % (serial, user))
            linotp.lib.token.setPin(newpin, None, serial, context=context)
            log.debug("pin set")
            # TODO: This random PIN could be processed and
            # printed in a PIN letter
    elif 'getserial' == method:
        # check if the serial/token, that was returned is in
        # the realms of the admin!
        policies = getAdminPolicies("getserial", context=context)
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial,
                                        User('', '', ''), context=context)):
            log.warning("the admin >%s< is not allowed to get "
                        "serial of token %s" % (policies['admin'], serial))
            raise PolicyException(_("You do not have the administrative "
                                  "right to get serials from this realm!"))
    else:
        # unknown method
        log.error("an unknown method <<%s>> was passed." % method)
        raise PolicyException(_("Failed to run getPolicyPost. "
                              "Unknown method: %s") % method)

    return ret


def _checkSystemPolicyPost(method, param=None, user=None, context=None):

    ret = {}
    controller = 'system'
    _ = context['translate']

    log.debug("entering controller %s" % controller)

    if 'getRealms' == method:
        systemReadRights = False
        res = param['realms']
        auth = _getAuthorization('system', 'read', context=context)
        if auth['auth']:
            systemReadRights = True

        if not systemReadRights:
            # If the admin is not allowed to see all realms,
            # (policy scope=system, action=read)
            # the realms, where he has no administrative rights need,
            # to be stripped.
            pol = getAdminPolicies('', context=context)
            if pol['active']:
                log.debug("the admin has policies "
                          "in these realms: %r" % pol['realms'])

                lowerRealms = uniquify(pol['realms'])
                for realm, _v in res.items():
                    if ((not realm.lower() in lowerRealms)
                            and (not '*' in lowerRealms)):
                        log.debug("the admin has no policy in "
                                  "realm %r. Deleting "
                                  "it: %r" % (realm, res))
                        del res[realm]
            else:
                log.error("system: : getRealms: "
                          "The admin >%s< is not allowed to read system "
                          "config and has not realm administrative rights!"
                          % auth['admin'])
                raise PolicyException(_("You do not have system config read "
                                      "rights and not realm admin "
                                      "policies."))
        ret['realms'] = res
    return ret


def _checkSelfservicePolicyPost(method, param=None, user=None, context=None):

    ret = {}
    _ = context['translate']
    controller = 'selfservice'

    log.debug("entering controller %s" % controller)
    log.debug("entering method %s" % method)
    log.debug("using params %s" % param)
    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam(context=context)

    if 'enroll' == method:
        # check if we are supposed to genereate a random OTP PIN
        randomPINLength = _getRandomOTPPINLength(user, context=context)
        if randomPINLength > 0:
            newpin = _getRandomPin(randomPINLength, context=context)
            log.debug("setting random pin for token with serial "
                      "%s and user: %s" % (serial, user))
            linotp.lib.token.setPin(newpin, None, serial)
            log.debug("[init] pin set")
            # TODO: This random PIN could be processed and
            # printed in a PIN letter

    return ret


def checkPolicyPost(controller, method, param=None, user=None, context=None):
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
    _ = context['translate']

    if param is None:
        param = {}

    if 'admin' == controller:
        ret = _checkAdminPolicyPost(method, param=param, user=user,
                                   context=context)

    elif 'system' == controller:
        ret = _checkSystemPolicyPost(method, param=param, user=user,
                                    context=context)
    elif 'selfservice' == controller:
        ret = _checkSelfservicePolicyPost(method, param=param, user=user,
                                    context=context)
    else:
        # unknown controller
        log.error("an unknown constroller <<%s>> "
                  "was passed." % controller)
        raise PolicyException(_("Failed to run getPolicyPost. "
                              "Unknown controller: %s") % controller)
    return ret


###############################################################################
#
# Client Policies
#
def get_client_policy(client, scope=None, action=None, realm=None, user=None,
                      find_resolver=True, userObj=None, context=None):
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

    log.debug("with params %r, client %r and user %r" % (param, client, user))
    Pols = getPolicy(param, context=context)
    log.debug("got policies %s " % Pols)

    def get_array(policy, attribute="client", marks=False):
        # # This function returns the parameter "client" or
        # # "user" in a policy as an array
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

    # # 1. Find a policy with this client
    for pol, policy in Pols.items():
        log.debug("checking policy %s" % pol)
        clients_array = get_array(policy, attribute="client")
        log.debug("the policy %s has these clients: %s. "
                  "checking against %s." % (pol, clients_array, client))

        # accept wildcards for clients
        if '*' in clients_array:
            Policies[pol] = policy
            continue

        client_found = False
        client_excluded = False
        for cl in clients_array:
            try:
                if cl[0] in ['-', '!']:
                    if IPAddress(client) in IPNetwork(cl[1:]):
                        log.debug("the client %s is excluded by %s in policy "
                                  "%s" % (client, cl, pol))
                        client_excluded = True
                if IPAddress(client) in IPNetwork(cl):
                    client_found = True
            except Exception as e:
                log.warning("authorization policy %s with invalid client: %r"
                            % (pol, e))

        if client_found and not client_excluded:
            Policies[pol] = policy

    # No policy for this client was found, but maybe
    # there is one without clients
    if len(Policies) == 0:
        log.debug("looking for policy without any client")
        for pol, policy in Pols.items():
            if len(get_array(policy, attribute="client")) == 0:
                Policies[pol] = policy

    # # 2. Within those policies select the policy with the user.
    # #     if there is a policy with this very user, return only
    # #     these policies, otherwise return all policies
    if user:
        user_policy_found = False
        own_policies = {}
        default_policies = {}
        for polname, pol in Policies.items():
            users = get_array(pol, attribute="user")
            log.debug("search user %s in users %s of policy %s" %
                      (user, users, polname))
            if user in users or '*' in users:
                log.debug("adding %s to own_policies" % polname)
                own_policies[polname] = pol
            elif len(users) == 0:
                log.debug("adding %s to default_policies" % polname)

                default_policies[polname] = pol
            else:
                log.debug("policy %s contains only users (%s) other than %s" %
                          (polname, users, user))

        if len(own_policies):
            Policies = own_policies
            user_policy_found = True
        else:
            Policies = default_policies

        # #3. If no user specific policy was found, we now take a look,
        # #   if we find a policy with the matching resolver.
        if not user_policy_found and realm and find_resolver:
            # # get the resolver of the user in the realm and search for this
            # # resolver in the policies
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
                        log.debug("adding %s to own_policies" % polname)
                        own_policies[polname] = pol
                    elif len(resolvs) == 0:
                        log.debug("adding %s (no resolvers) default_policies"
                                   % polname)
                        default_policies[polname] = pol
                    else:
                        log.debug("policy %s contains only resolvers (%s) "
                                  "other than %s" % (polname, resolvs, r))
            if len(own_policies):
                Policies = own_policies
            else:
                Policies = default_policies

    return Policies


def set_realm(login, realm, exception=False, context=None):
    '''
    this function reads the policy scope: authorization, client: x.y.z,
    action: setrealm=new_realm and overwrites the existing realm of the user
    with the new_realm.
    This can be used, if the client is not able to pass a realm and the users
    are not be located in the default realm.

    returns:
        realm    - name of the new realm taken from the policy
    '''

    client = _get_client(context)

    log.debug("got the client %s" % client)
    log.debug("users %s original realm is %s" % (login, realm))
    policies = get_client_policy(client, scope="authorization",
                                 action="setrealm", realm=realm,
                                 user=login, find_resolver=False,
                                 context=context)

    if len(policies):
        realm = getPolicyActionValue(policies, "setrealm", is_string=True)

    log.debug("users %s new realm is %s" % (login, realm))
    return realm


def check_user_authorization(login, realm, exception=False, context=None):
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
    client = _get_client(context)

    # if there is absolutely NO policy in scope authorization,
    # we return immediately
    if len(getPolicy({"scope": "authorization", "action": "authorize"},
                     context=context)) == 0:
        log.debug("absolutely no authorization policy.")
        return True

    log.debug("got the client %s" % client)
    policies = get_client_policy(client, scope="authorization",
                                 action="authorize", realm=realm, user=login,
                                 context=context)
    log.debug("got policies %s for user %s" % (policies, login))

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
def get_auth_passthru(user, context=None):
    '''
    returns True, if the user in this realm should be authenticated against
    the UserIdResolver in case the user has no tokens assigned.
    '''
    ret = False
    client = _get_client(context)

    pol = get_client_policy(client, scope="authentication",
                            action="passthru", realm=user.realm,
                            user=user.login, userObj=user,
                            context=context)
    if len(pol) > 0:
        ret = True
    return ret


def get_auth_forward(user, context=None):
    '''
    returns the list of all forwarding servers
    '''
    client = _get_client(context)

    pol = get_client_policy(client, scope="authentication",
                            action="forward", realm=user.realm,
                            user=user.login, userObj=user,
                            context=context)
    if not pol:
        return None

    servers = getPolicyActionValue(pol, "forward", is_string=True)

    return servers


def get_auth_passOnNoToken(user, context=None):
    '''
    returns True, if the user in this realm should be always authenticated
    in case the user has no tokens assigned.
    '''
    ret = False
    client = _get_client(context)

    pol = get_client_policy(client, scope="authentication",
                            action="passOnNoToken", realm=user.realm,
                            user=user.login, userObj=user,
                            context=context)
    if len(pol) > 0:
        ret = True
    return ret


def trigger_sms(realms=None, context=None):
    """
    returns true, if a check_s should be allowed to trigger an sms
    """
    client = _get_client(context)
    user = _getUserFromParam(context=context)

    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm(context=context)
        realms = [realm]

    ret = False
    for realm in realms:
        pol = get_client_policy(client, scope="authentication",
                                action="trigger_sms", realm=realm,
                                user=login, userObj=user,
                                context=context)

        if len(pol) > 0:
            log.debug("found policy in realm %s" % realm)
            ret = True

    return ret


def get_auth_AutoSMSPolicy(realms=None, context=None):
    '''
    Returns true, if the autosms policy is set in one of the realms

    return:
        True or False

    input:
        list of realms
    '''
    log.debug("checking realms %r " % realms)
    client = _get_client(context)

    user = _getUserFromParam(context=context)
    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm(context=context)
        realms = [realm]

    ret = False
    for realm in realms:
        pol = get_client_policy(client, scope="authentication",
                                action="autosms", realm=realm,
                                user=login, userObj=user,
                                context=context)

        if len(pol) > 0:
            log.debug("found policy in realm %s" % realm)
            ret = True

    return ret


def get_auth_challenge_response(user, ttype, context=None):
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

    client = _get_client(context)

    pol = get_client_policy(client, scope="authentication",
                            action="challenge_response",
                            realm=p_realm,
                            user=p_user, userObj=user,
                            context=context)
    log.debug("got policy %r for user %r@%r from client %r" %
              (pol, p_user, p_realm, client))

    Token_Types = getPolicyActionValue(pol, "challenge_response", is_string=True)
    token_types = [t.lower() for t in Token_Types.split()]

    if ttype.lower() in token_types or '*' in token_types:
        log.debug("found matching token type %s" % ttype)
        ret = True

    return ret


def _get_auth_PinPolicy(realm=None, user=None, context=None):
    '''
    Returns the PIN policy, that defines, how the OTP PIN is to be verified
    within the given realm

    :return:
        - 0 verify against fixed OTP PIN
        - 1 verify the password component against the
          UserResolver (LPAP Password etc.)
        - 2 verify no OTP PIN at all! Only OTP value!

    The policy is defined via::

        scope : authentication
        realm : ....
        action: otppin=0/1/2
        client: IP
        user  : some user
    '''
    log.debug("[get_auth_PinPolicy]")
    client = _get_client(context)

    if user is None:
        user = _getUserFromParam(context=context)
    login = user.login
    if realm is None:
        realm = user.realm or _getDefaultRealm(context=context)

    pol = get_client_policy(client, scope="authentication", action="otppin",
                            realm=realm, user=login, userObj=user,
                            context=context)

    log.debug("got policy %s for user %s@%s  client %s"
              % (pol, login, realm, client))
    pin_check = getPolicyActionValue(pol, "otppin", max=False)

    if pin_check in [1, 2]:
        return pin_check

    return 0

def get_qrtan_url(realms, context=None):
    '''
    Returns the URL for the half automatic mode for the QR TAN token
    for the given realm

    :remark: there might be more than one url, if the token
             belongs to more than one realm

    :param realms: list of realms or None

    :return: url string

    '''
    log.debug("getting qrtan callback url ")
    url = ''
    urls = []

    if realms is None:
        realms = []

    for realm in realms:
        pol = getPolicy({"scope": "authentication", 'realm': realm},
                        context=context)
        url = getPolicyActionValue(pol, "qrtanurl", is_string=True)
        if url:
            urls.append(url)

    if len(urls) > 1:
        raise Exception('multiple enrollement urls %r found for realm set: %r'
                        % (urls, realms))

    log.debug("got callback url %s for realms %r" % (url, realms))
    return url


###############################################################################
#
#  Authorization
#
def check_auth_tokentype(serial, exception=False, user=None, context=None):
    '''
    Checks if the token type of the given serial matches the tokentype policy

    :return: True/False - returns true or false or raises an exception
                          if exception=True
    '''

    _ = context['translate']

    log.debug("[check_auth_tokentype]")
    if serial is None:
        # if no serial is given, we return True right away
        log.debug("We have got no serial. Obviously doing passthru.")
        return True

    client = _get_client(context)

    if user is None:
        user = _getUserFromParam(context=context)
    login = user.login
    realm = user.realm or _getDefaultRealm(context=context)
    tokentypes = []
    tokentype = ""
    res = False

    pol = get_client_policy(client, scope="authorization", action="tokentype",
                            realm=realm, user=login, userObj=user,
                            context=context)

    log.debug("got policy %s for user %s@%s  client %s"
              % (pol, login, realm, client))

    t_type = getPolicyActionValue(pol, "tokentype", max=False, is_string=True)
    if len(t_type) > 0:
        tokentypes = [t.strip() for t in t_type.lower().split(" ")]

    log.debug("found these tokentypes: <%s>" % tokentypes)

    toks = linotp.lib.token.getTokens4UserOrSerial(None, serial,
                                                   context=context)
    if len(toks) > 1:
        log.error("multiple tokens with serial %s found"
                  " - cannot get OTP!" % serial)
        raise PolicyException(_("multiple tokens found - "
                              "cannot determine tokentype!"))
    elif len(toks) == 1:
        log.debug("found one token with serial %s" % serial)
        tokentype = toks[0].getType().lower()
        log.debug("got the type %s for token %s" % (tokentype, serial))

        if (tokentype in tokentypes or '*' in tokentypes
                or len(tokentypes) == 0):
            res = True
    elif len(toks) == 0:
        # # TODO if the user does not exis or does have no token
        ## ---- WHAT DO WE DO? ---
        # # At the moment we pass through: This is the old behaviour...
        res = True

    if res is False and exception:
        context['audit']["action_detail"] = \
            "failed due to authorization/tokentype policy"
        raise AuthorizeException("Authorization for token %s with type %s "
                                 "failed on client %s" % (serial, tokentype,
                                                          client))

    return res


def check_auth_serial(serial, exception=False, user=None, context=None):
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

    if serial is None:
        # if no serial is given, we return True right away
        log.debug("We have got no serial. Obviously doing passthru.")
        return True

    client = _get_client(context)

    if user is None:
        user = _getUserFromParam(context=context)
    login = user.login
    realm = user.realm or _getDefaultRealm(context=context)
    res = False

    pol = get_client_policy(client, scope="authorization", action="serial",
                            realm=realm, user=login, userObj=user,
                            context=context)
    if len(pol) == 0:
        # No policy found, so we skip the rest
        log.debug("No policy scope=authorize, action=serial for user %r, "
                  "realm %r, client %r" % (login, realm, client))
        return True

    log.debug("got policy %s for user %s@%s  client %s" %
              (pol, login, realm, client))

    # extract the value from the policy
    serial_regexp = getPolicyActionValue(pol, "serial", max=False, is_string=True)
    log.debug("found this regexp /%r/ for the serial %r"
              % (serial_regexp, serial))

    if re.search(serial_regexp, serial):
        log.debug("regexp matches.")
        res = True

    if res is False and exception:
        context['audit']["action_detail"] = ("failed due to authorization/"
                                            "serial policy")
        raise AuthorizeException("Authorization for token %s failed on "
                                 "client %s" % (serial, client))

    return res


def is_auth_return(success=True, user=None, context=None):
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

    client = _get_client(context)

    if user is None:
        user = _getUserFromParam(context=context)

    login = user.login
    realm = user.realm or _getDefaultRealm(context=context)
    if success:
        pol = get_client_policy(client, scope="authorization",
                                action="detail_on_success", realm=realm,
                                user=login, userObj=user,
                                context=context)
    else:
        pol = get_client_policy(client, scope="authorization",
                                action="detail_on_fail", realm=realm,
                                user=login, userObj=user,
                                context=context)

    if len(pol):
        ret = True

    return ret


### helper ################################
def get_pin_policies(user, context=None):
    '''
    lookup for the pin policies - the list of policies
    is preserved for repeated lookups

    : raises: exception, if more then one pin policies are matching

    :param user: the policies which are applicable to the user
    :return: list of otppin id's
    '''
    pin_policies = []

    pin_policies.append(_get_auth_PinPolicy(user=user, context=context))
    pin_policies = list(set(pin_policies))

    if len(pin_policies) > 1:
        msg = ("conflicting authentication polices. "
               "Check scope=authentication. policies: %r" % pin_policies)

        log.error("[__checkToken] %r" % msg)
        # self.context.audit['action_detail'] = msg
        raise Exception('multiple pin policies found')
        # # former return -2

    return pin_policies

#eof###########################################################################
