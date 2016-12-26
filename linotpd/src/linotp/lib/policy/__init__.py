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
""" policy processing """

import logging
# for loading XML file
import string
import re

from copy import deepcopy

from netaddr import IPAddress
from netaddr import IPNetwork

import linotp
from linotp.lib.user import getUserRealms
from linotp.lib.user import User
from linotp.lib.user import getResolversOfUser

from linotp.lib.error import LinotpError
from linotp.lib.error import ParameterError

from linotp.lib.context import request_context as context

from linotp.lib.policy.definitions import SYSTEM_ACTIONS

from linotp.lib.policy.util import get_realm_from_policies
from linotp.lib.policy.util import get_resolvers_for_realms
from linotp.lib.policy.util import are_the_same

from linotp.lib.policy.evaluate import PolicyEvaluater

from linotp.lib.policy.legacy import legacy_getAuthorization
from linotp.lib.policy.legacy import legacy_getPolicy

from linotp.lib.policy.processing import new_getAuthorization
from linotp.lib.policy.processing import new_getPolicy


# for generating random passwords
from linotp.lib.crypto import urandom
from linotp.lib.util import uniquify

from linotp.lib.policy.filter import AttributeCompare
from linotp.lib.policy.filter import UserDomainCompare

from linotp.lib.policy.util import _getAuthenticatedUser
from linotp.lib.policy.util import _get_client
from linotp.lib.policy.util import _get_pin_values
from linotp.lib.policy.util import _getDefaultRealm
from linotp.lib.policy.util import _getLinotpConfig
from linotp.lib.policy.util import _getRealms
from linotp.lib.policy.util import _getUserFromParam

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


def _getUserRealms(user):
    return getUserRealms(user,
                         allRealms=context['Realms'],
                         defaultRealm=context['defaultRealm'])


def getPolicy(param, display_inactive=False):
    """
    migration method for the getPolicy old and new
    """

    pols_old = legacy_getPolicy(param,
                                display_inactive=display_inactive)
    pols_new = new_getPolicy(param,
                             display_inactive=display_inactive)

    the_same = are_the_same(pols_old, pols_new)

    if not the_same:
        log.error('PolicyEvaluation is not the same for params %r', param)
        log.error('old: new %r <> %r', pols_old, pols_new)

        raise_exx = context['Config'].get('NewPolicyEvaluation.exception',
                                          'True')
        pols_old = legacy_getPolicy(param,
                                display_inactive=display_inactive)
        pols_new = new_getPolicy(param,
                                 display_inactive=display_inactive)

        if raise_exx.lower() == 'true':
            raise Exception('Policy Engine missmatch: %r:%r' %
                            (pols_old, pols_new))

    use_new_one = context['Config'].get('NewPolicyEvaluation', 'False')

    if use_new_one.lower() == 'true':
        return pols_new

    return pols_old


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
        if type(ret) in [str, unicode] and is_string is False:
            try:
                ret = int(ret)
            except ValueError:
                pass

        if ret:
            results[_polname] = ret

    if len(results) > 1:
        for val in results.values():
            if val != results.values()[0]:
                log. error("Policies: multiple different action value matches "
                           "exist: %r" % results)

    ret = -1
    if is_string:
        ret = ""

    if results:
        ret = results.values()[0]

    return ret


def getAdminPolicies(action, scope='admin'):
    """
    This internal function returns the policies (default: of scope=admin)
    for the currently authenticated administrativ user.__builtins__

    :param action: this is the action (like enable, disable, init...)
    :param scope: scope of the policies,
                    might be admin, monitoring, reporting.access

    :return: a dictionary with the following keys:

        - active (if policies are used)
        - realms (the realms, in which the admin is allowed to do this action)
        - resolvers (the resolvers in which the admin is allowed to perform
          this action)
        - admin (the name of the authenticated admin user)
    """
    active = True

    # We may change this later to other authentication schemes
    admin_user = _getAuthenticatedUser()
    log.info("Evaluating policies for the user: %s" % admin_user['login'])

    # check if we got admin policies at all
    p_at_all = getPolicy({'scope': scope})

    if not p_at_all:
        log.info("No policies in scope admin found."
                 " Admin authorization will be disabled.")
        active = False
        realms = []
        resolvers = []

    else:
        pol_request = {'user': admin_user['login'], 'scope': scope}
        if action:
            pol_request['action'] = action

        policies = getPolicy(pol_request)
        log.debug("Found the following policies: %r", policies)

        realms = get_realm_from_policies(policies)
        resolvers = get_resolvers_for_realms(realms)

    log.debug("Found the following resolvers in the policy: %r", resolvers)
    return {'active': active,
            'realms': realms,
            'resolvers': resolvers,
            'admin': admin_user['login']}


def _getAuthorization(scope, action):
    """
    migration stub for the new policy engine
    """


    new_pols = new_getAuthorization(scope, action)
    retro = legacy_getAuthorization(scope, action)

    the_same = are_the_same(retro, new_pols)

    if not the_same:
        log.error('PolicyEvaluation is not the same for params %r,%r',
                  scope, action)
        log.error('old: new %r <> %r', retro, new_pols)

        raise_exx = context['Config'].get('NewPolicyEvaluation.exception',
                                          'True')

        new_pols = new_getAuthorization(scope, action)

        if raise_exx.lower() == 'true':
            raise Exception('Policy Engine missmatch: %r:%r' %
                            (retro, new_pols))

    use_new_one = context['Config'].get('NewPolicyEvaluation', 'False')
    if use_new_one.lower() == 'true':
        return new_pols

    return retro


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
        if user.realm == "" and user.resolver_config_identifier == "":
            return _getDefaultRealm() in policies['realms']
        if not user.realm and not user.resolver_config_identifier:
            return _getDefaultRealm() in policies['realms']
        # we got a realm:
        if user.realm != "":
            return user.realm.lower() in policies['realms']
        if user.resolver_config_identifier != "":
            lower_config_id = user.resolver_config_identifier.lower()
            return lower_config_id in policies['resolvers']

    # catch all
    return False


def getSelfserviceActions(user):
    '''
    This function returns the allowed actions in the self service portal
    for the given user
    '''
    login = user.login
    realm = user.realm
    client = _get_client()

    log.debug("checking actions for scope=selfservice,"
              " realm=%r" % realm)

    policies = get_client_policy(client, scope="selfservice", realm=realm,
                                 user=login, userObj=user)

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


def _checkTokenNum(user=None, realm=None, post_check=False):
    '''
    This internal function checks if the number of the tokens is valid...
    for a certain realm...

    Therefor it checks the policy
        "scope = enrollment", action = "tokencount = <number>"

    if there are more tokens assigned than in tokencount mentioned,
    return will be false

    :param user: the user in the realm
    :param realm: the relevant realm
    :return: boolean - True if token number is allowed
    '''

    # If there is an empty user, we need to set it to None
    if user:
        if "" == user.login:
            user = None

    if user is None and realm is None:
        # No user and realm given, so we check all the tokens
        ret = True
        tNum = linotp.lib.token.getTokenNumResolver()
        return ret

    else:
        # allRealms = getRealms()
        Realms = []

        if user:
            # 1. alle resolver aus dem Realm holen.
            # 2. fuer jeden Resolver die tNum holen.
            # 3. die Policy holen und gegen die tNum checken.
            Realms = _getUserRealms(user)
        elif realm:
            Realms = [realm]

        tokenInRealms = {}
        for R in Realms:
            tIR = linotp.lib.token.getTokenInRealm(R)
            tokenInRealms[R] = tIR

        # Now we are checking the policy for every Realm! (if there are more)
        policyFound = False
        maxToken = 0
        for R in Realms:
            pol = getPolicy({'scope': 'enrollment', 'realm': R,
                             'action': 'tokencount'})
            polTNum = getPolicyActionValue(pol, 'tokencount')
            if polTNum > -1:
                policyFound = True

                if int(polTNum) > int(maxToken):
                    maxToken = int(polTNum)

            if post_check:
                if int(maxToken) >= int(tokenInRealms[R]):
                    return True
            else:
                if int(maxToken) > int(tokenInRealms[R]):
                    return True

        if policyFound is False:
            log.debug("there is no scope=enrollment, action=tokencount policy "
                      "for the realms %r" % Realms)
            return True

        log.info("No policy available for realm %r, where enough managable "
                 "tokens were defined." % Realms)

    return False


def _checkTokenAssigned(user):
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

    client = _get_client()
    Realms = _getUserRealms(user)

    log.debug("Policies: checking the already assigned tokens for user %s, "
              "realms %s" % (user.login, Realms))

    for R in Realms:
        pol = get_client_policy(client, scope='enrollment', realm=R,
                                user=user.login, userObj=user)
        if len(pol) == 0:
            log.debug("there is no scope=enrollment policy for Realm %s" % R)
            return True

        maxTokenAssigned = getPolicyActionValue(pol, "maxtoken")

        # get the tokens of the user
        tokens = linotp.lib.token.getTokens4UserOrSerial(user, "")
        # If there is a policy, where the tokennumber exceeds the tokens in
        # the corresponding realm..
        log.debug("the user %r has %r tokens assigned. The policy says a "
                  "maximum of %r tokens." % (user.login, len(tokens),
                                             maxTokenAssigned))
        if (int(maxTokenAssigned) > int(len(tokens)) or
                maxTokenAssigned == -1):
            return True

    return False


def get_tokenissuer(user="", realm="", serial=""):
    '''
    This internal function returns the issuer of the token as defined in policy
    scope = enrollment, action = tokenissuer = <string>
    The string can have the following variables:
        <u>: user
        <r>: realm
        <s>: token serial

    This function is used to create 'otpauth' tokens
    '''
    tokenissuer = "LinOTP"
    client = _get_client()
    pol = get_client_policy(client, scope="enrollment",
                            realm=realm, user=user)
    if len(pol) != 0:
        string_issuer = getPolicyActionValue(pol, "tokenissuer", is_string=True)
        if string_issuer:
            string_issuer = re.sub('<u>', user, string_issuer)
            string_issuer = re.sub('<r>', realm, string_issuer)
            string_issuer = re.sub('<s>', serial, string_issuer)
            tokenissuer = string_issuer

    log.debug("[get_tokenissuer] providing tokenissuer = %s" % str(tokenissuer))
    return tokenissuer


def get_tokenlabel(user="", realm="", serial=""):
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
    client = _get_client()

    # TODO: What happens when we got no realms?
    # pol = getPolicy( {'scope': 'enrollment', 'realm': realm} )
    pol = get_client_policy(client, scope="enrollment", action="tokenlabel",
                            realm=realm, user=user)
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


def get_autoassignment(user):
    '''
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    '''
    ret = False
    client = _get_client()

    pol = get_client_policy(client, scope='enrollment',
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        val = getPolicyActionValue(pol, "autoassignment")
        # with  LinOTP 2.7 the autassign policy is treated as boolean
        if val is True:
            ret = True
        # for backwar compatibility, we accept any values
        # other than -1, which indicates an error
        elif val != -1:
            ret = True

    log.debug("Policies: got the autoassignement value %r", ret)
    return ret


def get_auto_enrollment(user):
    '''
    this function checks the policy scope=enrollment, action=autoenrollment
    This policy policy returns the tokentyp: sms or email
    The function returns true, if autoenrollment is defined.
    '''
    ret = False
    token_typ = ''

    client = _get_client()

    pol = get_client_policy(client, scope='enrollment',
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        t_typ = getPolicyActionValue(pol, "autoenrollment", is_string=True)
        if type(t_typ) in [str, unicode] and t_typ.lower() in ['sms', 'email']:
            ret = True
            token_typ = t_typ.lower()

    return ret, token_typ


def autoassignment_forward(user):
    '''
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    '''
    ret = False
    client = _get_client()

    pol = get_client_policy(client, scope='enrollment',
                            action="autoassignment_forward",
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        ret = True

    return ret


def ignore_autoassignment_pin(user):
    '''
    This function checks the policy
        scope=enrollment, action=ignore_autoassignment_pin
    This is a boolean policy.
    The function returns true, if the password used in the autoassignment
    should not be set as token pin.
    '''
    ret = False
    client = _get_client()

    pol = get_client_policy(client, scope='enrollment',
                            action="ignore_autoassignment_pin",
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        ret = True

    return ret


def _getRandomOTPPINLength(user):
    '''
    This internal function returns the length of the random otp pin that is
    define in policy scope = enrollment, action = otp_pin_random = 111
    '''
    Realms = _getUserRealms(user)
    maxOTPPINLength = -1
    client = _get_client()

    for R in Realms:
        pol = get_client_policy(client,
                                scope='enrollment', action='otp_pin_random',
                                realm=R, user=user.login, userObj=user)
        if len(pol) == 0:
            log.debug("there is no scope=enrollment policy for Realm %r" % R)
            return -1

        OTPPINLength = getPolicyActionValue(pol, "otp_pin_random")

        # If there is a policy, with a higher random pin length
        log.debug("found policy with otp_pin_random = %r" % OTPPINLength)

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
        Realms = _getUserRealms(user)

    for R in Realms:
        pol = getPolicy({'scope': 'enrollment', 'realm': R,
                         'action': 'otp_pin_encrypt'})
        if 1 == getPolicyActionValue(pol, 'otp_pin_encrypt'):
            encrypt_pin = 1

    return encrypt_pin


def _getOTPPINPolicies(user, scope="selfservice"):
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
    client = _get_client()

    Realms = _getUserRealms(user)
    ret = {'min':-1, 'max':-1, 'contents': ""}

    log.debug("searching for OTP PIN policies in scope=%r policies." % scope)
    for R in Realms:

        pol = get_client_policy(client, scope=scope, realm=R,
                                user=user.login, userObj=user)
        if len(pol) == 0:
            log.debug("there is no scope=%r policy for Realm %r" % (scope, R))
            return ret

        pol = get_client_policy(client, scope=scope, realm=R,
                                action="otp_pin_maxlength",
                                user=user.login, userObj=user)
        n_max = getPolicyActionValue(pol, "otp_pin_maxlength")

        pol = get_client_policy(client, scope=scope, realm=R,
                                action="otp_pin_minlength",
                                user=user.login, userObj=user)
        n_min = getPolicyActionValue(pol, "otp_pin_minlength", max=False)

        pol = get_client_policy(client, scope=scope, realm=R,
                                action="otp_pin_contents",
                                user=user.login, userObj=user)
        n_contents = getPolicyActionValue(pol, "otp_pin_contents", is_string=True)

        # find the maximum length
        if (int(n_max) > ret['max']):
            ret['max'] = n_max

        # find the minimum length
        if (not n_min == -1):
            if (ret['min'] == -1):
                ret['min'] = n_min
            elif (n_min < ret['min']):
                ret['min'] = n_min

        # find all contents
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
    _ = context['translate']

    pol = _getOTPPINPolicies(user)
    log.debug("Policies: checking for otp_pin_minlength")
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

    log.debug("Policies: checking for otp_pin_contents")
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


def _getRandomPin(randomPINLength):
    newpin = ""
    log.debug("creating a random otp pin of length %r" % randomPINLength)
    chars = string.letters + string.digits
    for _i in range(randomPINLength):
        newpin = newpin + urandom.choice(chars)

    return newpin


def _checkAdminPolicyPre(method, param={}, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    serial = param.get("serial")
    if user is None:
        user = _getUserFromParam()

    realm = param.get("realm")
    if realm is None or len(realm) == 0:
        realm = _getDefaultRealm()

    if 'show' == method:

        # get the realms for this administrator
        policies = getAdminPolicies('')
        log.debug("[checkPolicyPre] The admin >%s< may manage the "
                  "following realms: %s" % (policies['admin'],
                                                policies['realms']))
        if policies['active'] and 0 == len(policies['realms']):
            log.error("[checkPolicyPre] The admin >%s< has no rights in "
                      "any realms!" % policies['admin'])
            raise PolicyException(_("You do not have any rights in any "
                                      "realm! Check the policies."))
        return {'realms': policies['realms'], 'admin': policies['admin'],
                "active": policies['active']}

    elif 'token_method' == method:

        # get the realms for this administrator
        policies = getAdminPolicies('token_method')
        log.debug("[checkPolicyPre] The admin >%s< may manage the "
                  "following realms: %s" % (policies['admin'],
                                            policies['realms']))
        if policies['active'] and 0 == len(policies['realms']):
            log.error("[checkPolicyPre] The admin >%s< has no rights in "
                      "any realms!" % policies['admin'])
            raise PolicyException(_("You do not have any rights in any "
                                    "realm! Check the policies."))
        return {'realms': policies['realms'], 'admin': policies['admin'],
                "active": policies['active']}

    elif 'remove' == method:
        policies = getAdminPolicies("remove")
        # FIXME: A token that belongs to multiple realms should not be
        #        deleted. Should it? If an admin has the right on this
        #        token, he might be allowed to delete it,
        #        even if the token is in other realms.
        # We could use fitAllRealms=True
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to remove token %s for "
                        "user %s@%s" % (policies['admin'], serial, user.login,
                                        user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to remove token %s. Check the "
                                  "policies.") % serial)

    elif 'enable' == method:
        policies = getAdminPolicies("enable")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("[enable] the admin >%s< is not allowed to enable "
                        "token %s for user %s@%s"
                        % (policies['admin'], serial,
                           user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to enable token %s. Check the "
                                  "policies.") % serial)

        if not _checkTokenNum():
            raise PolicyException(_("You may not enable any more tokens. "
                                  "Your maximum token number is "
                                  "reached!"))

        # We need to check which realm the token will be in.
        realmList = linotp.lib.token.getTokenRealms(serial)
        for r in realmList:
            if not _checkTokenNum(realm=r):
                raise PolicyException(_("You may not enable any more tokens "
                                      "in realm %s. Check the policy "
                                      "'tokencount'") % r)

    elif 'disable' == method:
        policies = getAdminPolicies("disable")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to disable token %s for"
                        " user %s@%s" % (policies['admin'], serial, user.login,
                                         user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to disable token %s. Check the "
                                  "policies.") % serial)

    elif 'copytokenpin' == method:
        policies = getAdminPolicies("copytokenpin")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to copy token pin of "
                        "token %s for user %s@%s" % (policies['admin'], serial,
                           user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to copy PIN of token %s. Check "
                                  "the policies.") % serial)

    elif 'copytokenuser' == method:
        policies = getAdminPolicies("copytokenuser")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to copy token user of "
                        "token %s for user %s@%s" % (policies['admin'], serial,
                           user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to copy user of token %s. Check "
                                  "the policies.") % serial)

    elif 'losttoken' == method:
        policies = getAdminPolicies("losttoken")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to run "
                        "the losttoken workflow for token %s for "
                        "user %s@%s" % (policies['admin'], serial,
                                        user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to run the losttoken workflow "
                                  "for token %s. Check the "
                                  "policies.") % serial)

    elif 'getotp' == method:
        policies = getAdminPolicies("getotp")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to run the getotp "
                        "workflow for token %s for user %s@%s"
                        % (policies['admin'], serial, user.login,
                           user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to run the getotp workflow for "
                                  "token %s. Check the policies.") % serial)

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

        from linotp.lib.support import check_license_restrictions
        if linotp.lib.support.check_license_restrictions():
            raise PolicyException(_("Due to license restrictions no more"
                                    " tokens could be enrolled!"))

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
                raise Exception(_("The tokentype '%s' could not be "
                                "found.") % ttype)

        # We need to assure, that an admin does not enroll a token into a
        # realm were he has no ACCESS! : -(
        # The admin may not enroll a token with a serial, that is already
        # assigned to a user outside of his realm

        # if a user is given, we need to check the realm of this user
        if (policies['active'] and
            (user.login != "" and not
             checkAdminAuthorization(policies, "", user))):
            log.warning("the admin >%s< is not allowed to enroll token %s of "
                        "type %s to user %s@%s" % (policies['admin'], serial,
                                                ttype, user.login, user.realm))

            raise PolicyException(_("You do not have the administrative "
                                  "right to init token %s of type %s to "
                                  "user %s@%s. Check the policies.")
                                  % (serial, ttype, user.login,
                                     user.realm))

        # no right to enroll token in any realm
        if policies['active'] and len(policies['realms']) == 0:
            log.warning("the admin >%s< is not allowed to enroll "
                        "a token at all." % (policies['admin']))
            raise PolicyException(_("You do not have the administrative "
                                  "right to enroll tokens. Check the "
                                  "policies."))

        # the token is assigned to a user, not in the realm of the admin!
        # we only need to check this, if the token already exists. If
        # this is a new token, we do not need to check this.
        if policies['active'] and linotp.lib.token.tokenExist(serial):
            if not checkAdminAuthorization(policies, serial, ""):
                log.warning("the admin >%s< is not allowed to enroll token %s "
                            "of type %s." % (policies['admin'], serial, ttype))
                raise PolicyException(_("You do not have the administrative "
                                      "right to init token %s of type %s.")
                                      % (serial, ttype))

        # Here we check, if the tokennum exceeded
        if not _checkTokenNum():
            log.error("The maximum token number is reached!")
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        # if a policy restricts the tokennumber for a realm
        for R in policies['realms']:
            if not _checkTokenNum(realm=R):
                log.warning("the admin >%s< is not allowed to enroll any more "
                            "tokens for the realm %s" % (policies['admin'], R))
                raise PolicyException(_("The maximum allowed number of "
                                      "tokens for the realm %s was "
                                      "reached. You can not init any more "
                                      "tokens. Check the policies "
                                      "scope=enrollment, "
                                      "action=tokencount.") % R)

        if not _checkTokenNum(user=user):
            log.warning("the admin >%s< is not allowed to enroll any more "
                        "tokens for the realm %s" %
                        (policies['admin'], user.realm))
            raise PolicyException(_("The maximum allowed number of tokens "
                                  "for the realm %s was reached. You can "
                                  "not init any more tokens. Check the "
                                  "policies scope=enrollment, "
                                  "action=tokencount.") % user.realm)

        # if a policy restricts the tokennumber for the user in a realm
        if not _checkTokenAssigned(user):
            log.warning("the maximum number of allowed tokens per user is "
                        "exceeded. Check the policies")
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "per user is exceeded. Check the "
                                  "policies scope=enrollment, "
                                  "action=maxtoken"))
        # ==== End of policy check 'init' ======
        ret['realms'] = policies['realms']

    elif 'unassign' == method:
        policies = getAdminPolicies("unassign")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to unassign token %s "
                        "for user %s@%s" % (policies['admin'], serial,
                                            user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to unassign token %s. Check the "
                                  "policies.") % serial)

    elif 'assign' == method:
        policies = getAdminPolicies("assign")

        # the token is assigned to a user, not in the realm of the admin!
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, "")):
            log.warning("the admin >%s< is not allowed to assign token %s. "
                        % (policies['admin'], serial))
            raise PolicyException(_("You do not have the administrative "
                                  "right to assign token %s. "
                                  "Check the policies.") % (serial))

        # The user, the token should be assigned to,
        # is not in the admins realm
        if (policies['active'] and not
                checkAdminAuthorization(policies, "", user)):
            log.warning("the admin >%s< is not allowed to assign "
                        "token %s for user %s@%s" % (policies['admin'],
                                                     serial, user.login,
                                                     user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to assign token %s. Check the "
                                  "policies.") % serial)

        # check the number of assigned tokens
        if not _checkTokenAssigned(user):
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
            policies1 = getAdminPolicies("setSCPIN")
            policies2 = getAdminPolicies("setMOTPPIN")
            if ((policies1['active'] and not
                    (checkAdminAuthorization(policies1, serial,
                                             User("", "", ""))))
                    or (policies2['active'] and not
                    (checkAdminAuthorization(policies2, serial,
                                             User("", "", ""))))):
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
            policies = getAdminPolicies("setSCPIN")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial,
                                            User("", "", ""))):
                log.warning("the admin >%s< is not allowed to setPIN for "
                            "token %s." % (policies['admin'], serial))
                raise PolicyException(_("You do not have the administrative "
                                      "right to set Smartcard PIN for "
                                      "token %s. Check the policies.")
                                      % serial)

    elif 'set' == method:

        if "pin" in param:
            policies = getAdminPolicies("setOTPPIN")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
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
            policies = getAdminPolicies("set")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):
                log.warning("the admin >%s< is not allowed to set "
                            "token properites for %s for user %s@%s"
                            % (policies['admin'], serial,
                               user.login, user.realm))
                raise PolicyException(_("You do not have the administrative "
                                      "right to set token properties for "
                                      "%s. Check the policies.") % serial)

    elif 'resync' == method:

        policies = getAdminPolicies("resync")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to resync token %s for "
                        "user %s@%s" % (policies['admin'], serial,
                                        user.login, user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to resync token %s. Check the "
                                  "policies.") % serial)

    elif 'userlist' == method:
        policies = getAdminPolicies("userlist")
        # check if the admin may view the users in this realm
        if (policies['active'] and
                not checkAdminAuthorization(policies, "", user)):
            log.warning("the admin >%s< is not allowed to list"
                        " users in realm %s(%s)!"
                        % (policies['admin'], user.realm,
                           user.resolver_config_identifier))
            raise PolicyException(_("You do not have the administrative"
                                  " right to list users in realm %s(%s).")
                                  % (user.realm,
                                  user.resolver_config_identifier))

    elif 'tokenowner' == method:
        policies = getAdminPolicies("tokenowner")
        # check if the admin may view the users in this realm
        if (policies['active'] and
                not checkAdminAuthorization(policies, "", user)):
            log.warning("the admin >%s< is not allowed to get"
                        " the token owner in realm %s(%s)!"
                        % (policies['admin'], user.realm,
                        user.resolver_config_identifier))
            raise PolicyException(_("You do not have the administrative"
                                  " right to get the token owner in realm"
                                  " %s(%s).") % (user.realm,
                                  user.resolver_config_identifier))

    elif 'checkstatus' == method:
        policies = getAdminPolicies("checkstatus")
        # check if the admin may view the users in this realm
        if (policies['active'] and not
                checkAdminAuthorization(policies, "", user)):
            log.warning("the admin >%s< is not allowed to show status of token"
                        " challenges in realm %s(%s)!"
                        % (policies['admin'], user.realm,
                        user.resolver_config_identifier))
            raise PolicyException(_("You do not have the administrative "
                                  "right to show status of token "
                                  "challenges in realm "
                                  "%s(%s).") % (user.realm,
                                  user.resolver_config_identifier))

    elif 'tokenrealm' == method:
        # The admin needs to have the right "manageToken" for all realms,
        # the token is currently in and all realm the Token should go into.
        policies = getAdminPolicies("manageToken")

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
                                        User("dummy", r, None))):
                log.warning("the admin >%s< is not allowed "
                            "to manage tokens in realm %s"
                            % (policies['admin'], r))
                raise PolicyException(_("You do not have the administrative "
                                      "right to remove tokens from realm "
                                      "%s. Check the policies.") % r)

        for r in realmNewList:
            if (policies['active'] and not
                checkAdminAuthorization(policies, None,
                                        User("dummy", r, None))):
                log.warning("the admin >%s< is not allowed "
                            "to manage tokens in realm %s"
                            % (policies['admin'], r))
                raise PolicyException(_("You do not have the administrative "
                                      "right to add tokens to realm %s. "
                                      "Check the policies.") % r)

            if not _checkTokenNum(realm=r):
                log.warning("the maximum tokens for the "
                            "realm %s is exceeded." % r)
                raise PolicyException(_("You may not put any more tokens in "
                                      "realm %s. Check the policy "
                                      "'tokencount'") % r)

    elif 'reset' == method:

        policies = getAdminPolicies("reset")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):
            log.warning("the admin >%s< is not allowed to reset "
                        "token %s for user %s@%s" % (policies['admin'],
                                                     serial, user.login,
                                                     user.realm))
            raise PolicyException(_("You do not have the administrative "
                                  "right to reset token %s. Check the "
                                  "policies.") % serial)

    elif 'import' == method:
        policies = getAdminPolicies("import")
        # no right to import token in any realm
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
        policies = getAdminPolicies("import")
        if policies['active'] and tokenrealm not in policies['realms']:
            log.warning("the admin >%s< is not allowed to "
                        "import token files to realm %s: %s"
                        % (policies['admin'], tokenrealm, policies))
            raise PolicyException(_("You do not have the administrative "
                                  "right to import token files to realm %s"
                                  ". Check the policies.") % tokenrealm)

        if not _checkTokenNum(realm=tokenrealm):
            log.warning("the maximum tokens for the realm "
                        "%s is exceeded." % tokenrealm)
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "in realm %s is exceeded. Check policy "
                                  "tokencount!") % tokenrealm)

    else:
        # unknown method
        raise PolicyException(_("Failed to run checkPolicyPre. "
                              "Unknown method: %s") % method)

    return ret


def checkAuthorisation(scope, method):
    """
    check if the authenticated user has the right to do the given action
    :param scope: scope of the policy to be checked
    :param method: the requested action
    :return: nothing if authorized, else raise PolicyException
    """
    _ = context['translate']

    auth = _getAuthorization(scope, method)
    if auth['active'] and not auth['auth']:
        log.warning("the user >%r< is not allowed to "
                    "do %s" % (auth['admin'], scope))

        ret = _("You do not have the administrative right to do this. "
                "You are missing a policy scope=%s, action=%s") % (scope, method)

        raise PolicyException(ret)


def _checkGetTokenPolicyPre(method, param={}, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    if 'max_count' == method[0: len('max_count')]:
        ret = 0
        serial = param.get("serial")
        ttype = linotp.lib.token.getTokenType(serial).lower()
        trealms = linotp.lib.token.getTokenRealms(serial)
        pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")
        admin_user = _getAuthenticatedUser()
        if pol_action == "":
            raise PolicyException(_("There is no policy gettoken/"
                                  "max_count definable for the "
                                  "tokentype %r") % ttype)

        policies = {}
        for realm in trealms:
            pol = getPolicy({'scope': 'gettoken', 'realm': realm,
                             'user': admin_user['login'],
                             'action': pol_action})

            policies.update(pol)

        value = getPolicyActionValue(policies, pol_action)
        ret = value

    return ret


def _checkAuditPolicyPre(method, param={}, authUser=None, user=None):

    ret = {}
    _ = context['translate']

    if 'view' == method:
        auth = _getAuthorization("audit", "view")
        if auth['active'] and not auth['auth']:
            log.warning("the admin >%r< is not allowed to "
                        "view the audit trail" % auth['admin'])

            ret = _("You do not have the administrative right to view the "
                   "audit trail. You are missing a policy "
                   "scope=audit, action=view")
            raise PolicyException(ret)
    else:
        raise PolicyException(_("Failed to run checkPolicyPre. Unknown "
                              "method: %s") % method)

    return ret


def _checkManagePolicyPre(method, param={}, authUser=None, user=None):
    controller = 'manage'
    ret = {}
    return ret


def checkToolsAuthorisation(method, param={}):
    # TODO: fix the semantic of the realm in the policy!

    auth_user = context['AuthUser']

    _checkToolsPolicyPre(method, param=param, authUser=auth_user, user=None)


def _checkToolsPolicyPre(method, param={}, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    auth = _getAuthorization("tools", method)
    if auth['active'] and not auth['auth']:
        log.warning("the admin >%r< is not allowed to "
                    "view the audit trail" % auth['admin'])

        ret = _("You do not have the administrative right to manage tools. "
               "You are missing a policy scope=tools, action=%s") % method

        raise PolicyException(ret)


def _checkSelfservicePolicyPre(method, param={}, authUser=None, user=None):

    ret = {}
    _ = context['translate']
    controller = 'selfservice'
    client = _get_client()


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
                                     userObj=authUser)
        if policies == {}:
            raise PolicyException(_("There is no policy selfservice/"
                                  "max_count defined for the tokentype "
                                  "%s in realm %s.") % (ttype, urealm))

        value = getPolicyActionValue(policies, pol_action)
        ret = value

    elif 'usersetpin' == method:

        if not 'setOTPPIN' in getSelfserviceActions(authUser):
            log.warning("user %s@%s is not allowed to call this function!" %
                        (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userreset' == method:

        if not 'reset' in getSelfserviceActions(authUser):
            log.warning("user %s@%s is not allowed to call this function!" %
                        (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userresync' == method:

        if not 'resync' in getSelfserviceActions(authUser):
            log.warning("user %s@%s is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'usersetmpin' == method:

        if not 'setMOTPPIN' in getSelfserviceActions(authUser):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'useractivateocratoken' == method:
        user_selfservice_actions = getSelfserviceActions(authUser)
        typ = param.get('type').lower()
        if (typ == 'ocra'
                and 'activateQR' not in user_selfservice_actions):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'useractivateocra2token' == method:
        user_selfservice_actions = getSelfserviceActions(authUser)
        typ = param.get('type').lower()
        if (typ == 'ocra2'
                and 'activateQR2' not in user_selfservice_actions):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userassign' == method:

        if not 'assign' in getSelfserviceActions(authUser):
            log.warning("user %r@%r is not allowed to call "
                        "this function!" % (authUser.login,
                                            authUser.realm))
            raise PolicyException(_('The policy settings do not allow '
                                  'you to issue this request!'))

        # Here we check, if the tokennum exceeds the tokens
        if not _checkTokenNum():
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        if not _checkTokenAssigned(authUser):
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    elif 'usergetserialbyotp' == method:

        if not 'getserial' in getSelfserviceActions(authUser):
            log.warning("user %s@%s is not allowed to call this function!" %
                        (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you to'
                                  ' request a serial by OTP!'))

    elif 'userdisable' == method:

        if not 'disable' in getSelfserviceActions(authUser):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userenable' == method:

        if not 'enable' in getSelfserviceActions(authUser):
            log.warning("user %s@%s is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you to'
                                  ' issue this request!'))

    elif 'userunassign' == method:

        if not 'unassign' in getSelfserviceActions(authUser):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userdelete' == method:

        if not 'delete' in getSelfserviceActions(authUser):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

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
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _checkTokenNum():
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        if not _checkTokenAssigned(authUser):
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    elif 'userhistory' == method:
        if not 'history' in getSelfserviceActions(authUser):
            log.warning("user %r@%r is not allowed to call this function!"
                        % (authUser.login, authUser.realm))
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif 'userinit' == method:

        allowed_actions = getSelfserviceActions(authUser)
        typ = param['type'].lower()
        meth = 'enroll' + typ.upper()

        if meth not in allowed_actions:
            log.warning("user %r@%r is not allowed to enroll %s!"
                        % (authUser.login, authUser.realm, typ))
            raise PolicyException(_('The policy settings do not allow '
                                  'you to issue this request!'))

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _checkTokenNum():
            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        if not _checkTokenAssigned(authUser):
            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    else:
        log.error("Unknown method in selfservice: %s" % method)
        raise PolicyException(_("Unknown method in selfservice: %s") % method)

    return ret


def _checkSystemPolicyPre(method, param={}, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    if method not in SYSTEM_ACTIONS:
        log.error("an unknown method was passed in system: %s" % method)
        raise PolicyException(_("Failed to run checkPolicyPre. "
                              "Unknown method: %s") % method)

    auth = _getAuthorization(scope='system', action=SYSTEM_ACTIONS[method])

    if auth['active'] and not auth['auth']:
        log.warning("admin >%s< is not authorited to %s."
                    " Missing policy scope=system, action=%s"
                    % (auth['admin'], method, SYSTEM_ACTIONS[method]))

        raise PolicyException(_("Policy check failed. You are not allowed "
                              "to %s system config.") % SYSTEM_ACTIONS[method])

    return ret


def _checkOcraPolicyPre(method, param={}, authUser=None, user=None):

    ret = {}
    _ = context['translate']
    client = _get_client()

    method_map = {'request': 'request', 'status': 'checkstatus',
                  'activationcode': 'getActivationCode',
                  'calcOTP': 'calculateOtp'}

    admin_user = _getAuthenticatedUser()
    policies = getPolicy({'user': admin_user.get('login'), 'scope': 'ocra',
                          'action': method, 'client': client})

    if len(policies) == 0:
        log.warning("the admin >%r< is not allowed to do an ocra/%r"
                    % (admin_user.get('login'), method_map.get(method)))
        raise PolicyException(_("You do not have the administrative right to"
                              " do an ocra/%s") % method_map.get(method))

    return ret


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
    _ = context["translate"]

    if 'admin' == controller:
        ret = _checkAdminPolicyPre(method=method, param=param,
                                   authUser=authUser, user=user)

    elif 'gettoken' == controller:
        ret = _checkGetTokenPolicyPre(method=method, param=param,
                                      authUser=authUser, user=user)
    elif 'audit' == controller:
        ret = _checkAuditPolicyPre(method=method, param=param,
                                   authUser=authUser, user=user)

    elif 'manage' == controller:
        ret = _checkManagePolicyPre(method=method, param=param,
                                    authUser=authUser, user=user)

    elif controller in ['tools']:
        ret = _checkToolsPolicyPre(method=method, param=param,
                                   authUser=authUser, user=user)

    elif 'selfservice' == controller:
        ret = _checkSelfservicePolicyPre(method=method, param=param,
                                         authUser=authUser, user=user)

    elif 'system' == controller:
        ret = _checkSystemPolicyPre(method=method, param=param,
                                    authUser=authUser, user=user)

    elif controller == 'ocra':
        ret = _checkOcraPolicyPre(method=method, param=param,
                                  authUser=authUser, user=user)

    else:
        # unknown controller
        raise PolicyException(_("Failed to run getPolicyPre. Unknown "
                              "controller: %s") % controller)

    return ret


##############################################################################
def _checkAdminPolicyPost(method, param=None, user=None):
    ret = {}
    controller = 'admin'
    _ = context['translate']

    log.debug("using params %s" % param)
    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam()

    if method in ['init', 'assign', 'setPin', 'loadtokens']:
        # check if we are supposed to genereate a random OTP PIN
        randomPINLength = _getRandomOTPPINLength(user)

        if randomPINLength > 0:
            newpin = _getRandomPin(randomPINLength)
            log.debug("setting random pin for token with serial %s and user: "
                      "%s" % (serial, user))
            linotp.lib.token.setPin(newpin, None, serial)
            # TODO: This random PIN could be processed and
            # printed in a PIN letter

        if method == 'assign':
            if not _checkTokenNum(realm=user.realm, post_check=True):
                admin = context['AuthUser']
                log.warning("the admin >%s< is not allowed to enroll any more "
                            "tokens for the realm %s", admin, user.realm)
                raise PolicyException(_("The maximum allowed number of tokens "
                                      "for the realm %s was reached. You can "
                                      "not init any more tokens. Check the "
                                      "policies scope=enrollment, "
                                      "action=tokencount.") % user.realm)

    elif 'getserial' == method:
        # check if the serial/token, that was returned is in
        # the realms of the admin!
        policies = getAdminPolicies("getserial")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial,
                                        User('', '', ''))):
            log.warning("the admin >%s< is not allowed to get "
                        "serial of token %s" % (policies['admin'], serial))
            raise PolicyException(_("You do not have the administrative "
                                  "right to get serials from this realm!"))
    else:
        # unknown method
        raise PolicyException(_("Failed to run getPolicyPost. "
                              "Unknown method: %s") % method)
    return ret


def _checkSystemPolicyPost(method, param=None, user=None):

    ret = {}
    controller = 'system'
    _ = context['translate']

    if 'getRealms' == method:
        systemReadRights = False
        res = param['realms']
        auth = _getAuthorization('system', 'read')
        if auth['auth']:
            systemReadRights = True

        if not systemReadRights:
            # If the admin is not allowed to see all realms,
            # (policy scope=system, action=read)
            # the realms, where he has no administrative rights need,
            # to be stripped.
            pol = getAdminPolicies('')
            if pol['active']:

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


def _checkSelfservicePolicyPost(method, param=None, user=None):

    ret = {}
    _ = context['translate']
    controller = 'selfservice'

    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam()

    if 'enroll' == method:
        # check if we are supposed to genereate a random OTP PIN
        randomPINLength = _getRandomOTPPINLength(user)
        if randomPINLength > 0:
            newpin = _getRandomPin(randomPINLength)
            log.debug("setting random pin for token with serial "
                      "%s and user: %s" % (serial, user))
            linotp.lib.token.setPin(newpin, None, serial)
            # TODO: This random PIN could be processed and
            # printed in a PIN letter

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
    _ = context['translate']

    if param is None:
        param = {}

    if 'admin' == controller:
        ret = _checkAdminPolicyPost(method, param=param, user=user)

    elif 'system' == controller:
        ret = _checkSystemPolicyPost(method, param=param, user=user)

    elif 'selfservice' == controller:
        ret = _checkSelfservicePolicyPost(method, param=param, user=user)

    else:
        # unknown controller
        raise PolicyException(_("Failed to run getPolicyPost. "
                              "Unknown controller: %s") % controller)

    return ret


###############################################################################
#
# Client Policies
#

def split_value(policy, attribute="client", marks=False):
    # This function returns the parameter "client" or
    # "user" in a policy as an array
    attrs = policy.get(attribute, "")
    if attrs == "None" or attrs is None:
        attrs = ""
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

    4. if nothing matched so far, we try the extended policy check

    '''
    Policies = {}

    param = {}

    if scope:
        param["scope"] = scope
    if action:
        param["action"] = action
    if realm:
        param["realm"] = realm

    Pols = getPolicy(param)

    # 1. Find a policy with this client
    for pol, policy in Pols.items():
        clients_array = split_value(policy, attribute="client")
        log.debug("[get_client_policy] the policy %s has these clients: %s. "
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
            if len(split_value(policy, attribute="client")) == 0:
                Policies[pol] = policy

    if not Policies:
        return Policies

    if user or userObj:
        if not userObj:
            userObj = User(login=user, realm=realm)

        # filter the policies for the user
        Policies = _user_filter(Policies, userObj, scope, find_resolver)

    return Policies


def _user_filter(Policies, userObj, scope, find_resolver=True):
    # 2. Within those policies select the policy with the user.
    #     if there is a policy with this very user, return only
    #     these policies, otherwise return all policies
    exact_matched_policies = {}
    matched_policies = {}
    default_policies = {}
    ext_policies = {}

    user = userObj.login
    realm = userObj.realm

    for polname, pol in Policies.items():
        policy_users = split_value(pol, attribute="user")

        if not policy_users:
            default_policies[polname] = pol
            continue

        if '*' not in policy_users and user in policy_users:
            exact_matched_policies[polname] = pol
        elif '*' in policy_users:
            matched_policies[polname] = pol
        else:
            ext_policies[polname] = pol

    if exact_matched_policies:
        return exact_matched_policies

    if matched_policies:
        return matched_policies

    if not find_resolver:
        return default_policies

    # 3. If no user specific policy was found, we now take a look,
    #    if we find a policy with the matching resolver.
    (matched_policies,
     empty_policies,
     ext_resolver_policies) = _user_filter_for_resolver(default_policies,
                                                        userObj)

    if matched_policies:
        return matched_policies

    if empty_policies:
        return empty_policies

    # 4. if nothing matched before and there are extended user filter
    #    definitions, try these out - but only in scope 'selfservice'
    if ext_resolver_policies or ext_policies and scope in ['selfservice']:
        ext_policies.update(ext_resolver_policies)
        (matched_policies,
         default_policies) = _user_filter_extended(ext_policies, userObj)

        # we found something so we return it
        if matched_policies:
            return matched_policies

    return {}


def _user_filter_extended(Policies, userObj):
    """
    check for extended user search expressions

    cases are:
        *@domain#key     + *@domain#key==val
        res:#key         + res:#key==val

    :param Policies: the input policies
    :param userObj: the user as User class Object
    :return: tuple of matched and empty policies
    """
    matched_policies = {}
    empty_policies = {}

    for polname, pol in Policies.items():
        extended_user_def = pol.get("user").split(',')

        for user_def in extended_user_def:
            user_def = user_def.strip()
            res = None

            # check if there is an attribute filter in defintion
            if '#' in user_def:
                attr_comp = AttributeCompare()
                res = attr_comp.compare(userObj, user_def)

            # if no attribute filter we support as well domain filter
            elif "@" in user_def:
                domain_comp = UserDomainCompare()
                res = domain_comp.compare(userObj, user_def)

            # if there is an : in the user, we compare the resolver
            elif ":" in user_def:
                domain_comp = UserDomainCompare()
                res = domain_comp.compare(userObj, user_def)

            # any other filter is returned as ignored
            else:
                empty_policies[polname] = pol
                continue

            if res is True:
                matched_policies[polname] = pol
            elif res is False:
                log.debug("policy %s faild to matched policies", polname)

    return matched_policies, empty_policies


def _user_filter_for_resolver(Policies, userObj):
    """
    check if user matches with a policy user defintion like 'resolver:'

    :param Policies: the to be processed policies
    :param userObj: the user as User class object
    :return: tuple of matched and unmatched policies
    """

    matched_policies = {}
    empty_policies = {}
    ext_resolver_policies = {}

    # get the resolver of the user in the realm and search for this
    # resolver list in the policies. Therefore we trim the user resolver
    # e.g. 'useridresolver.LDAPIdResolver.IdResolver.local'
    # to its shortname 'local' and preserve this as set for the intersection
    # with the resolver defintion

    resolvers_of_user = set()
    for resolver in getResolversOfUser(userObj):
        reso = resolver.split('.')[-1]
        resolvers_of_user.add(reso)

    for polname, pol in Policies.items():
        resolver_def = set(split_value(pol, attribute="user", marks=True))

        # are there any resolver definitions in the policy
        if not resolver_def:
            empty_policies[polname] = pol
            continue

        # there might be some resolver prefixed by user like *.reso1:
        # thus we extract the resolver as the last part before the last '.'
        for reso_def in resolver_def:
            sub_resolvers = set()
            if '.' in reso_def:
                sub_resolvers.add(reso_def.split('.')[-1])

        # if we have some, intersect them with the user resolvers
        if resolver_def & resolvers_of_user:
            matched_policies[polname] = pol

        # or if we have some sub-resolvers, intersect them
        elif sub_resolvers & resolvers_of_user:
            ext_resolver_policies[polname] = pol

        # if no intersection match, write a short log output
        else:
            log.debug("policy %s contains only resolvers (%r) other than %r",
                      polname, resolver_def, resolvers_of_user)

    # return the identified Policies and if they are default
    return matched_policies, empty_policies, ext_resolver_policies


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

    client = _get_client()

    log.debug("Realm overwrite: users %s original realm is %s" % (login, realm))
    policies = get_client_policy(client, scope="authorization",
                                 action="setrealm", realm=realm,
                                 user=login, find_resolver=False)

    if len(policies):
        realm = getPolicyActionValue(policies, "setrealm", is_string=True)

    log.debug("Realm overwrite: users %s new realm is %s" % (login, realm))
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
    client = _get_client()

    # if there is absolutely NO policy in scope authorization,
    # we return immediately
    if len(getPolicy({"scope": "authorization", "action": "authorize"})) == 0:
        log.debug("absolutely no authorization policy.")
        return True

    policies = get_client_policy(client, scope="authorization",
                                 action="authorize", realm=realm, user=login)

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
    client = _get_client()

    pol = get_client_policy(client, scope="authentication",
                            action="passthru", realm=user.realm,
                            user=user.login, userObj=user)
    if len(pol) > 0:
        ret = True
    return ret


def get_auth_forward(user):
    '''
    returns the list of all forwarding servers
    '''
    client = _get_client()

    pol = get_client_policy(client, scope="authentication",
                            action="forward_server", realm=user.realm,
                            user=user.login, userObj=user)
    if not pol:
        return None

    servers = getPolicyActionValue(pol, "forward_server", is_string=True)

    return servers


def get_auth_passOnNoToken(user):
    '''
    returns True, if the user in this realm should be always authenticated
    in case the user has no tokens assigned.
    '''
    ret = False
    client = _get_client()

    pol = get_client_policy(client, scope="authentication",
                            action="passOnNoToken", realm=user.realm,
                            user=user.login, userObj=user)
    if len(pol) > 0:
        ret = True
    return ret


def disable_on_authentication_exceed(user, realms=None):
    '''
    returns True if the token should be disable, if max auth count is reached
    '''
    ret = False
    client = _get_client()

    if user.login:
        pol = get_client_policy(client, scope="authentication",
                                action="disable_on_authentication_exceed",
                                realm=user.realm,
                                user=user.login, userObj=user)
        if len(pol) > 0:
            return True
    else:
        for realm in realms:
            pol = get_client_policy(client, scope="authentication",
                                    action="disable_on_authentication_exceed",
                                    realm=realm)
            if len(pol) > 0:
                return True

    return False


def delete_on_authentication_exceed(user, realms=None):
    '''
    returns True if the token should be disable, if max auth count is reached
    '''

    client = _get_client()

    if user.login:
        pol = get_client_policy(client, scope="authentication",
                                action="delete_on_authentication_exceed",
                                realm=user.realm,
                                user=user.login, userObj=user)
        if len(pol) > 0:
            return True

    else:
        for realm in realms:
            pol = get_client_policy(client, scope="authentication",
                                    action="delete_on_authentication_exceed",
                                    realm=realm)
            if len(pol) > 0:
                return True

    return False


def trigger_sms(realms=None):
    """
    returns true, if a check_s should be allowed to trigger an sms
    """
    client = _get_client()
    user = _getUserFromParam()

    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = get_client_policy(client, scope="authentication",
                                action="trigger_sms", realm=realm,
                                user=login, userObj=user)

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
    client = _get_client()

    user = _getUserFromParam()
    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = get_client_policy(client, scope="authentication",
                                action="autosms", realm=realm,
                                user=login, userObj=user)

        if len(pol) > 0:
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

    client = _get_client()

    pol = get_client_policy(client, scope="authentication",
                            action="challenge_response",
                            realm=p_realm,
                            user=p_user, userObj=user)

    Token_Types = getPolicyActionValue(pol, "challenge_response", is_string=True)
    token_types = [t.lower() for t in Token_Types.split()]

    if ttype.lower() in token_types or '*' in token_types:
        ret = True

    return ret


def _get_auth_PinPolicy(realm=None, user=None):
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

    '''
        policy value mapping - from policy defintion:
            'value': [0, 1, 2, "token_pin", "password", "only_otp"],
    '''
    pin_policy_lookup = {
        "token_pin": 0,
        'password': 1,
        "only_otp": 2,
    }

    client = _get_client()

    if user is None:
        user = _getUserFromParam()
    login = user.login
    if realm is None:
        realm = user.realm or _getDefaultRealm()

    pol = get_client_policy(client, scope="authentication", action="otppin",
                            realm=realm, user=login, userObj=user)

    pin_check = getPolicyActionValue(pol, "otppin", max=False)

    # we map the named values back, to provide interface compatibility
    if pin_check in pin_policy_lookup:
        pin_check = pin_policy_lookup[pin_check]

    return pin_check


def get_qrtan_url(realms):
    '''
    Returns the URL for the half automatic mode for the QR TAN token
    for the given realm

    :remark: there might be more than one url, if the token
             belongs to more than one realm

    :param realms: list of realms or None

    :return: url string

    '''
    url = ''
    urls = []

    if realms is None:
        realms = []

    for realm in realms:
        pol = getPolicy({"scope": "authentication", 'realm': realm,
                         'action': "qrtanurl"})
        url = getPolicyActionValue(pol, "qrtanurl", is_string=True)
        if url:
            urls.append(url)

    if len(urls) > 1:
        raise Exception('multiple enrollement urls %r found for realm set: %r'
                        % (urls, realms))

    log.debug("got qrtan callback url %s for realms %r" % (url, realms))
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

    _ = context['translate']

    if serial is None:
        # if no serial is given, we return True right away
        log.debug("We have got no serial. Obviously doing passthru.")
        return True

    client = _get_client()

    if user is None:
        user = _getUserFromParam()
    login = user.login
    realm = user.realm or _getDefaultRealm()
    tokentypes = []
    tokentype = ""
    res = False

    pol = get_client_policy(client, scope="authorization", action="tokentype",
                            realm=realm, user=login, userObj=user)

    t_type = getPolicyActionValue(pol, "tokentype", max=False, is_string=True)
    if len(t_type) > 0:
        tokentypes = [t.strip() for t in t_type.lower().split(" ")]

    toks = linotp.lib.token.getTokens4UserOrSerial(None, serial)
    if len(toks) > 1:
        raise PolicyException(_("multiple tokens found - "
                              "cannot determine tokentype!"))
    elif len(toks) == 1:
        tokentype = toks[0].getType().lower()

        if (tokentype in tokentypes or '*' in tokentypes or
           len(tokentypes) == 0):
            res = True
    elif len(toks) == 0:
        # TODO if the user does not exist or does have no token
        # ---- WHAT DO WE DO? ---
        #  At the moment we pass through: This is the old behaviour...
        res = True

    if res is False and exception:
        context['audit']["action_detail"] = \
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

    if serial is None:
        # if no serial is given, we return True right away
        log.debug("We have got no serial. Obviously doing passthru.")
        return True

    client = _get_client()

    if user is None:
        user = _getUserFromParam()
    login = user.login
    realm = user.realm or _getDefaultRealm()
    res = False

    pol = get_client_policy(client, scope="authorization", action="serial",
                            realm=realm, user=login, userObj=user)
    if len(pol) == 0:
        # No policy found, so we skip the rest
        log.debug("No policy scope=authorize, action=serial for user %r, "
                  "realm %r, client %r" % (login, realm, client))
        return True

    # extract the value from the policy
    serial_regexp = getPolicyActionValue(pol, "serial", max=False, is_string=True)

    if re.search(serial_regexp, serial):
        res = True

    if res is False and exception:
        context['audit']["action_detail"] = ("failed due to authorization/"
                                            "serial policy")
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

    client = _get_client()

    if user is None:
        user = _getUserFromParam()

    login = user.login
    realm = user.realm or _getDefaultRealm()
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

    pin_policies.append(_get_auth_PinPolicy(user=user))
    pin_policies = list(set(pin_policies))

    if len(pin_policies) > 1:
        msg = ("conflicting authentication polices. "
               "Check scope=authentication. policies: %r" % pin_policies)

        log.error("[__checkToken] %r" % msg)
        # self.context.audit['action_detail'] = msg
        raise Exception('multiple pin policies found')
        # # former return -2

    return pin_policies


def check_token_reporting(realm):
    """
    parse reporting policies for given realm and user
    :param realm: the realm to be reported
    :return: list of status like [assigned, active&unassigned, total]
    """

    if not realm:
        realm = None

    report_policies = getPolicy({'scope': 'reporting', 'realm': realm})
    actions = []
    for polname, policy in report_policies.items():
        action = policy.get('action', '')
        action = str(action)
        action = action.split(',')
        for act in action:
            if 'token_total' in act:
                actions.append('total')
            if 'token_status' in act:
                status = act.split('=')
                actions.append(status[1])
            if act is '*':
                status = ['active', 'inactive', 'assigned', 'unassigned',
                          'active&assigned', 'active&unassigned',
                          'inactive&assigned', 'inactive&unassigned', 'total']
                for stat in status:
                    actions.append(unicode(stat))
    return actions


def supports_offline(realms, token):

    """
    Check if offline is allowed for the given token.

    :param realms: the realms to be checked
    :param token: the token to be checked

    :returns bool
    """

    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    for realm in realms:
        policy = getPolicy({"scope": "authentication", 'realm': realm,
                            'action': 'support_offline'})
        action_value = getPolicyActionValue(policy, 'support_offline',
                                            is_string=True)
        if action_value:
            token_types = action_value.split()
            if token.getType() in token_types:
                return True

    return False


def get_partition(realms, user):
    """
    returns the partition (key pair identifier) that should be used
    """
    action_values = []
    login = None
    ret = 0

    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    action = 'partition'

    params = {'scope': 'enrollment',
              'action': action}

    for realm in realms:
        params['realm'] = realm
        if login:
            params['user'] = login

        policy = getPolicy(params)
        action_value = getPolicyActionValue(policy, action,
                                            is_string=True)
        if action_value:
            action_values.append(action_value)

    if len(action_values) > 1:
        for value in action_values:
            if value != action_values[0]:
                raise Exception('conflicting policy values %r found for '
                                'realm set: %r' % (action_values, realms))
    if action_values:
        ret = int(action_values[0])

    return ret


def get_single_auth_policy(policy_name, user=None, realms=None):
    """
    Retrieves a policy value and checks if the value is consistent
    across realms.

    :param policy_name: the name of the policy, e.g:
        * qrtoken_pairing_callback_url
        * qrtoken_pairing_callback_sms
        * qrtoken_challenge_response_url
        * qrtoken_challenge_response_sms

    :param realms: the realms that his policy should be effective in
    """

    action_values = []
    login = None
    ret = None

    if user and user.login and user.realm:
        realms = [user.realm]
        login = user.login

    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    params = {"scope": "authentication",
              'action': policy_name}

    for realm in realms:
        params['realm'] = realm
        if login:
            params['user'] = login

        policy = getPolicy(params)
        action_value = getPolicyActionValue(policy, policy_name,
                                            is_string=True)
        if action_value:
            action_values.append(action_value)

    if len(action_values) > 1:
        for value in action_values:
            if value != action_values[0]:
                raise Exception('conflicting policy values %r found for '
                                'realm set: %r' % (action_values, realms))
    if action_values:
        ret = action_values[0]

    return ret
# eof ##########################################################################
