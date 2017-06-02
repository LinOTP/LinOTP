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
""" static policy definitions """


from linotp.lib.context import request_context

SYSTEM_ACTIONS = {
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
    'setProvider': 'write',
    'setDefaultProvider': 'write',
    'delProvider': 'write',
    'getProvider': 'read', }


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
            'tokenowner': {'type': 'bool'},
            'token_method': {'type': 'bool'},
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
                },
            'show': {'type': 'bool'},
            'unpair': {'type': 'bool'},
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
                'desc': 'Allow to search an unassigned token by OTP value.'},
            'otpLogin': {
                'type': 'bool',
                'desc': 'Requires OTP for selfservice authentication'},
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
            'tokenissuer': {
                 'type': 'str',
                 'desc': 'the issuer label for the google authenticator.'},

            'autoenrollment': {
                'type': 'str',
                'desc': 'users can enroll a token just by using the '
                        'pin to authenticate and will an otp for authentication'},
            'autoassignment_forward': {
                'type': 'bool',
                'desc': 'in case of an autoassignement with a remotetoken, '
                        'the credentials are forwarded'},
            'autoassignment': {
                'type': 'bool',
                'desc': 'users can assign a token just by using the '
                            'unassigned token to authenticate.'},

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
            "delete_on_authentication_exceed": {
                'type': 'bool',
                'desc': ('should the token be deleted if maximum '
                         'authentication count was reached')},
            "disable_on_authentication_exceed": {
                'type': 'bool',
                'desc': ('should the token be disabled if maximum '
                         'authentication count was reached')},
            "push_provider": {
                'type': 'str',
                'desc': 'The push provider that should be used to '
                        'send push notifications'},
            "email_provider": {
                'type': 'str',
                'desc': 'The email provider that should be used to '
                        'send emails'},
            "sms_provider": {
                'type': 'str',
                'desc': 'The sms provider that should be used to '
                        'submit sms'},
            'trigger_sms': {
                'type': 'bool',
                'desc': 'should it be possible to trigger a sms challenge'
                        'by check_s'},
            'smstext': {
                'type': 'str',
                'desc': 'The text that will be send via SMS for an SMS token. '
                        'Use <otp> and <serial> as parameters.'},
            'otppin': {
                'type': 'set',
                'value': [0, 1, 2, "token_pin", "password", "only_otp"],
                'desc': 'either use the Token PIN (0=token_pin), '
                        'use the Userstore Password (1=password) or '
                        'use no fixed password component (2=only_otp).'},
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
            'forward_server': {
                'type': 'str',
                'desc': 'If set, the users authentication request will be '
                        'forwarded to another linotp or radius server.'
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
            'qrtanurl_init': {
                'type': 'str',
                'desc': 'The URL for rollout in the half automatic mode that '
                        'should be used in a QR Token rollout.'
                },
            'challenge_response': {
                'type': 'str',
                'desc': 'A list of tokentypes for which challenge response '
                        'should be used.'
                },
            'qrtoken_pairing_callback_url': {
                'type': 'str',
                'desc': 'The url the pairing response should be send to'
                },
            'qrtoken_pairing_callback_sms': {
                'type': 'str',
                'desc': 'The phone number the pairing response should '
                        'be send to'
                },
            'qrtoken_challenge_callback_url': {
                'type': 'str',
                'desc': 'The url the challenge response should be send to'
                },
            'qrtoken_challenge_callback_sms': {
                'type': 'str',
                'desc': 'The sms number the challenge response should '
                        'be send to'
                },
            'qrtoken_pairing_cert': {
                'type': 'str',
                'desc': 'Signifies the certificate id that should be used '
                        'during pairing. If it is not set, the system will '
                        'assume that pairing should be done without a '
                        'certificate.'
                },
            'support_offline': {
                'type': 'set',
                'value': ['qr', 'u2f'], # TODO: currently hardcoded
                'desc': 'The token types that should support offline '
                        'authentication'
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
        'tools': {
            'migrate_resolver': {
                'type': 'bool',
                'desc': 'Support the migration of assigned tokens to '
                        'a new resolver '
            },
            'import_users': {
                'type': 'bool',
                'desc': 'Import users from a file into a new resolver '
            },
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
        },
        'monitoring': {
            'config': {
                'type': 'bool',
                'desc': 'Allow to see basic configuratiuon'},
            'license': {
                'type': 'bool',
                'desc': 'Allow to check the license'},
            'storageEncryption': {
                'type': 'bool',
                'desc': 'Allow to check if encryption works'},
            'tokens': {
                'type': 'bool',
                'desc': 'Allow to see number of tokens in realms'},
            'userinfo': {
                'type': 'bool',
                'desc': 'Allow to get information on user-id-resolvers'},
            'activeUsers': {
                'type': 'bool',
                'desc': 'Allow to get information on active user count'}
        },
        'reporting': {
            'token_total': {
                'type': 'bool',
                'desc': 'Report total number of tokens'},
            'token_status': {
                'type': 'str',
                'desc': 'Report number of tokens which are in-/active,un-/assigned'
                        ' or combinations of these concatenatet with "&"'},
        },
        'reporting.access': {
            'maximum': {'type': 'bool'},
            'delete_all': {'type': 'bool'},
            'delete_before': {
                'type': 'bool',
                'desc': 'Delete all reporting entries before given date.'
                        'Date must be geiven as "yyyy-mm-dd"'
            },
            'show': {'type': 'bool'},
        },
    }

    linotp_config = request_context['Config']
    oath_support = (str(linotp_config.get('linotp.OATHTokenSupport', 'False'))
                    .lower() == 'True')

    if oath_support:
        pol['webprovisionOATH'] = {'type': 'bool'}

    # now add generic policies, which every token should provide:
    # - init<TT>
    # - enroll<TT>, but only, if there is a rendering section
    import linotp.lib.token
    token_type_list = linotp.lib.token.get_token_type_list()

    for ttype in token_type_list:
        pol['admin']["init%s" % ttype.upper()] = {'type': 'bool'}

        # TODO: action=initETNG
        # Haben wir auch noch den die policy
        #
        # scope=admin, action=initETNG?
        #
        # Das ist nämlich eine spezialPolicy, die der HMAC-Token mitbringen
        # muss.

        # todo: if all tokens are dynamic, the token init must be only shown
        # if there is a rendering section for:
        # conf = linotp.lib.token.getTokenConfig(ttype, section='init')
        # if len(conf) > 0:
        #    pol['admin']["init%s" % ttype.upper()]={'type': 'bool'}

        conf = linotp.lib.token.getTokenConfig(ttype, section='selfservice')
        if conf and 'enroll' in conf:
            pol['selfservice']["enroll%s" % ttype.upper()] = {
                'type': 'bool',
                'desc': "The user is allowed to enroll a %s token." % ttype}

        ## now merge the dynamic Token policy definition
        ## into the global definitions
        policy = linotp.lib.token.getTokenConfig(ttype, section='policy')

        ## get all policy sections like: admin, selfservice . . '''
        pol_keys = pol.keys()

        for pol_section in policy.keys():
            # if we have a dyn token definition of this section type
            # add this to this section - and make sure, that it is
            # then token type prefixed
            if pol_section in pol_keys:
                pol_entry = policy.get(pol_section)
                for pol_def in pol_entry:
                    set_def = pol_def
                    # check if the token type is already part of
                    # the policy name
                    if ttype.lower() not in set_def.lower():
                        set_def = '%s_%s' % (ttype, pol_def)

                    pol[pol_section][set_def] = pol_entry.get(pol_def)

    ##return sub section, if scope is defined
    ##  make sure that scope is in the policy key
    ##  e.g. scope='_' is undefined and would break
    if scope and scope in pol:
        pol = pol[scope]

    return pol# -*- coding: utf-8 -*-
