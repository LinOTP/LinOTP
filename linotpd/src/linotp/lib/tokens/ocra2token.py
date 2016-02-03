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

"""This file containes the standard token definitions:
              - OCRA2TokenClass

   the OCRA2 Token will use the standard challenge response
   instead of the dedicated ocra/request and ocra/check_t

    rollout an ocra2 token:
    ------------------------
    The rollout is a 2 step process with the following steps:

    1. call the /admin/init controller with the following parameters

      :param type: must be "ocra2" for an ocra2 token
      :param genkey: must be "1", if the server should generate the seed
                     otherwise you can use the :param otpkey: with the seed
      :param ocrasuite: your ocra suite of choice e.g.
                              "OCRA-1:HOTP-SHA256-8:C-QA64"
      :param sharedsecret: value must be "1"
      :param serial: optional, if the serial will be defined by external

    as reply a set of information is returned, where the relevant part is the
    in the image data for the softtoken qrscan in the structure
         detail/ocraurl/img

    <img    width=250   src="data:image/png;base64,iVBO....

    which could be embedded in the enrollment application. Other relevant
    information (as well part in the qr encoded data) is the

    "sharedsecret": "25676ef34bd1873834bbe10c4c4176b0a9689619"

    which is the server data part for the pairing process transferd to the
    qrtan app.

    2. complete the rollout
    The qrtan app will calculate an activation code, that must be transfered
    back to the server as a set of input data for the second enrollment step by
    calling the /admin/init controller with the following parameters:

      :param type: must be of the same token type "ocra2"
      :param serial: must be the same as received from the first request
      :param genkey: must be of "1", which indicates, that the init is not
                     finished
      :param activationcode: "GEZDGNBVGY3TQOJQ01",
      :param ocrasuite: same ocrasuite as above
                              "OCRA-1:HOTP-SHA256-8:C-QA64",
      :param message: optional the message, that is displayed in the app, e.g.
                      "Transaktion: Ausrollen eines OCRA2 Tokens",

    As response again an <img > is returned, which is the 'finishing'
    transaction, where the qrtan app will reply only with an otp value


    Further challenge request and response processing could then be managed by
    using the /validate/check_s with

     :param serial: token serial number, as defined above
     :param challenge: the challenge input data as heart of the transaction

    or when using /validate/check with

     :param user: the assigned token user / owner
     :param passw: which contains the token pin
     :param challenge: the challenge input data as heart of the transaction

    a response to this request will then contain the /detail/ocraurl/img
    image data and the transaction id, which is the referer to the incomming
    challenge respones from the qrtan app.

    The challenge response then is verified by /validate/check_t and the
    parameters:

     :param transactionid: the transaction id "440364804594",
     :param pass: the otp value e.g. "48344099"

    But as well the /validate/check controller could be used to verify the
    transaction by providing in addition the user name.

"""

import binascii
import logging
import time
import datetime
import traceback

from linotp.lib.config  import getFromConfig

from linotp.lib.crypt   import decryptPin, encryptPin
from linotp.lib.crypt   import kdf2
from linotp.lib.crypt   import createNonce

from linotp.lib.policy  import getPolicy
from linotp.lib.policy  import getPolicyActionValue


### TODO: move this as ocra specific methods
from linotp.lib.token import getRolloutToken4User
from linotp.lib.util import normalize_activation_code

from linotp.lib.ocra    import OcraSuite

from linotp.lib.validate import create_challenge, check_pin, split_pin_otp
from linotp.lib.validate import get_challenges
from linotp.lib.reply   import create_img

from pylons.i18n.translation import _

from linotp.lib.tokenclass import TokenClass

# needed for ocra token
import urllib

import sys
if sys.version_info[0:2] >= (2, 6):
    from json import loads, dumps
else:
    from simplejson import loads, dumps


optional = True
required = False

log = logging.getLogger(__name__)


def qrtan_url(realms, callback_id=None):
    """
    Returns the URL for the half automatic mode for the QR TAN token
    for the given realm

    :remark: there might be more than one url, if the token
             belongs to more than one realm

    :param realms: list of realms or None

    :return: url string

    """
    url = get_qrtan_url('qrtanurl', realms, callback_id=callback_id)
    return url


def qrtanurl_init(realms, callback_id=None):
    '''
    Returns the URL for the half automatic mode for the QR TAN token
    for the given realm

    :remark: there might be more than one url, if the token
             belongs to more than one realm

    :param realms: list of realms or None

    :return: url string

    '''
    url = get_qrtan_url('qrtanurl_init', realms, callback_id=callback_id)
    return url


def get_qrtan_url(qrtan_policy_name, realms, callback_id=None):
    '''
    Worker to returns the URL for the half automatic mode for the QR TAN token
    for the given realm

    :param qrtan_policy_name: either 'qrtanurl_init' or 'qrtanurl'
    :param realms: list of realms or None
    :param callback_id: support of multiple callback definitions

    :return: url string


    :remark: there might be more than one url, if the token belongs to more
             than one realm. it is tested, if all are the same, otherwise
             an exception is raised

    '''
    log.debug("getting qrtan callback url ")
    urls = []

    # Policies defintions with wildcard defintions '*'
    # if there is no realm defined, we can catch by this trick the
    # policy definition, which have an realm wildcard definition '*'
    # so that the wildcard will match as well the empty realm
    # By setting the realm to '/:no realm:/' there is no collission with
    # any realm as this string contains characters, which are not allowed in
    # realm names
    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    for realm in realms:
        pol = getPolicy({"scope": "authentication", 'realm': realm})
        url = getPolicyActionValue(pol, qrtan_policy_name, is_string=True,
                                   subkey=callback_id)
        if url:
            urls.append(url)

    # now verify, that all urls are the same
    if len(urls) > 1:
        for url in urls:
            if url != url[0]:
                raise Exception('multiple enrollement urls %r found for '
                                'realm set: %r' % (urls, realms))

    url = ''
    if urls:
        url = urls[0]

    log.debug("got callback url %s for realms %r" % (url, realms))
    return url


#### Ocra2TokenClass #####################################
class Ocra2TokenClass(TokenClass):
    '''
    Ocra2TokenClass  implement an ocra compliant token

    used from Config
        OcraMaxChallenges         - number of open challenges per token
                                            if None: 3
        Ocra2ChallengeValidityTime  timeout definition in seconds
        OcraDefaultSuite          - if none :'OCRA-1:HOTP-SHA256-8:C-QN08'
        QrOcraDefaultSuite        - if none :'OCRA-1:HOTP-SHA256-8:C-QA64'


    algorithm Ocra Token Rollout: tow phases of rollout

    1. https://linotpserver/admin/init?
        type=ocra&
        genkey=1&
        sharedsecret=1&
        user=BENUTZERNAME&
        session=SESSIONKEY

        =>> "serial" : SERIENNUMMER, "sharedsecret" : DATAOBJECT, "app_import" : IMPORTURL
        - genSharedSecret - vom HSM oder urandom ?
        - app_import : + linotp://
                       + ocrasuite ->> default aus dem config: (DefaultOcraSuite)
                       + sharedsecret (Länge wie ???)
                       + seriennummer
        - seriennummer: uuid
        - token wird angelegt ist aber nicht aktiv!!! (counter == 0)


    2. https://linotpserver/admin/init?
        type=ocra&
        genkey=1&
        activationcode=AKTIVIERUNGSCODE&
        user=BENUTZERNAME&
        message=MESSAGE&
        session=SESSIONKEY

        =>> "serial" : SERIENNUMMER, "nonce" : DATAOBJECT, "transactionid" : "TRANSAKTIONSID, "app_import" : IMPORTURL

        - nonce - von HSM oder random ?
        - pkcs5 - kdf2
        - es darf zur einer Zeit nur eine QR Token inaktiv (== im Ausrollzustand) sein !!!!!
          der Token wird über den User gefunden
        - seed = pdkdf2(nonce + activcode + shared secret)
        - challenge generiern - von urandom oder HSM

    3. check_t
        - counter ist > nach der ersten Transaktion
        - if counter >= 1: delete sharedsecret löschen


    '''

    @classmethod
    def getClassType(cls):
        '''
        getClassType - return the token type shortname

        :return: 'ocra2'
        :rtype: string
        '''
        log.debug('[getClassType] ocra2')
        return "ocra2"

    @classmethod
    def getClassPrefix(cls):
        return "LSO2"

    @classmethod
    def classInit(cls, param, user=None):

        helper_param = {}

        tok_type = "ocra2"

        ## take the keysize from the ocrasuite
        ocrasuite = param.get("ocrasuite", None)
        activationcode = param.get("activationcode", None)
        sharedsecret = param.get("sharedsecret", None)
        serial = param.get("serial", None)
        genkey = param.get("genkey", None)

        if activationcode is not None:
            ## dont create a new key
            genkey = None
            serial = getRolloutToken4User(user=user, serial=serial,
                                          tok_type=tok_type)
            if serial is None:
                raise Exception('no token found for user: %r or serial: %r'
                                % (user, serial))
            helper_param['serial'] = serial
            helper_param['activationcode'] = normalize_activation_code(
                                                                activationcode)

        if ocrasuite is None:
            if sharedsecret is not None or  activationcode is not None:
                ocrasuite = getFromConfig("QrOcraDefaultSuite",
                                          'OCRA-1:HOTP-SHA256-6:C-QA64')
            else:
                ocrasuite = getFromConfig("OcraDefaultSuite",
                                          'OCRA-1:HOTP-SHA256-8:C-QN08')
            helper_param['ocrasuite'] = ocrasuite

        if genkey is not None:
            if ocrasuite.find('-SHA256'):
                key_size = 32
            elif ocrasuite.find('-SHA512'):
                key_size = 64
            else:
                key_size = 20
            helper_param['key_size'] = key_size

        return helper_param

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):
        '''
        getClassInfo - returns all or a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype : s.o.

        '''

        res = {
               'type' : 'ocra2',
               'title' : _('OCRA2 Token'),
               'description' :
                    _('ocra challenge-response token - hmac event based'),
               'init'         : { 'title'  : {'html'      : 'ocra2token.mako',
                                             'scope'     : 'enroll.title', },
                                  'page' : {'html'      : 'ocra2token.mako',
                                            'scope'      : 'enroll', },
                                   },

               'config'         : {'title'  : {'html'      : 'ocra2token.mako',
                                             'scope'     : 'config.title', },
                                   'page' : {'html'      : 'ocra2token.mako',
                                            'scope'      : 'config', },
                                   },

               'selfservice'   :  { 'enroll' :
                                   {'title'  :
                                    { 'html'      : 'ocra2token.mako',
                                      'scope'     : 'selfservice.title.enroll',
                                      },
                                    'page' :
                                    {'html'       : 'ocra2token.mako',
                                     'scope'      : 'selfservice.enroll',
                                     },
                                    },
                                   'activate_OCRA2' :
                                   {'title'  :
                                    { 'html'      : 'ocra2token.mako',
                                      'scope'     : 'selfservice.title.activate',
                                      },
                                    'page' :
                                    {'html'       : 'ocra2token.mako',
                                     'scope'      : 'selfservice.activate',
                                     },
                                    },

                                  },
            'policy': {'selfservice': {
                            'activate_OCRA2': {'type': 'bool'}
                            },  # eof selfservice
                      }  # eof policy
        }

        if key and key in res:
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res

        return ret

    def __init__(self, aToken):
        '''
        getInfo - return the status of the token rollout

        :return: info of the ocra token state
        :rtype: dict
        '''
        log.debug('[__init__]')

        TokenClass.__init__(self, aToken)
        self.setType(u"ocra2")
        self.transId = 0

        self.mode = ['challenge']
        log.debug('[__init__]:')
        return

    def getInfo(self):
        '''
        getInfo - return the status of the token rollout

        :return: info of the ocra token state
        :rtype: dict
        '''
        log.debug('[getInfo] %r ' % (self.info))
        return self.info

    def update(self, params, reset_failcount=True):
        '''
        update: add further definition for token from param in case of init
        '''
        log.debug('[update] %r: %r: ' % (params, reset_failcount))

        if 'ocrasuite' in params:
            self.ocraSuite = params.get('ocrasuite')
        else:
            activationcode = params.get('activationcode', None)
            sharedSecret = params.get('sharedsecret', None)

            if activationcode is None and sharedSecret is None:
                self.ocraSuite = self.getOcraSuiteSuite()
            else:
                self.ocraSuite = self.getQROcraSuiteSuite()

        if params.get('activationcode', None):
            ## due to changes in the tokenclass parameter handling
            ## we have to add for compatibility a genkey parameter
            if 'otpkey' not in params and 'genkey' not in params:
                log.warning('[Ocra2TokenClass:update] missing parameter genkey\
                             to complete the rollout 2!')
                params['genkey'] = 1

        TokenClass.update(self, params, reset_failcount=reset_failcount)

        self.addToTokenInfo('ocrasuite', self.ocraSuite)

        ocraSuite = OcraSuite(self.ocraSuite)
        otplen = ocraSuite.truncation
        self.setOtpLen(otplen)

        ocraPin = params.get('ocrapin', None)
        if ocraPin is not None:
            self.token.setUserPin(ocraPin)

        if 'otpkey' in params:
            self.setOtpKey(params.get('otpkey'))

        self._rollout_1(params)
        self._rollout_2(params)

        log.debug('[update]:')
        return

    def _rollout_1(self, params):
        '''
        do the rollout 1 step

        1. https://linotpserver/admin/init?
            type=ocra&
            genkey=1&
            sharedsecret=1&
            user=BENUTZERNAME&
            session=SESSIONKEY

            =>> "serial" : SERIENNUMMER, "sharedsecret" : DATAOBJECT, "app_import" : IMPORTURL
            - genSharedSecret - vom HSM oder urandom ?
            - app_import : + linotp://
                           + ocrasuite ->> default aus dem config: (DefaultOcraSuite)
                           + sharedsecret (Länge wie ???)
                           + seriennummer
            - seriennummer: uuid ??
            - token wird angelegt ist aber nicht aktiv!!! (counter == 0)

        '''
        log.debug('[_rollout_1] %r ' % (params))

        sharedSecret = params.get('sharedsecret', None)
        if sharedSecret == '1':
            ##  preserve the rollout state
            self.addToTokenInfo('rollout', '1')

            ##  preseerver the current key as sharedSecret
            secObj = self.token.getHOtpKey()
            key = secObj.getKey()
            encSharedSecret = encryptPin(key)
            self.addToTokenInfo('sharedSecret', encSharedSecret)

            info = {}
            uInfo = {}

            info['sharedsecret'] = key
            uInfo['sh'] = key

            info['ocrasuite'] = self.getOcraSuiteSuite()
            uInfo['os'] = self.getOcraSuiteSuite()

            info['serial'] = self.getSerial()
            uInfo['se'] = self.getSerial()

            callback = self._prepare_callback_url(params, qrtanurl_init)
            callback = callback.encode('utf-8')

            if callback:
                uInfo['u'] = callback

            # the info url must be provided in any case
            info["url"] = callback

            info['app_import'] = 'lseqr://init?%s' % (urllib.urlencode(uInfo))
            del info['ocrasuite']
            self.info = info

            self.token.LinOtpIsactive = False

        log.debug('[_rollout_1]:')
        return

    def _prepare_callback_url(self, params, policy_lookup_funtion,
                               transactionid=None):
        """
        prepare the callback url
        - check if it is allowed to get the callback from the parameters
        - get callback url from parameters or as fallback, from policy value

        finaly replace <user>, <password>, <transactionid>, <serial> in the url

        :param params: the dict of calling parameters
        :param policy_lookup_funtion: function to check for the policy defined
                    callback, either standard callback or rollout callback
        :param transactionid: optional the transactionid, if not in rollout
                              scope
        :return: the callback url or an empty string

        """
        callback = ''

        realms = []
        tokenrealms = self.token.getRealms()
        for realm in tokenrealms:
            realms.append(realm.name)

        # is there an callbac selector
        callback_id = params.get('callback.id', None)
        callback = policy_lookup_funtion(realms, callback_id)

        # is the callback supressed for the current request?
        if 'no_callback' in params:
            callback = ''

        # now adjust the callback with replacements
        if callback:
            callback = callback.replace('<serial>', self.getSerial())

            if '<transactionid>' in callback and transactionid:
                callback = callback.replace('<transactionid>', transactionid)

            # now handle the replacement parts for the authetication
            callback_pass = params.get('callback.password', '')
            callback_user = params.get('callback.user', '')

            if "<user>" in callback and callback_user:
                user = urllib.quote(callback_user)
                callback = callback.replace('<user>', user)

            if "<password>" in callback and callback_pass:
                passw = urllib.quote(callback_pass)
                callback = callback.replace('<password>', passw)

        return callback

    def _rollout_2(self, params):
        '''
        2.

        https://linotpserver/admin/init?
            type=ocra&
            genkey=1&
            activationcode=AKTIVIERUNGSCODE&
            user=BENUTZERNAME&
            message=MESSAGE&
            session=SESSIONKEY

        =>> "serial" : SERIENNUMMER, "nonce" : DATAOBJECT, "transactionid" : "TRANSAKTIONSID, "app_import" : IMPORTURL

        - nonce - von HSM oder random ?
        - pkcs5 - kdf2
        - es darf zur einer Zeit nur eine QR Token inaktiv (== im Ausrollzustand) sein !!!!!
          der Token wird über den User gefunden
        - seed = pdkdf2(nonce + activcode + shared secret)
        - challenge generiern - von urandom oder HSM

        '''
        log.debug('[_rollout_2] %r ' % (params))

        activationcode = params.get('activationcode', None)
        if activationcode is not None:

            ##  genkey might have created a new key, so we have to rely on
            encSharedSecret = self.getFromTokenInfo('sharedSecret', None)
            if encSharedSecret is None:
                raise Exception('missing shared secret of initialition for '
                                 'token %r' % (self.getSerial()))

            sharedSecret = decryptPin(encSharedSecret)

            ##  we generate a nonce, which in the end is a challenge
            nonce = createNonce()
            self.addToTokenInfo('nonce', nonce)

            ##  create a new key from the ocrasuite
            key_len = 20
            if self.ocraSuite.find('-SHA256'):
                key_len = 32
            elif self.ocraSuite.find('-SHA512'):
                key_len = 64

            newkey = kdf2(sharedSecret, nonce, activationcode, key_len)
            self.setOtpKey(binascii.hexlify(newkey))

            ##  generate challenge, which is part of the app_import
            message = params.get('message', None)

            #(transid, challenge, _ret, url) = self.challenge(message)

            #self.createChallenge()
            (res, opt) = create_challenge(self, options=params)

            challenge = opt.get('challenge')
            transid = opt.get('transactionid')
            url = opt.get('url')
            url = url.replace('<serial>', self.getSerial())
            url = url.replace('<transactionid>', transid)

            ##  generate response
            info = {}
            uInfo = {}
            info['serial'] = self.getSerial()
            uInfo['se'] = self.getSerial()
            info['nonce'] = nonce
            uInfo['no'] = nonce
            info['transactionid'] = transid
            uInfo['tr'] = transid
            info['challenge'] = challenge
            uInfo['ch'] = challenge
            if message is not None:
                uInfo['me'] = str(message.encode("utf-8"))

            ustr = urllib.urlencode({'u': str(url.encode("utf-8"))})
            if ustr[2:]:
                uInfo['u'] = ustr[2:]
                info['url'] = str(url.encode("utf-8"))

            app_import = 'lseqr://nonce?%s' % (urllib.urlencode(uInfo))

            ##  add a signature of the url
            signature = {'si': self.signData(app_import)}
            info['signature'] = signature.get('si')

            info['app_import'] = "%s&%s" % (app_import,
                                             urllib.urlencode(signature))
            self.info = info

            ##  setup new state
            self.addToTokenInfo('rollout', '2')
            self.enable(True)

        log.debug('[_rollout_2]:')
        return

    def getOcraSuiteSuite(self):
        '''
        getQROcraSuiteSuite - return the QR Ocra Suite - if none, it will return the default

        :return: Ocrasuite of token
        :rtype: string
        '''
        log.debug('[getOcraSuiteSuite]')

        defaultOcraSuite = getFromConfig("OcraDefaultSuite",
                                         'OCRA-1:HOTP-SHA256-8:C-QN08')
        self.ocraSuite = self.getFromTokenInfo('ocrasuite', defaultOcraSuite)

        log.debug('[getOcraSuiteSuite] %r:' % (self.ocraSuite))
        return self.ocraSuite

    def getQROcraSuiteSuite(self):
        '''
        getQROcraSuiteSuite - return the QR Ocra Suite - if none, it will return the default

        :return: QROcrasuite of token
        :rtype: string
        '''
        log.debug('[getQROcraSuiteSuite]')

        defaultOcraSuite = getFromConfig("QrOcraDefaultSuite",
                                         'OCRA-1:HOTP-SHA256-8:C-QA64')
        self.ocraSuite = self.getFromTokenInfo('ocrasuite', defaultOcraSuite)

        log.debug('[getQROcraSuiteSuite] %r:' % (self.ocraSuite))
        return self.ocraSuite

    def signData(self, data):
        '''
        sign the received data with the secret key

        :param data: arbitrary string object
        :type param: string

        :return: hexlified signature of the data
        '''
        log.debug('[signData] %r:' % (data))

        secretHOtp = self.token.getHOtpKey()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secretHOtp)
        signature = ocraSuite.signData(data)

        log.debug('[signData]: %r:' % (signature))
        return signature

    def verify_challenge_is_valid(self, challenge, session):
        '''
        verify, if a challenge is valid according to the ocrasuite definition
        of the token
        '''

        ret = True

        counter = self.getOtpCount()

        secretHOtp = self.token.getHOtpKey()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secretHOtp)

        ## set the pin onyl in the compliant hashed mode
        pin = ''
        if ocraSuite.P is not None:
            pinObj = self.token.getUserPin()
            pin = pinObj.getKey()

        try:
            param = {}
            param['C'] = counter
            param['Q'] = challenge
            param['P'] = pin
            param['S'] = session
            if ocraSuite.T is not None:
                now = datetime.datetime.now()
                stime = now.strftime("%s")
                itime = int(stime)
                param['T'] = itime

            ''' verify that the data is compliant with the OcraSuitesuite
                and the client is able to calc the otp
            '''
            c_data = ocraSuite.combineData(**param)
            ocraSuite.compute(c_data)

        except Exception as ex:
            log.exception("[Ocra2TokenClass] challenge verification failed: "
                                "%s,%r: " % (challenge, ex))
            ret = False

        return ret

    def createChallenge(self, state, options=None):
        '''
        standard API to create an ocra challenge
        '''
        res = True

        ## which kind of challenge gen should be used
        typ = 'raw'

        input_data = None
        challenge = None
        session = None
        message = ""

        if options:
            input_data = options.get('challenge',
                                     options.get('message',
                                                 options.get('data', None)))

            typ = options.get('challenge_type', 'raw')
            ## ocra token could contain a session attribute
            session = options.get('ocra_session', None)

        if input_data is None or len(input_data) == 0:
            typ = 'random'

        secretHOtp = self.token.getHOtpKey()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secretHOtp)

        if typ == 'raw':
            challenge = ocraSuite.data2rawChallenge(input_data)
        elif typ == 'random':
            challenge = ocraSuite.data2randomChallenge(input_data)
        elif typ == 'hash':
            challenge = ocraSuite.data2hashChallenge(input_data)

        log.debug('[Ocra2TokenClass] challenge: %r ' % (challenge))

        store_data = {
                'challenge': "%s" % (challenge),
                'serial': self.token.getSerial(),
                'input': '',
                'url': '',
                }

        if input_data is not None:
            store_data['input'] = input_data

        if session is not None:
            store_data["session"] = session

        res = self.verify_challenge_is_valid(challenge, session)

        # add Info: so depending on the Info, the rendering could be done
        #   as a callback into the token via
        #       token.getQRImageData(opt=details)

        # do we have a callback url, that will receive the otp value
        callback = self._prepare_callback_url(options, qrtan_url,
                                          transactionid=state)
        callback = callback.encode('utf-8')

        store_data["url"] = callback

        # we will return a dict of all
        attributes = self.prepare_message(store_data, state)
        attributes['challenge'] = challenge

        if attributes != None and "data" in attributes:
            message = attributes.get("data")
            del attributes['data']

        return (res, message, store_data, attributes)

    def prepare_message(self, data, transId):
        '''
        prepare the challenge response message

        :param data:
        :param transId: the transaction/state refenence id
        remark:
        we need the state/transId in the inner scope to support the signing
        of the whole request including the state/transId
        '''

        url = data.get("url")
        u = (str(urllib.urlencode({'u': '%s' % url})))
        u = urllib.urlencode({'u': "%s" % (url.encode("utf-8"))})

        challenge = data.get('challenge')
        input_data = data.get('input')

        uInfo = {'tr': transId,
                 'ch': challenge,
                 'me': str(input_data.encode("utf-8")),
                 }
        if url:
            uInfo['u'] = str(u[2:])
        detail = {'request': str(input_data.encode("utf-8")),
                  'url': str(url.encode("utf-8")),
                 }

        ## create the app_url from the data
        dataobj = 'lseqr://req?%s' % (str(urllib.urlencode(uInfo)))

        ## append the signature to the url
        signature = {'si': self.signData(dataobj)}
        uInfo['si'] = signature
        dataobj = '%s&%s' % (dataobj, str(urllib.urlencode(signature)))

        detail["data"] = dataobj
        detail["ocraurl"] = {
                    "value": detail.get('data'),
                    "img": create_img(detail.get('data'), width=250)
                    }

        return detail

    def challenge(self, data, session='', typ='raw', challenge=None):
        '''
        the challenge method is for creating an transaction / challenge object

        remark: the transaction has a maximum lifetime and a reference to
                the OcraSuite token (serial)

        :param data:     data, which is the base for the challenge or None
        :type data:     string or None
        :param session:  session support for ocratokens
        :type session:  string
        :type typ:      define, which kind of challenge base should be used
                         could be raw - take the data input as is
                               (extract chars accordind challenge definition Q)
                         or random    - will generate a random input
                         or hased     - will take the hash of the input data

        :return:    challenge response containing the transcation id and the
                    challenge for the ocrasuite
        :rtype :    tuple of (transId(string), challenge(string))


        '''
        log.debug('[challenge] %r: %r: %r' % (data, session, challenge))

        secretHOtp = self.token.getHOtpKey()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secretHOtp)

        if data is None or len(data) == 0:
            typ = 'random'

        if challenge is None:
            if typ == 'raw':
                challenge = ocraSuite.data2rawChallenge(data)
            elif typ == 'random':
                challenge = ocraSuite.data2randomChallenge(data)
            elif typ == 'hash':
                challenge = ocraSuite.data2hashChallenge(data)

        log.debug('[Ocra2TokenClass] challenge: %r ' % (challenge))

        counter = self.getOtpCount()

        ## set the pin onyl in the compliant hashed mode
        pin = ''
        if ocraSuite.P is not None:
            pinObj = self.token.getUserPin()
            pin = pinObj.getKey()

        try:
            param = {}
            param['C'] = counter
            param['Q'] = challenge
            param['P'] = pin
            param['S'] = session
            if ocraSuite.T is not None:
                now = datetime.datetime.now()
                stime = now.strftime("%s")
                itime = int(stime)
                param['T'] = itime

            ''' verify that the data is compliant with the OcraSuitesuite
                and the client is able to calc the otp
            '''
            c_data = ocraSuite.combineData(**param)
            ocraSuite.compute(c_data)

        except Exception as ex:
            raise Exception('[Ocra2TokenClass] Failed to create ocrasuite '
                                                        'challenge: %r' % (ex))

        ##  create a non exisiting challenge
        try:

            (res, opt) = create_challenge(self, options={'messgae': data})

            transid = opt.get('transactionid')
            challenge = opt.get('challenge')

        except Exception as ex:
            ##  this might happen if we have a db problem or
            ##   the uniqnes constrain does not fit
            log.error("[Ocra2TokenClass] %r" % (traceback.format_exc()))
            raise Exception('[Ocra2TokenClass] Failed to create '
                                                'challenge object: %s' % (ex))

        realms = []
        tokenrealms = self.token.getRealms()
        for realm in tokenrealms:
            realms.append(realm.name)

        url = qrtan_url(realms)

        log.debug('[challenge]: %r: %r: %r' % (transid, challenge, url))
        return (transid, challenge, True, url)

### challenge interfaces starts here
    def is_challenge_request(self, passw, user, options=None):
        '''
        check, if the request would start a challenge

        - default: if the passw contains only the pin, this request would
        trigger a challenge

        - in this place as well the policy for a token is checked

        :param passw: password, which might be pin or pin+otp
        :param options: dictionary of additional request parameters

        :retrun: returns true or false
        '''

        request_is_valid = False

        if passw is None:
            ## for compatibility:
            # in case of ocra2, we accept to trigger a challenge even with an
            # missing password, if there is a challenge or data in the request
            if 'data' in options or 'challenge' in options:
                request_is_valid = True
        else:
            tok = super(Ocra2TokenClass, self)
            request_is_valid = tok.is_challenge_request(passw, user,
                                                        options=options)

        return request_is_valid

    def is_challenge_response(self, passw, user, options=None, challenges=None):
        '''
        test for the ocra token, if this is a response to a challenge

        normal challenge response brings in a password and there is at least
        a stored challenge available. But OCRA support as well direct
        challenges, which bring the challenge data and the otp within the same
        request.

        :param passw: password, which might be pin or pin+otp
        :param user: the requesting user
        :param options: dictionary of additional request parameters

        :return: returns true or false
        '''

        challenge_response = False

        if passw is not None and len(passw) > 0:
            # for a challenge response a pin+otp is required
            # if passw matches a password, this is a challenge request
            if check_pin(self, passw, user, options=options):
                return False

            if challenges is not None and len(challenges) > 0:
                challenge_response = True

            # we might have a direct challenge:
            # direct challenge comes along with a pin+otp and direct challenge
            elif 'challenge' in options or 'data' in options:
                    challenge_response = True

        elif 'challenge' in options or 'data' in options:
            challenge_response = False

        # we leave out the checkOtp, which is done later
        # either in checkResponse4Challenge
        # or in the check pin+otp

        return challenge_response

    def is_challenge_valid(self, challenge=None):
        '''
        this method proves the validity of a challenge
        - the default implementation tests, if the challegenge start
        is in the default vality time window.

        :param challenge: challenge object
        :return: true or false
        '''

        return True

    def checkResponse4Challenge(self, user, passw, options=None, challenges=None):
        '''
        verify the response of a previous challenge

        :param user:      the requesting user
        :param passw:     the to be checked pass: (otp) & trans_id | (pin+otp)
        :param options:   options an additional argument, which could be token
                          specific
        :param challenges: the list of challenges, where each challenge is
                            described as dict
        :return: tuple of (boolean and the list matching challenge ids)
        '''
        res = False
        otpcount = -1
        matching_challenges = []
        mids = {}
        loptions = {}

        if options is not None:
            loptions.update(options)
        if 'session' in loptions:
            del loptions['session']

        (pin, otpval) = self.splitPinPass(passw)
        res = self.checkPin(pin)

        if res == False:
            if 'transactionid' in options or 'state' in options:
                transactionid = options.get('state', options.get('transactionid'))
                for challenge in challenges:
                    transid = challenge.get('transid', None)
                    if transid == transactionid:
                        res = True
                        pin = None
                        otpval = passw
                        break

        if res == True:
            window = self.getCounterWindow()
            counter = self.getOtpCount()
            transids = set()

            ## preserve the provided transaction
            if 'transactionid' in options:
                transids.add(options.get('transactionid'))

            ## add all identified challenges by transid
            for challenge in challenges:
                ### checkOtp recieve the challenge in the options
                ### as transcationid
                try:
                    transid = challenge.get('transid', None)
                except Exception:
                    pass
                if transid is not None:
                    mids[transid] = challenge

            for transid in mids.keys():
                ## intentional overwrite the transaction which has been provided
                loptions['transactionid'] = transid
                otpcount = self.checkOtp(otpval, counter, window, options=loptions)
                if otpcount >= 0:
                    matching_challenges.append(mids.get(transid))
                    break

            # direct challenge -
            # brings the challange along with the matching pin
            if not mids and 'challenge' in options:
                otpcount = self.checkOtp(otpval, counter, window,
                                         options=options)

        return (otpcount, matching_challenges)

    def checkOtp(self, passw , counter, window, options=None):
        '''
        checkOtp - standard callback of linotp to verify the token

        :param passw:      the passw / otp, which has to be checked
        :type passw:       string
        :param counter:    the start counter
        :type counter:     int
        :param  window:    the window, in which the token is valid
        :type  window:     int
        :param options:    options contains the transaction id,
                            eg. if check_t checks one transaction
                            this will support assynchreonous otp checks
                            (when check_t is used)
        :type options:     dict

        :return:           verification counter or -1
        :rtype:            int (-1)

        '''
        log.debug('[checkOtp] %r: %r: %r' % (passw, counter, window))
        ret = -1

        challenges = []
        serial = self.getSerial()

        if options is None:
            options = {}

        maxRequests = int(getFromConfig("Ocra2MaxChallengeRequests", '3'))

        if 'transactionid' in options:
            transid = options.get('transactionid', None)
            challs = get_challenges(serial=serial, transid=transid)
            for chall in challs:
                (rec_tan, rec_valid) = chall.getTanStatus()
                if rec_tan == False:
                    challenges.append(chall)
                elif rec_valid == False:
                    ## add all touched but failed challenges
                    if chall.getTanCount() <= maxRequests:
                        challenges.append(chall)

        if 'challenge' in options:
            ## direct challenge - there might be addtionalget info like
            ## session data in the options
            challenges.append(options)

        if len(challenges) == 0:
            challs = get_challenges(serial=serial)
            for chall in challs:
                (rec_tan, rec_valid) = chall.getTanStatus()
                if rec_tan == False:
                    ## add all untouched challenges
                    challenges.append(chall)
                elif rec_valid == False:
                    ## add all touched but failed challenges
                    if chall.getTanCount() <= maxRequests:
                        challenges.append(chall)

        if len(challenges) == 0:
            err = 'No open transaction found for token %s' % serial
            log.error(err)  ##TODO should log and fail!!
            raise Exception(err)

        ## prepare the challenge check - do the ocra setup
        secretHOtp = self.token.getHOtpKey()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secretHOtp)

        ## set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            ocraPinObj = self.token.getUserPin()
            ocraPin = ocraPinObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if  ocraSuite.T is not None:
            defTimeWindow = int(getFromConfig("ocra.timeWindow", 180))
            window = int(self.getFromTokenInfo('timeWindow', defTimeWindow)) / ocraSuite.T
            defTimeShift = int(getFromConfig("ocra.timeShift", 0))
            timeShift = int(self.getFromTokenInfo("timeShift", defTimeShift))

        default_retry_window = int(getFromConfig("ocra2.max_check_challenge_retry", 0))
        retry_window = int(self.getFromTokenInfo("max_check_challenge_retry", default_retry_window))

        ## now check the otp for each challenge

        for ch in challenges:
            challenge = {}

            ##  preserve transaction context, so we could use this in the status callback
            self.transId = ch.get('transid', None)
            challenge['transid'] = self.transId
            challenge['session'] = ch.get('session', None)

            ## we saved the 'real' challenge in the data
            data = ch.get('data', None)
            if data is not None:
                challenge['challenge'] = data.get('challenge')
            elif 'challenge' in ch:
                ## handle explicit challenge requests
                challenge['challenge'] = ch.get('challenge')

            if challenge.get('challenge') is None:
                raise Exception('could not checkOtp due to missing challenge'
                                ' in request: %r' % ch)

            ret = ocraSuite.checkOtp(passw, counter, window, challenge, pin=ocraPin , options=options, timeshift=timeShift)
            log.debug('[checkOtp]: %r' % (ret))

            ## due to the assynchronous challenge verification of the checkOtp
            ## it might happen, that the found counter is lower than the given
            ## one. Thus we fix this here to deny assynchronous verification

            # we do not support retry checks anymore:
            # which means, that ret might be smaller than the actual counter
            if ocraSuite.T is None:
                if ret + retry_window < counter:
                    ret = -1

            if ret != -1:
                break

        if -1 == ret:
            ##  autosync: test if two consecutive challenges + it's counter match
            ret = self.autosync(ocraSuite, passw, challenge)


        return ret

    def autosync(self, ocraSuite, passw, challenge):
        '''
        try to resync a token automaticaly, if a former and the current request failed

        :param  ocraSuite: the ocraSuite of the current Token
        :type  ocraSuite: ocra object
        :param  passw:
        '''
        log.debug('[OcraToken::autosync] %r : %r' % (passw, challenge))
        res = -1

        autosync = False

        try:
            async = getFromConfig("AutoResync")
            if async is None:
                autosync = False
            elif "true" == async.lower():
                autosync = True
            elif "false" == async.lower():
                autosync = False
        except Exception as ex:
            log.exception('autosync check undefined %r' % (ex))
            return res

        ' if autosync is not enabled: do nothing '
        if False == autosync:
            return res

        ##
        ## AUTOSYNC starts here
        ##

        counter = self.token.getOtpCounter()
        syncWindow = self.token.getSyncWindow()
        if  ocraSuite.T is not None:
            syncWindow = syncWindow / 10


        ## set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            ocraPinObj = self.token.getUserPin()
            ocraPin = ocraPinObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if  ocraSuite.T is not None:
            timeShift = int(self.getFromTokenInfo("timeShift", 0))

        #timeStepping    = int(ocraSuite.T)

        tinfo = self.getTokenInfo()

        ## autosync does only work, if we have a token info, where the last challenge and the last sync-counter is stored
        ## if no tokeninfo, we start with a autosync request, thus start the lookup in the sync window

        if 'lChallenge' not in tinfo:
            ## run checkOtp, with sync window for the current challenge
            log.info('[OcraToken:autosync] initial sync')
            count_0 = -1
            try:
                otp0 = passw
                count_0 = ocraSuite.checkOtp(otp0, counter, syncWindow, challenge, pin=ocraPin, timeshift=timeShift)
            except Exception as ex:
                log.exception(' error during autosync0 %r' % (ex))

            if count_0 != -1:
                tinfo['lChallenge'] = {'otpc' : count_0}
                self.setTokenInfo(tinfo)
                log.info('[OcraToken:autosync] initial sync - success: %r' % (count_0))

            res = -1
            log.info('[OcraToken:autosync] initial sync done!')

        else:
            ## run checkOtp, with sync window for the current challenge
            log.info('[OcraToken:autosync] sync')
            count_1 = -1
            try:
                otp1 = passw
                count_1 = ocraSuite.checkOtp(otp1, counter, syncWindow, challenge, pin=ocraPin, timeshift=timeShift)
            except Exception as ex:
                log.exception(' error during autosync1 %r' % (ex))

            if count_1 == -1:
                del tinfo['lChallenge']
                self.setTokenInfo(tinfo)
                log.info('[OcraToken:autosync] sync failed! Not a valid pass in scope (%r)' % (otp1))
                res = -1
            else:
                ## run checkOtp, with sync window for the old challenge
                lChallange = tinfo.get('lChallenge')
                count_0 = lChallange.get('otpc')

                if ocraSuite.C is not None:
                    ##  sync the counter based ocra token
                    if count_1 - count_0 < 2:
                        self.setOtpCount(count_1)
                        res = count_1

                if ocraSuite.T is not None:
                    ##  sync the timebased ocra token
                    if count_1 - count_0 < ocraSuite.T * 2 :
                        ## calc the new timeshift !
                        log.debug("[autosync] the counter %r matches: %r" %
                                  (count_1, datetime.datetime.fromtimestamp(count_1)))

                        currenttime = int(time.time())
                        new_shift = (count_1 - currenttime)

                        tinfo['timeShift'] = new_shift
                        self.setOtpCount(count_1)
                        res = count_1

                ##  if we came here, the old challenge is not required anymore
                del tinfo['lChallenge']
                self.setTokenInfo(tinfo)

            log.info('[OcraToken:autosync] sync done!')

        log.debug('[autosync]: %r ' % (res))
        return res

    def statusValidationFail(self):
        '''
        statusValidationFail - callback to enable a status change,

        will be called if the token verification has failed

        :return - nothing

        '''
        log.debug('[statusValidationFail]')
        challenge = None

        if self.transId == 0:
            return
        try:

            challenges = get_challenges(self.getSerial(), transid=self.transId)
            if len(challenges) == 1:
                challenge = challenges[0]
                challenge.setTanStatus(received=True, valid=False)

            ##  still in rollout state??
            rolloutState = self.getFromTokenInfo('rollout', '0')

            if rolloutState == '1':
                log.info('rollout state 1 for token %r not completed'
                         % (self.getSerial()))

            elif rolloutState == '2':
                if challenge.received_count >= int(getFromConfig("OcraMaxChallengeRequests", '3')):
                    ##  after 3 fails in rollout state 2 - reset to rescan
                    self.addToTokenInfo('rollout', '1')
                    log.info('rollout for token %r reset to phase 1:'
                             % (self.getSerial()))

                log.info('rollout for token %r not completed'
                         % (self.getSerial()))

        except Exception as ex:
            log.exception('[Ocra2TokenClass:statusValidationFail] Error during '
                          'validation finalisation for token %r :%r'
                          % (self.getSerial(), ex))
            raise Exception(ex)

        finally:
            if challenge is not None:
                challenge.save()

        log.debug('[statusValidationFail]')
        return

    def statusValidationSuccess(self):
        '''
        statusValidationSuccess - callback to enable a status change,

        remark: will be called if the token has been succesfull verified

        :return: - nothing

        '''
        log.debug('[statusValidationSuccess]')

        if self.transId == 0:
            return

        challenges = get_challenges(self.getSerial(), transid=self.transId)
        if len(challenges) == 1:
            challenge = challenges[0]
            challenge.setTanStatus(True, True)
            challenge.save()

        ##  still in rollout state??
        rolloutState = self.getFromTokenInfo('rollout', '0')

        if rolloutState == '2':
            t_info = self.getTokenInfo()
            if 'rollout' in t_info:
                del t_info['rollout']
            if 'sharedSecret' in t_info:
                del t_info['sharedSecret']
            if 'nonce' in t_info:
                del t_info['nonce']
            self.setTokenInfo(t_info)

            log.info('rollout for token %r completed' % (self.getSerial()))

        elif rolloutState == '1':
            raise Exception('unable to complete the rollout ')

        log.debug('[statusValidationSuccess]:')
        return


    def resync(self, otp1, otp2, options=None):
        '''
        - for the resync to work, we take the last two transactions and their challenges
        - for each challenge, we search forward the sync window length

        '''
        log.debug('[resync] %r : %r' % (otp1, otp2))

        ret = False
        challenges = []

        ## the challenges are orderd, the first one is the newest
        challenges = get_challenges(self.getSerial())

        ##  check if there are enough challenges around
        if len(challenges) < 2:
            return False

        challenge1 = {}
        challenge2 = {}

        if options is None:

            ## the newer one
            ch1 = challenges[0]
            challenge1['challenge'] = ch1.get('data').get('challenge')
            challenge1['transid'] = ch1.get('transid')
            challenge1['session'] = ch1.get('session')
            challenge1['id'] = ch1.get('id')

            ## the elder one
            ch2 = challenges[0]
            challenge2['challenge'] = ch2.get('data').get('challenge')
            challenge2['transid'] = ch2.get('transid')
            challenge2['session'] = ch2.get('session')
            challenge2['id'] = ch2.get('id')

        else:
            if 'challenge1' in options:
                challenge1['challenge'] = options.get('challenge1')
            if 'challenge2' in options:
                challenge2['challenge'] = options.get('challenge2')

        if len(challenge1) == 0 or len(challenge2) == 0:
            error = "No challeges found!"
            log.error('[Ocra2TokenClass:resync] %s' % (error))
            raise Exception('[Ocra2TokenClass:resync] %s' % (error))

        secretHOtp = self.token.getHOtpKey()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secretHOtp)

        syncWindow = self.token.getSyncWindow()
        if  ocraSuite.T is not None:
            syncWindow = syncWindow / 10

        counter = self.token.getOtpCounter()

        ## set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            ocraPinObj = self.token.getUserPin()
            ocraPin = ocraPinObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if  ocraSuite.T is not None:
            timeShift = int(self.getFromTokenInfo("timeShift", 0))

        try:

            count_1 = ocraSuite.checkOtp(otp1, counter, syncWindow, challenge1, pin=ocraPin, timeshift=timeShift)
            if count_1 == -1:
                log.info('[resync] lookup for first otp value failed!')
                ret = False
            else:
                count_2 = ocraSuite.checkOtp(otp2, counter, syncWindow, challenge2, pin=ocraPin, timeshift=timeShift)
                if count_2 == -1:
                    log.info('[resync] lookup for second otp value failed!')
                    ret = False
                else:
                    if ocraSuite.C is not None:
                        if count_1 + 1 == count_2:
                            self.setOtpCount(count_2)
                            ret = True

                    if  ocraSuite.T is not None:
                        if count_1 - count_2 <= ocraSuite.T * 2:
                            ##  callculate the timeshift
                            date = datetime.datetime.fromtimestamp(count_2)
                            log.info('[resync] syncing token to new timestamp: %r' % (date))

                            now = datetime.datetime.now()
                            stime = now.strftime("%s")
                            timeShift = count_2 - int(stime)
                            self.addToTokenInfo('timeShift', timeShift)
                            ret = True

        except Exception as ex:
            log.exception('[Ocra2TokenClass:resync] unknown error: %r' % (ex))
            raise Exception('[Ocra2TokenClass:resync] unknown error: %s' % (ex))

        log.debug('[resync]: %r ' % (ret))
        return ret


    def getStatus(self, transactionId):
        '''
        getStatus - assembles the status of a transaction / challenge in a dict

        {   "serial": SERIENNUMMER1,
            "transactionid": TRANSACTIONID1,
            "received_tan": true,
            "valid_tan": true,
            "failcount": 0
        }

        :param transactionId:    the transaction / challenge id
        :type transactionId:    string

        :return:    status dict
        :rtype:       dict
        '''

        log.debug('[getStatus] %r' % (transactionId))

        statusDict = {}
        challenge = get_challenges(self.getSerial(), transid=transactionId)
        if challenge is not None:
            statusDict['serial'] = challenge.tokenserial
            statusDict['transactionid'] = challenge.transid
            statusDict['received_tan'] = challenge.received_tan
            statusDict['valid_tan'] = challenge.valid_tan
            statusDict['failcount'] = self.getFailCount()
            statusDict['id'] = challenge.id
            statusDict['timestamp'] = unicode(challenge.timestamp)
            statusDict['active'] = unicode(self.isActive())


        log.debug('[getStatus]: %r' % (statusDict))
        return statusDict


    def getInitDetail(self, params , user=None):
        '''
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        '''
        response_detail = {}

        info = self.getInfo()
        # add : app_import, serial and sharedsecret
        response_detail.update(info)

        otpkey = None
        if 'otpkey' in info:
            otpkey = info.get('otpkey')

        if otpkey != None:
            response_detail["otpkey"] = {
                        "order"      : '1',
                        "description": _("OTP seed"),
                        "value"      :  "seed://%s" % otpkey,
                        "img"        :  create_img(otpkey, width=200),
                        }

        ocra_url = info.get('app_import')

        response_detail["ocraurl"] = {
                    "order"      : '0',
                    "description" : _("URL for OCRA2 token"),
                    "value" : ocra_url,
                    "img"   : create_img(ocra_url, width=250)
                    }

        return response_detail

    def getQRImageData(self, response_detail):
        '''
        '''
        url = None
        hparam = {}

        if response_detail is not None:
            if 'ocraurl' in response_detail:
                url = response_detail.get('ocraurl', {}).get("value", "")
                hparam['alt'] = url
            if 'data' in response_detail:
                url = response_detail.get('data')
                hparam['alt'] = url

        return url, hparam


#eof###########################################################################

