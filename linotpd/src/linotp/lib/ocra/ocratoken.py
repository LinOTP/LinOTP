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
This file containes the standard token definitions:
- OCRATokenClass

It also contains the base class "TokenClass", that you may use to
define your own tokenclasses.

You can add your own Tokens by adding the modules comma seperated to the
directive 'linotpTokenModules' in the linotp.ini file.

depends on several modules from linotp.lib but also in case of VascoTokenClass
on linotp.lib.ImportOTP.vasco
"""

import binascii
import datetime

import logging
import time
import re

# needed for ocra token
import urllib

from sqlalchemy import asc, desc

import linotp

from linotp.lib.config import getFromConfig
from linotp.lib.crypto import createNonce
from linotp.lib.crypto import decryptPin
from linotp.lib.crypto import encryptPin
from linotp.lib.crypto import kdf2
from linotp.lib.crypto import urandom
from linotp.lib.crypto import SecretObj

from linotp.lib.policy import get_qrtan_url

# TODO: move this as ocra specific methods
from linotp.lib.token import getRolloutToken4User
from linotp.lib.util import normalize_activation_code

from linotp.lib.ocra import OcraSuite
from linotp.model import Challenge as OcraChallenge

from linotp.lib.reply import create_img

from linotp.lib.context import request_context as context
from linotp.lib.tokenclass import TokenClass

import linotp.model.meta

Session = linotp.model.meta.Session

optional = True
required = False

log = logging.getLogger(__name__)

### OcraTokenClass #####################################

class OcraTokenClass(TokenClass):
    """
    OcraTokenClass  implement an ocra compliant token

    used from Config
        OcraMaxChallenges:    number of open challenges per token if None: 3
        OcraChallengeTimeout: timeout definition like 1D, 2H or 3M if None: 1M
        OcraDefaultSuite:     if none :'OCRA-1:HOTP-SHA256-8:C-QN08'
        QrOcraDefaultSuite:   if none :'OCRA-1:HOTP-SHA256-8:C-QA64'


    algorithm Ocra Token Rollout: two phases of rollout::

        1. https://linotpserver/admin/init?
            type=ocra&
            genkey=1&
            sharedsecret=1&
            user=BENUTZERNAME&
            session=SESSIONKEY

            =>> "serial" : SERIENNUMMER, "sharedsecret" : DATAOBJECT,
                                  "app_import" : IMPORTURL
            - genSharedSecret - vom HSM oder urandom ?
            - app_import : + linotp://
                        + ocrasuite ->> default aus dem config:
                                                    (DefaultOcraSuite)
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

            =>> "serial" : SERIENNUMMER, "nonce" : DATAOBJECT,
                "transactionid" : "TRANSAKTIONSID, "app_import" : IMPORTURL

            - nonce - von HSM oder random ?
            - pkcs5 - kdf2
            - es darf zur einer Zeit nur eine QR Token inaktiv
                   (== im Ausrollzustand) sein !!!!!
            der Token wird über den User gefunden
            - seed = pdkdf2(nonce + activcode + shared secret)
            - challenge generiern - von urandom oder HSM

        3. check_t
            - counter ist > nach der ersten Transaktion
            - if counter >= 1: delete sharedsecret löschen
    """

    @classmethod
    def get_helper_params_post(cls, param, user=None):

        helper_param = {}

        tok_type = "ocra"

        # take the keysize from the ocrasuite
        ocrasuite = param.get("ocrasuite", None)
        activationcode = param.get("activationcode", None)
        sharedsecret = param.get("sharedsecret", None)
        serial = param.get("serial", None)
        genkey = param.get("genkey", None)

        if activationcode is not None:
            # dont create a new key
            genkey = None
            serial = getRolloutToken4User(user=user, serial=serial,
                                          tok_type=tok_type)
            if serial is None:
                raise Exception('no token found for user: %r or serial: %r'
                                % (user, serial))
            helper_param['serial'] = serial
            helper_param['activationcode'] = \
                normalize_activation_code(activationcode)

        if ocrasuite is None:
            if sharedsecret is not None or activationcode is not None:
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
    def getClassType(cls):
        '''
        getClassType - return the token type shortname

        :return: 'ocra'
        :rtype: string
        '''
        return "ocra"

    @classmethod
    def getClassPrefix(cls):
        return "ocra"

    def __init__(self, aToken):
        '''
        getInfo - return the status of the token rollout

        :return: info of the ocra token state
        :rtype: dict
        '''
        TokenClass.__init__(self, aToken)
        self.setType(u"ocra")
        self.transId = 0
        return

    def getInfo(self):
        '''
        getInfo - return the status of the token rollout

        :return: info of the ocra token state
        :rtype: dict
        '''
        return self.info

    def update(self, params, reset_failcount=True):
        '''
        update: add further defintion for token from param in case of init
        '''

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
            # due to changes in the tokenclass parameter handling
            # we have to add for compatibility a genkey parameter
            if 'otpkey' not in params and 'genkey' not in params:
                log.warning('[OcraTokenClass:update] missing parameter genkey'
                            ' to complete the rollout 2!')
                params['genkey'] = 1

        TokenClass.update(self, params, reset_failcount=reset_failcount)

        self.addToTokenInfo('ocrasuite', self.ocraSuite)

        ocraSuite = OcraSuite(self.ocraSuite)
        otplen = ocraSuite.truncation
        self.setOtpLen(otplen)

        ocraPin = params.get('ocrapin', None)
        if ocraPin is not None:
            self.setUserPin(ocraPin)

        if 'otpkey' in params:
            self.setOtpKey(params.get('otpkey'))

        self._rollout_1(params)
        self._rollout_2(params)

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

            =>> "serial" : SERIENNUMMER, "sharedsecret" : DATAOBJECT,
                                         "app_import" : IMPORTURL
            - genSharedSecret - vom HSM oder urandom ?
            - app_import : + linotp://
                           + ocrasuite ->> default aus dem config:
                                                           (DefaultOcraSuite)
                           + sharedsecret (Länge wie ???)
                           + seriennummer
            - seriennummer: uuid ??
            - token wird angelegt ist aber nicht aktiv!!! (counter == 0)

        '''

        sharedSecret = params.get('sharedsecret', None)
        if sharedSecret == '1':
            #  preserve the rollout state
            self.addToTokenInfo('rollout', '1')

            # preserve the current key as sharedSecret
            secObj = self._get_secret_object()
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

            info['app_import'] = 'lseqr://init?%s' % (urllib.urlencode(uInfo))
            del info['ocrasuite']
            self.info = info

            self.token.LinOtpIsactive = False

        return

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

        =>> "serial" : SERIENNUMMER, "nonce" : DATAOBJECT,
            "transactionid" : "TRANSAKTIONSID, "app_import" : IMPORTURL

        - nonce - von HSM oder random ?
        - pkcs5 - kdf2
        - es darf zur einer Zeit nur eine QR Token inaktiv
                                        (== im Ausrollzustand) sein !!!!!
          der Token wird über den User gefunden
        - seed = pdkdf2(nonce + activcode + shared secret)
        - challenge generiern - von urandom oder HSM

        '''

        activationcode = params.get('activationcode', None)
        if activationcode is not None:

            #  genkey might have created a new key, so we have to rely on
            encSharedSecret = self.getFromTokenInfo('sharedSecret', None)
            if encSharedSecret is None:
                raise Exception('missing shared secret of initialition'
                                ' for token %r' % (self.getSerial()))

            sharedSecret = decryptPin(encSharedSecret)

            #  we generate a nonce, which in the end is a challenge
            nonce = createNonce()
            self.addToTokenInfo('nonce', nonce)

            #  create a new key from the ocrasuite
            key_len = 20
            if self.ocraSuite.find('-SHA256'):
                key_len = 32
            elif self.ocraSuite.find('-SHA512'):
                key_len = 64

            newkey = kdf2(sharedSecret, nonce, activationcode, key_len)
            self.setOtpKey(binascii.hexlify(newkey))

            #  generate challenge, which is part of the app_import
            message = params.get('message', None)
            (transid, challenge, _ret, url) = self.challenge(message)

            #  generate response
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
            uInfo['u'] = ustr[2:]
            info['url'] = str(url.encode("utf-8"))

            app_import = 'lseqr://nonce?%s' % (urllib.urlencode(uInfo))

            #  add a signature of the url
            signature = {'si': self.signData(app_import)}
            info['signature'] = signature.get('si')

            info['app_import'] = "%s&%s" % (app_import,
                                            urllib.urlencode(signature))
            self.info = info

            #  setup new state
            self.addToTokenInfo('rollout', '2')
            self.enable(True)

        return

    def getOcraSuiteSuite(self):
        '''
        getQROcraSuiteSuite - return the QR Ocra Suite
                            - if none, it will return the default

        :return: Ocrasuite of token
        :rtype: string
        '''

        defaultOcraSuite = getFromConfig("OcraDefaultSuite",
                                         'OCRA-1:HOTP-SHA256-8:C-QN08')
        self.ocraSuite = self.getFromTokenInfo('ocrasuite', defaultOcraSuite)

        return self.ocraSuite

    def getQROcraSuiteSuite(self):
        '''
        getQROcraSuiteSuite - return the QR Ocra Suite
                            - if none, it will return the default

        :return: QROcrasuite of token
        :rtype: string
        '''

        defaultOcraSuite = getFromConfig("QrOcraDefaultSuite",
                                         'OCRA-1:HOTP-SHA256-8:C-QA64')
        self.ocraSuite = self.getFromTokenInfo('ocrasuite', defaultOcraSuite)

        return self.ocraSuite

    def signData(self, data):
        '''
        sign the received data with the secret key

        :param data: arbitrary string object
        :type param: string

        :return: hexlified signature of the data
        '''

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)
        signature = ocraSuite.signData(data)

        return signature

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

        :return:    challenge response containing the transcation id and
                    the challenge for the ocrasuite
        :rtype :    tuple of (transId(string), challenge(string))

        '''

        s_data = 'None'
        s_session = 'None'
        s_challenge = 'None'
        if data is not None:
            s_data = data
        if session is not None:
            s_session = session
        if challenge is None:
            s_challenge = challenge

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)

        if not data:
            typ = 'random'

        if challenge is None:
            if typ == 'raw':
                challenge = ocraSuite.data2rawChallenge(data)
            elif typ == 'random':
                challenge = ocraSuite.data2randomChallenge(data)
            elif typ == 'hash':
                challenge = ocraSuite.data2hashChallenge(data)


        serial = self.getSerial()
        counter = self.getOtpCount()

        # set the pin onyl in the compliant hashed mode
        pin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            pin = secObj.getKey()

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
            log.exception("[OcraTokenClass] Failed to create ocrasuite challenge")
            raise Exception('[OcraTokenClass] Failed to create ocrasuite'
                            'challenge: %r' % (ex))

        #  save the object
        digits = '0123456789'
        transid = ''
        transactionIdLen = 12

        try:
            transactionIdLen = int(getFromConfig("OcraDefaultSuite", '12'))
        except:
            transactionIdLen = 12
            log.debug("[OcraTokenClass] Failed to set transactionId length"
                      " from config - using fallback %d" % (transactionIdLen))

        #  create a non exisiting challenge
        try:
            while True:
                for _c in range(0, transactionIdLen):
                    transid += urandom.choice(digits)

                chall = OcraTokenClass.getTransaction(transid)
                if chall is None:
                    break

            ddata = ''
            if data is not None:
                ddata = data

            chall = OcraChallenge(transid=transid,
                                  tokenserial=serial,
                                  challenge=typ + ':' + challenge,
                                  data=typ + ':' + ddata)
            chall.save()

        except Exception as ex:
            #  this might happen if we have a db problem or
            # the uniqnes constrain does not fit
            log.exception("[OcraTokenClass] Failed to create challenge")
            raise Exception('[OcraTokenClass] Failed to create challenge'
                            ' object: %s' % (ex))

        realms = []
        tokenrealms = self.token.getRealms()
        for realm in tokenrealms:
            realms.append(realm.name)

        url = get_qrtan_url(realms)

        return (transid, challenge, True, url)

    def get_challenge_validity(self):
        validity = 1200
        return validity

    def checkOtp(self, passw, counter, window, options=None):
        '''
        checkOtp - standard callback of linotp to verify the token

        :param passw:      the passw / otp, which has to be checked
        :type passw:       string
        :param counter:    the start counter
        :type counter:     int
        :param  window:    the window, in which the token is valid
        :type  window:     int
        :param options:    options contains the transaction id, eg. if check_t
                           checks one transaction this will support
                           assynchreonous otp checks (when check_t is used)
        :type options:     dict

        :return:           verification counter or -1
        :rtype:            int (-1)

        '''

        ret = -1

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)

        # if we have no transactionid given through the options,
        # we have to retrieve the eldest challenge for this ocra token
        serial = self.getSerial()
        challenges = []

        # set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            ocraPin = secObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if ocraSuite.T is not None:
            defTimeWindow = int(getFromConfig("ocra.timeWindow", 180))
            window = (int(self.getFromTokenInfo('timeWindow', defTimeWindow))
                      / ocraSuite.T)
            defTimeShift = int(getFromConfig("ocra.timeShift", 0))
            timeShift = int(self.getFromTokenInfo("timeShift", defTimeShift))

        if options is None:
            challenges = OcraTokenClass.getTransactions4serial(serial,
                                                               currentOnly=True)

        elif options is not None:
            if type(options).__name__ != 'dict':
                err = ('[chekOtp] "options" not of type dict! %r' %
                       type(options))
                log.error(err)
                raise Exception(err)

            if 'transactionid' in options:
                transid = options.get('transactionid')
                challenges.append(OcraTokenClass.getTransaction(transid))

            elif 'challenge' in options:
                challenges.append(options)

            # due to the added options in checkUserPass, we have to extend
            # the logic here:
            # if no challenges found in between but we have a serial, we catch
            # the open challenges by serial (s.o.)
            if len(challenges) == 0:
                challenges = OcraTokenClass.getTransactions4serial(serial,
                                                                   currentOnly=True)

        if len(challenges) == 0:
            #  verify that there has already been a challenge
            challenges = OcraTokenClass.getTransactions4serial(serial)
            if len(challenges) > 0:
                err = 'No current transaction found!'
                ret = -1
                return ret
            else:
                err = 'No open transaction found!'
                log.error(err)
                if type(options) == dict and 'transactionid' in options:
                    raise Exception(err)
                ret = -1
                return ret

        for ch in challenges:
            challenge = {}

            if isinstance(ch, dict):
                #  transaction less checkOtp
                self.transId = 0
                challenge.update(ch)

            elif type(ch) == OcraChallenge:
                #  preserve transaction context, so we could use this in
                # the status callback
                self.transId = ch.transid
                challenge['challenge'] = ch.challenge
                challenge['transid'] = ch.transid
                challenge['session'] = ch.session

            ret = ocraSuite.checkOtp(passw, counter, window, challenge,
                                     pin=ocraPin, options=options,
                                     timeshift=timeShift)

            if ret != -1:
                break

        if -1 == ret:
            #  autosync: test if two consecutive challenges +
            # it's counter match
            ret = self.autosync(ocraSuite, passw, challenge)

        return ret

    def autosync(self, ocraSuite, passw, challenge):
        '''
        try to resync a token automaticaly, if a former and the current
        request failed

        :param  ocraSuite: the ocraSuite of the current Token
        :type  ocraSuite: ocra object
        :param  passw:
        '''
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
            log.exception('Ocra: autosync check undefined %r' % (ex))
            return res

        ' if autosync is not enabled: do nothing '
        if False == autosync:
            return res

        ##
        # AUTOSYNC starts here
        ##

        counter = self.token.getOtpCounter()
        syncWindow = self.token.getSyncWindow()
        if ocraSuite.T is not None:
            syncWindow = syncWindow / 10

        # set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            ocraPin = secObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if ocraSuite.T is not None:
            timeShift = int(self.getFromTokenInfo("timeShift", 0))

        #timeStepping    = int(ocraSuite.T)

        tinfo = self.getTokenInfo()

        # autosync does only work, if we have a token info, where the
        # last challenge and the last sync-counter is stored
        # if no tokeninfo, we start with a autosync request, thus start the
        # lookup in the sync window

        if 'lChallenge' not in tinfo:
            # run checkOtp, with sync window for the current challenge
            log.info('[OcraToken:autosync] initial sync')
            count_0 = -1
            try:
                otp0 = passw
                count_0 = ocraSuite.checkOtp(otp0, counter, syncWindow,
                                             challenge, pin=ocraPin,
                                             timeshift=timeShift)
            except Exception as ex:
                log.exception('Ocra: Error during autosync0: %r' % (ex))

            if count_0 != -1:
                tinfo['lChallenge'] = {'otpc': count_0}
                self.setTokenInfo(tinfo)
                log.info('[OcraToken:autosync] initial sync - success: %r' %
                         count_0)

            res = -1

        else:
            # run checkOtp, with sync window for the current challenge
            count_1 = -1
            try:
                otp1 = passw
                count_1 = ocraSuite.checkOtp(otp1, counter, syncWindow,
                                             challenge, pin=ocraPin,
                                             timeshift=timeShift)
            except Exception as ex:
                log.exception('Ocra: Error during autosync1: %r' % (ex))

            if count_1 == -1:
                del tinfo['lChallenge']
                self.setTokenInfo(tinfo)
                log.info('[OcraToken:autosync] sync failed! Not a valid pass'
                         ' in scope (%r)' % (otp1))
                res = -1
            else:
                # run checkOtp, with sync window for the old challenge
                lChallange = tinfo.get('lChallenge')
                count_0 = lChallange.get('otpc')

                if ocraSuite.C is not None:
                    #  sync the counter based ocra token
                    if count_1 - count_0 < 2:
                        self.setOtpCount(count_1)
                        res = count_1

                if ocraSuite.T is not None:
                    #  sync the timebased ocra token
                    if count_1 - count_0 < ocraSuite.T * 2:
                        # calc the new timeshift !
                        log.debug("[autosync] the counter %r matches: %r" %
                                  (count_1,
                                   datetime.datetime.fromtimestamp(count_1)))

                        currenttime = int(time.time())
                        new_shift = (count_1 - currenttime)

                        tinfo['timeShift'] = new_shift
                        self.setOtpCount(count_1)
                        res = count_1

                #  if we came here, the old challenge is not required anymore
                del tinfo['lChallenge']
                self.setTokenInfo(tinfo)

        return res

    def is_challenge_response(self, passw, user, options=None,
                              challenges=None):
        '''
        check, if the request contains the result of a challenge

        :param passw: password, which might be pin or pin+otp
        :param user: the requesting user
        :param options: dictionary of additional request parameters

        :return: returns true or false
        '''

        challenge_response = False

        return challenge_response

    def statusValidationFail(self):
        '''
        statusValidationFail - callback to enable a status change,

        will be called if the token verification has failed

        :return - nothing

        '''
        ocraChallenge = None

        if self.transId == 0:
            return

        try:
            ocraChallenge = OcraTokenClass.getTransaction(self.transId)
            ocraChallenge.setTanStatus(received=True, valid=False, increment=False)

            #  still in rollout state??
            rolloutState = self.getFromTokenInfo('rollout', '0')

            if rolloutState == '1':
                log.info('Ocra: Rollout state 1 for token %r not completed'
                         % (self.getSerial()))

            elif rolloutState == '2':
                try:
                    maxchall = int(getFromConfig("OcraMaxChallengeRequests",
                                                 '3'))
                except:
                    maxchall = 3

                if int(ocraChallenge.received_count) >= maxchall:
                    #  after 3 fails in rollout state 2 - reset to rescan
                    self.addToTokenInfo('rollout', '1')
                    log.info('Ocra: Rollout for token %r reset to phase 1:'
                             % (self.getSerial()))

                log.info('Ocra: Rollout for token %r not completed'
                         % (self.getSerial()))

        except Exception as ex:
            log.exception('[OcraTokenClass:statusValidationFail] Error'
                          ' during validation finalisation for token %r :%r'
                          % (self.getSerial(), ex))
            raise Exception(ex)

        finally:
            if ocraChallenge is not None:
                ocraChallenge.save()

        return

    def statusValidationSuccess(self):
        '''
        statusValidationSuccess - callback to enable a status change,

        remark: will be called if the token shas been succesfull verified

        :return: - nothing

        '''

        if self.transId == 0:
            return

        ocraChallenge = OcraTokenClass.getTransaction(self.transId)
        ocraChallenge.setTanStatus(received=True, valid=True, increment=False)
        ocraChallenge.save()

        #  still in rollout state??
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

            log.info('Ocra: Rollout for token %r completed'
                     % (self.getSerial()))

        elif rolloutState == '1':
            raise Exception('unable to complete the rollout ')

        return

    def resync(self, otp1, otp2, options=None):
        '''
        - for the resync to work, we take the last two transactions and
          their challenges
        - for each challenge, we search forward the sync window length

        '''

        ret = False
        challenges = []

        o_challenges = OcraTokenClass.getTransactions4serial(self.getSerial())
        for challenge in o_challenges:
            challenges.append(challenge)

        #  check if there are enough challenges around
        if len(challenges) < 2:
            return False

        challenge1 = {}
        challenge2 = {}

        if options is None:
            ch1 = challenges[0]
            challenge1['challenge'] = ch1.challenge
            challenge1['transid'] = ch1.transid
            challenge1['session'] = ch1.session

            ch2 = challenges[1]
            challenge2['challenge'] = ch2.challenge
            challenge2['transid'] = ch2.transid
            challenge2['session'] = ch2.session

        else:
            if 'challenge1' in options:
                challenge1['challenge'] = options.get('challenge1')
            if 'challenge2' in options:
                challenge2['challenge'] = options.get('challenge2')

        if len(challenge1) == 0 or len(challenge2) == 0:
            error = "No challenges found!"
            log.error('[OcraTokenClass:resync] %s' % (error))
            raise Exception('[OcraTokenClass:resync] %s' % (error))

        secObj = self._get_secret_object()
        ocraSuite = OcraSuite(self.getOcraSuiteSuite(), secObj)

        syncWindow = self.token.getSyncWindow()
        if ocraSuite.T is not None:
            syncWindow = syncWindow / 10

        counter = self.token.getOtpCounter()

        # set the ocra token pin
        ocraPin = ''
        if ocraSuite.P is not None:
            key, iv = self.token.getUserPin()
            secObj = SecretObj(key, iv, hsm=context.get('hsm'))
            ocraPin = secObj.getKey()

            if ocraPin is None or len(ocraPin) == 0:
                ocraPin = ''

        timeShift = 0
        if ocraSuite.T is not None:
            timeShift = int(self.getFromTokenInfo("timeShift", 0))

        try:

            count_1 = ocraSuite.checkOtp(otp1, counter, syncWindow,
                                         challenge1, pin=ocraPin,
                                         timeshift=timeShift)
            if count_1 == -1:
                log.info('Ocra resync: lookup for first otp value failed!')
                ret = False
            else:
                count_2 = ocraSuite.checkOtp(otp2, counter, syncWindow,
                                             challenge2, pin=ocraPin,
                                             timeshift=timeShift)
                if count_2 == -1:
                    log.info('Ocra resync: lookup for second otp value failed!')
                    ret = False
                else:
                    if ocraSuite.C is not None:
                        if count_1 + 1 == count_2:
                            self.setOtpCount(count_2)
                            ret = True

                    if ocraSuite.T is not None:
                        if count_1 - count_2 <= ocraSuite.T * 2:
                            #  callculate the timeshift
                            date = datetime.datetime.fromtimestamp(count_2)
                            log.info('Ocra resync: Syncing token to new '
                                     'timestamp %r' % (date))

                            now = datetime.datetime.now()
                            stime = now.strftime("%s")
                            timeShift = count_2 - int(stime)
                            self.addToTokenInfo('timeShift', timeShift)
                            ret = True

        except Exception as ex:
            log.exception('[OcraTokenClass:resync] unknown error: %r' % (ex))
            raise Exception('[OcraTokenClass:resync] unknown error: %s' % (ex))

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

        statusDict = {}
        ocraChallenge = OcraTokenClass.getTransaction(transactionId)
        if ocraChallenge is not None:
            statusDict['serial'] = ocraChallenge.tokenserial
            statusDict['transactionid'] = ocraChallenge.transid
            statusDict['received_tan'] = ocraChallenge.received_tan
            statusDict['valid_tan'] = ocraChallenge.valid_tan
            statusDict['failcount'] = self.getFailCount()
            statusDict['id'] = ocraChallenge.id
            statusDict['timestamp'] = unicode(ocraChallenge.timestamp)
            statusDict['active'] = unicode(self.isActive())

        return statusDict

    @classmethod
    def timeoutJanitor(cls):
        '''
        timeoutJanitor - remove all outdated transactions / challenges

        :return: - nothing

        '''

        delta = datetime.timedelta(days=0)
        scopeDef = getFromConfig("OcraChallengeTimeout", '1D')

        #  timedelta supports : days[, seconds[, microseconds[, milliseconds[,
        # minutes[, hours[, weeks]]]]]]])
        if re.match('^(\d+[DHMS])+$', scopeDef):
            delta = datetime.timedelta(days=0)
            parts = re.findall('\d+[DHMS]', scopeDef)
            for part in parts:
                period = part[-1]
                quantity = int(part[:-1])
                if period == 'D':
                    delta = delta + datetime.timedelta(days=quantity)
                elif period == 'H':
                    delta = delta + datetime.timedelta(hours=quantity)
                elif period == 'M':
                    delta = delta + datetime.timedelta(minutes=quantity)
                elif period == 'S':
                    delta = delta + datetime.timedelta(seconds=quantity)
        else:
            log.warning('OcraChallengeTimeout value %r does not match timedelta'
                        ' definition (^(\d+[DHMS])+$)' % (scopeDef))
            try:
                scope_def = int(scopeDef)
                delta = datetime.timedelta(seconds=scope_def)
            except ValueError:
                log.warning('Failed to convert OcraChallengeTimeout value from'
                            ' config: %r' % (scopeDef))
                delta = datetime.timedelta(days=1)

        ocraChallenges = Session.query(OcraChallenge).filter(
            OcraChallenge.timestamp < datetime.datetime.now()
            - delta)

        for ocraChallenge in ocraChallenges:
            log.warning("Dropping outdated ocra challenge %r for token %r" %
                        (ocraChallenge.transid, ocraChallenge.tokenserial))
            Session.delete(ocraChallenge)

        return

    @classmethod
    def maxChallengeRequestJanitor(cls):
        '''
        maxChallengeRequestJanitor - remove all transactions / challenges
                                     which have been made more than
                                     maxChallengeRequests

        :return: - nothing

        '''

        maxRequests = int(getFromConfig("OcraMaxChallengeRequests", '3'))

        ocraChallenges = Session.query(OcraChallenge).filter(
            OcraChallenge.received_count >= maxRequests)

        for ocraChallenge in ocraChallenges:
            log.warning("Dropping outdated ocra challenge %r for token %r"
                        % (ocraChallenge.transid, ocraChallenge.tokenserial))
            Session.delete(ocraChallenge)

        return

    @classmethod
    def maxChallengeJanitor(cls, transId=None, serial=None):
        '''
        maxChallengeJanitor - remove for one token (serial) all challengens
                              but the last ones

        :param transId:     the current transaction, which provides a
                            the lookup for the serial number
        :type transId:     string

        :param serial:     the serial number of the token
        :type serial:     string

        :return: - nothing

        '''

        maxChallDef = getFromConfig("OcraMaxChallenges", '3')
        try:
            ones = int(maxChallDef)
        except ValueError as ex:
            log.exception('Failed to convert OcraMaxChallenges value from '
                          'config: %r :%r' % (maxChallDef, ex))
            ones = 3

        if ones <= 0:
            ones = 3

        if transId is not None:
            challenges = Session.query(OcraChallenge).filter(
                OcraChallenge.transid == u'' + transId)
            if challenges is None:
                return

            for challenge in challenges:
                serial = challenge.tokenserial

        if serial is None:
            log.error('Ocra max challenge janitor: Failed to lookup result '
                      'for transid %r or serial %r' % (transId, serial))
            return

        challenges = Session.query(OcraChallenge).\
            filter(OcraChallenge.tokenserial == u'' + serial)\
            .order_by(desc(OcraChallenge.id))

        lastIds = set()
        for challenge in challenges:
            if len(lastIds) < ones:
                lastIds.add(challenge.id)
            else:
                log.warning("Dropping ocra challenge %r (transaction id %r) "
                            "for token %r" % (challenge.id, challenge.transid,
                            challenge.tokenserial))
                Session.delete(challenge)

        return

    @classmethod
    def getTransaction(cls, transId):
        '''
        getTransaction - lookup for the challenge object of the given id

        :param transId:   challenge identifier
        :type transId:   string

        :return: the challenge data object
        :rtype: OcraChallenge

        '''

        #  first do housekeeping - remove outdated transactions
        # cls.timeoutJanitor()
        cls.maxChallengeRequestJanitor()
        cls.maxChallengeJanitor(transId=transId)

        ocraChallenge = None
        count = 0

        if transId is None:
            return None

        challenges = Session.query(OcraChallenge).filter(
            OcraChallenge.transid == u'' + transId).all()

        if challenges is None:
            log.info('no ocraChallenge found for tranid %r' % (transId))
            return None

        for ocraChallenge in challenges:
            log.debug("[OcraSuite:getTransactionId] %r for token: %r"
                      % (ocraChallenge.transid, ocraChallenge.tokenserial))
            count += 1

        if count == 0 or count > 1:
            log.error('%r ocraChallenge token found for this transaction %r '
                      % (count, transId))


        return ocraChallenge

    @classmethod
    def getTransactions4serial(cls, serial, currentOnly=False):
        '''
        getTransactions4serial - give all challenges for a
                                 given token serial number

        :param serial:     token serial identifier
        :type serial:     string
        :param currentOnly: boolean Flag to return all Challenges
                            (like for status request)
                             or to return the eldest open
                             transaction / challenge
        :type currentOnly: boolean flag

        :return:         return a list of Challenges
        :rtype:         OcraChallenge obejct list

        '''

        #  first do housekeeping - remove outdated transactions
        # cls.timeoutJanitor()
        cls.maxChallengeRequestJanitor()
        cls.maxChallengeJanitor(serial=serial)

        if serial is not None:
            if currentOnly is False:
                ocraChallenges = Session.query(
                            OcraChallenge
                                ).filter(
                            OcraChallenge.tokenserial == u'' + serial
                                ).order_by(desc(OcraChallenge.id)).all()
            else:

                #  return the oldest transaction only -  orderby(id).limit(1)

                ocraChallenges = Session.query(
                            OcraChallenge
                                ).filter(
                            OcraChallenge.tokenserial == u'' + serial
                                ).filter(
                            OcraChallenge.received_tan == False
                                ).order_by(asc(OcraChallenge.id)).all()

        if not ocraChallenges:
            log.info('no ocraChallenge found for serial %r' % (serial))
            return None

        for ocraChallenge in ocraChallenges:
            log.debug("[OcraSuite:getTransactionId] %r for token: %r"
                      % (ocraChallenge.transid, ocraChallenge.tokenserial))

        log.debug('[getTransactions4serial]')
        return ocraChallenges

    def getInitDetail(self, params, user=None):
        '''
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        '''

        _ = context['translate']

        response_detail = {}

        info = self.getInfo()
        # add : app_import, serial and sharedsecret
        response_detail.update(info)

        otpkey = None
        if 'otpkey' in info:
            otpkey = info.get('otpkey')

        if otpkey is not None:
            response_detail["otpkey"] = {
                "order": '1',
                "description": _("OTP seed"),
                "value": "seed://%s" % otpkey,
                "img": create_img(otpkey, width=200),
            }

        ocra_url = info.get('app_import')

        response_detail["ocraurl"] = {
            "order": '0',
            "description": _("URL for OCRA token"),
            "value": ocra_url,
            "img": create_img(ocra_url, width=250),
        }

        return response_detail

    def getQRImageData(self, response_detail):
        '''
        '''
        url = None
        hparam = {}

        if response_detail is not None:
            if 'ocraurl' in response_detail:
                url = response_detail.get('ocraurl', {}).get('value', '')
                hparam['alt'] = response_detail.get('app_import', '')
        return url, hparam

# eof #########################################################################
