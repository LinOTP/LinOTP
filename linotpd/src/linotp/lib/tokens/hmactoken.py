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
""" This file containes the dynamic hmac token implementation:
              - HmacTokenClas   (HOTP)
"""
import time
from datetime import datetime

from linotp.lib.HMAC    import HmacOtp
from linotp.lib.util    import getParam
from linotp.lib.config  import getFromConfig
from linotp.lib.tokenclass import TokenClass

from linotp.lib.validate import check_pin
from linotp.lib.validate import check_otp
from linotp.lib.validate import split_pin_otp, is_same_transaction

from linotp.lib.reply   import create_img
from linotp.lib.apps    import create_google_authenticator
from linotp.lib.apps    import NoOtpAuthTokenException
from linotp.lib.apps    import create_oathtoken_url


optional = True
required = False

from pylons.i18n.translation import _



import logging
log = logging.getLogger(__name__)

keylen = {'sha1' : 20,
          'sha256' : 32,
          'sha512' : 64
          }

class HmacTokenClass(TokenClass):
    '''
    hotp token class implementation
    '''

    @classmethod
    def getClassType(cls):
        '''
        getClassType - return the token type shortname

        :return: 'hmac'
        :rtype: string

        '''
        return "hmac"

    @classmethod
    def getClassPrefix(cls):
        return "oath"

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):
        '''
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype: s.o.

        '''
        log.debug("[getClassInfo] begin. Get class render info for section: key %r, ret %r " %
                  (key, ret))

        res = {
           'type'         : 'hmac',
           'title'        : 'HMAC Event Token',
           'description'  : ('event based otp token using the hmac algorithm'),

           'init'         : {'page' : {'html'      : 'hmactoken.mako',
                                        'scope'      : 'enroll', },
                               'title'  : {'html'      : 'hmactoken.mako',
                                         'scope'     : 'enroll.title', },
                               },

           'config'        : { 'page' : {'html'      : 'hmactoken.mako',
                                        'scope'      : 'config', },
                               'title'  : {'html'      : 'hmactoken.mako',
                                         'scope'     : 'config.title', },
                             },

           'selfservice'   :  { 'enroll' :
                               {'page' : {
                                  'html'       : 'hmactoken.mako',
                                  'scope'      : 'selfservice.enroll', },
                                'title'  :
                                 { 'html'      : 'hmactoken.mako',
                                   'scope'      : 'selfservice.title.enroll', },
                                  },
                              },

           'policy' : {
            'selfservice' : {
               'hmac_hashlib' : {
                  'type':'int',
                  'value' : [1, 2],
                  'desc' : _('Specify the hashlib to be used. Can be sha1 (1) or sha2-256 (2).')
                    },
               'hmac_otplen' : {'type':'int',
                  'value' : [6, 8],
                  'desc' : _('Specify the otplen to be used. Can be 6 or 8 digits.')
                  },
                }
                }
               }

        if key is not None and res.has_key(key):
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        log.debug("[getClassInfo] end. Returned the configuration section: ret %r " % (ret))
        return ret


    def __init__(self, a_token):
        '''
        constructor - create a token object

        :param aToken: instance of the orm db object
        :type aToken:  orm object

        '''
        log.debug("[init]  begin. Create a token object with: a_token %r" % (a_token))

        TokenClass.__init__(self, a_token)
        self.setType(u"HMAC")
        self.hKeyRequired = True

        # we support various hashlib methods, but only on create
        # which is effectively set in the update

        self.hashlibStr = u"sha1"
        try:
            self.hashlibStr = getFromConfig("hotp.hashlib", u'sha1')
        except Exception as ex:
            log.exception('[init] Failed to get the hotp.hashlib (%r)' % (ex))
            raise Exception(ex)


        log.debug("[init]  end. Token object created")
        return



    def update(self, param, reset_failcount=True):
        '''
        update - process the initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing
        '''

        log.debug("[update] begin. Process the initialization parameters: param %r" % (param))

        ## Remark: the otpKey is handled in the parent class

        val = getParam(param, "hashlib", optional)
        if val is not None:
            self.hashlibStr = val
        else:
            self.hashlibStr = 'sha1'

        ## check if the key_size id provided
        ## if not, we could derive it from the hashlib
        key_size = getParam(param, 'key_size', optional)
        if key_size == None:
            param['key_size'] = keylen.get(self.hashlibStr)

        param['hashlib'] = self.hashlibStr
        self.addToTokenInfo("hashlib", self.hashlibStr)

        TokenClass.update(self, param, reset_failcount)

        log.debug("[update] end. Processing the initialization parameters done.")
        return
### challenge interfaces starts here
    def is_challenge_request(self, passw, user, options=None):
        '''
        check, if the request would start a challenge

        - default: if the passw contains only the pin, this request would
        trigger a challenge

        - in this place as well the policy for a token is checked

        :param passw: password, which might be pin or pin+otp
        :param options: dictionary of additional request parameters

        :return: returns true or false
        '''

        trigger_challenge = False
        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            trigger_challenge = True

        return trigger_challenge

    def checkResponse4Challenge(self, user, passw, options=None, challenges=None):
        '''
        verify the response of a previous challenge

        :param user:     the requesting user
        :param passw:    the to be checked pass (pin+otp)
        :param options:  options an additional argument, which could be token
                          specific
        :param challenges: the list of challenges, where each challenge is
                            described as dict
        :return: tuple of (otpcounter and the list of matching challenges)

        '''
        otp_counter = -1
        transid = None
        matching = None
        matchin_challenges = []

        if 'transactionid' in options or 'state' in options:
            ## fetch the transactionid
            transid = options.get('transactionid', options.get('state', None))

        # check if the transactionid is in the list of challenges
        if transid is not None:
            for challenge in challenges:
                if is_same_transaction(challenge, transid):
                    matching = challenge
                    break
            if matching is not None:
                otp_counter = check_otp(self, passw, options=options)
                if otp_counter >= 0:
                    matchin_challenges.append(matching)

        return (otp_counter, matchin_challenges)


    def createChallenge(self, state, options=None):
        '''
        create a challenge, which is submitted to the user

        :param state: the state/transaction id
        :param options: the request context parameters / data
        :return: tuple of (bool, message and data)
                 message is submitted to the user
                 data is preserved in the challenge
                 attributes are additional attributes, which could be returned
        '''
        message = 'Please enter your otp value: '
        data = {
                'serial' : self.token.getSerial(),
                'date' : "%s" % datetime.now()
                }

        return (True, message, data, None)


    def checkOtp(self, anOtpVal, counter, window, options=None):
        '''
        checkOtp - validate the token otp against a given otpvalue

        :param anOtpVal: the to be verified otpvalue
        :type anOtpVal:  string

        :param counter: the counter state, that should be verified
        :type counter: int

        :param window: the counter +window, which should be checked
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or -1
        :rtype: int

        '''
        log.debug("[checkOtp] begin. Validate the token otp: anOtpVal: %r ,counter: %r,window: %r, options: %r " % (anOtpVal, counter, window, options))
        res = -1

        try:
            otplen = int(self.getOtpLen())
        except ValueError as ex:
            log.exception('[checkOtp] failed to initialize otplen: ValueError %r %r' % (ex, self.token.LinOtpOtpLen))
            raise Exception(ex)

        try:
            self.hashlibStr = self.getFromTokenInfo("hashlib", 'sha1')
        except Exception as ex:
            log.exception('[checkOtp] failed to initialize hashlibStr: %r' % (ex))
            raise Exception(ex)

        secretHOtp = self.token.getHOtpKey()
        #serialNum   = self.token.LinOtpTokenSerialnumber
        #log.debug("serial: %s",serialNum)

        hmac2Otp = HmacOtp(secretHOtp, counter, otplen,
                           self.getHashlib(self.hashlibStr))
        res = hmac2Otp.checkOtp(anOtpVal, window)

        if -1 == res:
            res = self.autosync(hmac2Otp, anOtpVal)

        log.debug("[checkOtp] end. otp verification result was: res %r" % (res))
        return res

    def check_otp_exist(self, otp, window=10, user=None, autoassign=False):
        '''
        checks if the given OTP value is/are values of this very token.
        This is used to autoassign and to determine the serial number of
        a token.

        :param otp: the to be verified otp value
        :type otp: string

        :param window: the lookahead window for the counter
        :type window: int

        :return: counter or -1 if otp does not exist
        :rtype:  int

        '''

        log.debug("[check_otp_exist] begin. checks if the given OTP value exists: otp %r, window %r " %
                  (otp, window))
        res = -1

        try:
            otplen = int(self.token.LinOtpOtpLen)
            counter = int(self.token.LinOtpCount)
        except ValueError as ex:
            log.warning("[check_otp_exist] a value error occurred while converting: otplen %r, counter %r : ValueError: %r ret: %r "
                      % (self.token.LinOtpOtpLen, self.token.LinOtpCount, ex, res))
            return res

        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1")

        secretHOtp = self.token.getHOtpKey()
        hmac2Otp = HmacOtp(secretHOtp, counter, otplen,
                             self.getHashlib(self.hashlibStr))
        res = hmac2Otp.checkOtp(otp, window)

        if res >= 0:
            # As usually the counter is increased in lib.token.checkUserPass, we
            # need to do this manually here:
            self.incOtpCounter(res)
        if res == -1:
            msg = "otp counter %r was not found" % otp
        else:
            msg = "otp counter %r was found" % otp
        log.debug("[check_otp_exist] end. %r: res %r" % (msg, res))
        return res


    def autosync(self, hmac2Otp, anOtpVal):
        '''
        auto - sync the token based on two otp values
        - internal method to realize the autosync within the
        checkOtp method

        :param hmac2Otp: the hmac object (with reference to the token secret)
        :type hmac2Otp: hmac object

        :param anOtpVal: the actual otp value
        :type anOtpVal: string

        :return: counter or -1 if otp does not exist
        :rtype:  int

        '''
        log.debug("[autosync] begin. Autosync the token, based on: hmac2Otp: %r, anOtpVal: %r" % (hmac2Otp, anOtpVal))

        res = -1
        autosync = False

        ## get autosync from config or use False as default
        async = getFromConfig("AutoResync", False)
        # TODO: nasty:
        # The SQLite database returns AutoResync as a boolean and not as a string.
        # So the boolean has no .lower()
        if isinstance(async, bool):
            autosync = async
        else:
            if "true" == async.lower():
                autosync = True
            elif "false" == async.lower():
                autosync = False
            else:
                autosync = False

        ## if autosync is enabled
        if False == autosync:
            log.debug("[autosync] end. autosync is not enabled : res %r" % (res))
            return res

        info = self.getTokenInfo()
        syncWindow = self.getSyncWindow()

        #check if the otpval is valid in the sync scope
        res = hmac2Otp.checkOtp(anOtpVal, syncWindow)

        #if yes:
        if res != -1:
            # if former is defined
            if "otp1c" in info:
                #check if this is consecutive
                otp1c = info.get("otp1c")
                otp2c = res

                if (otp1c + 1) != otp2c:
                    res = -1

                if "dueDate" in info:
                    dueDate = info.get("dueDate")
                    now = int(time.time())
                    if dueDate <= now:
                        res = -1
                else:
                    res = -1

                ## now clean the resync data
                del info["dueDate"]
                del info["otp1c"]
                self.setTokenInfo(info)

            else:
                info["otp1c"] = res
                info["dueDate"] = int(time.time()) + self.getSyncTimeOut()
                self.setTokenInfo(info)

                res = -1

        if res == -1:
            msg = "call was not successful"
        else:
            msg = "call was successful"
        log.debug("[autosync] end. %r: res %r" % (msg, res))

        return res


    def resync(self, otp1, otp2, options=None):
        '''
        resync the token based on two otp values
        - external method to do the resync of the token

        :param otp1: the first otp value
        :type otp1: string

        :param otp2: the second otp value
        :type otp2: string

        :param options: optional token specific parameters
        :type options:  dict or None

        :return: counter or -1 if otp does not exist
        :rtype:  int

        '''
        log.debug("[resync] .begin. Resync the token based on: %r, anOtpVal: %r, options: %r" % (otp1, otp2, options))

        ret = False

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as ex:
            log.debug("[resync] otplen ValueError: %r ret: %r " % (ex, ret))
            raise Exception(ex)

        self.hashlibStr = self.getFromTokenInfo("hashlib", 'sha1')

        secretHOtp = self.token.getHOtpKey()
        counter = self.token.getOtpCounter()
        syncWindow = self.token.getSyncWindow()
        #log.debug("serial: %s",serialNum)
        hmac2Otp = HmacOtp(secretHOtp, counter, otplen, self.getHashlib(self.hashlibStr))
        counter = hmac2Otp.checkOtp(otp1, syncWindow)

        if counter == -1:
            log.debug("[resync] exit. First counter (-1) not found  ret: %r" % (ret))
            return ret

        nextOtp = hmac2Otp.generate(counter + 1)

        if nextOtp != otp2:
            log.debug("[resync] exit. Failed to verify second otp: nextOtp: %r != otp2: %r ret: %r" % (nextOtp, otp2, ret))
            return ret

        ret = True
        self.incOtpCounter(counter + 1, True)

        log.debug("[resync] end. resync was successful: ret: %r" % (ret))
        return ret

    def getSyncTimeOut(self):
        '''
        get the token sync timeout value

        :return: timeout value in seconds
        :rtype:  int
        '''
        try:
            timeOut = int(getFromConfig("AutoResyncTimeout", 5 * 60))
        except Exception as ex:
            log.warning("[getSyncTimeOut] AutoResyncTimeout: value error %r - reset to 5*60" % (ex))
            timeOut = 5 * 60

        return timeOut

    def getOtp(self, curTime=None):
        '''
        get the next OTP value

        :return: next otp value
        :rtype: string
        '''
        log.debug("[getOtp] begin. Get the next OTP value for: curTime: %r" % (curTime))

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as ex:
            log.exception("[getOtp]: Could not convert otplen - value error %r " % (ex))
            raise Exception(ex)

        self.hashlibStr = self.getFromTokenInfo("hashlib", 'sha1')
        secretHOtp = self.token.getHOtpKey()

        hmac2Otp = HmacOtp(secretHOtp, self.getOtpCount(), otplen, self.getHashlib(self.hashlibStr))
        otpval = hmac2Otp.generate(inc_counter=False)

        pin = self.token.getPin()
        combined = "%s%s" % (otpval, pin)

        if getFromConfig("PrependPin") == "True" :
            combined = "%s%s" % (pin, otpval)

        log.debug("[getOtp]  end. Return opt is: (pin: %r, otpval: %r, combined: %r) " %
                  (pin, otpval, combined))
        return (1, pin, otpval, combined)

    def get_multi_otp(self, count=0, epoch_start=0, epoch_end=0, curTime=None):
        '''
        return a dictionary of multiple future OTP values of the HOTP/HMAC token

        :param count:   how many otp values should be returned
        :type count:    int

        :return:     tuple of status: boolean, error: text and the OTP dictionary

        '''
        log.debug("[get_multi_otp] begin. Get a dictionary of multiple future OTP values for: count: %r, epoch_start: %r, epoch_end: %r, curTime: %r" %
                  (count, epoch_start, epoch_end, curTime))

        otp_dict = {"type" : "HMAC", "otp": {}}
        ret = False
        error = "No count specified"
        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as ex:
            log.exception("[get_multi_otp]: Could not convert otplen - value error %r " % (ex))
            raise Exception(ex)
        s_count = self.getOtpCount()
        secretHOtp = self.token.getHOtpKey()
        hmac2Otp = HmacOtp(secretHOtp, s_count, otplen, self.getHashlib(self.hashlibStr))
        log.debug("[get_multi_otp] retrieving %i OTP values for token %s" % (count, hmac2Otp))

        if count > 0:
            for i in range(count):
                otpval = hmac2Otp.generate(s_count + i, inc_counter=False)
                otp_dict["otp"][s_count + i] = otpval
            ret = True

        log.debug("[get_multi_otp] end. dictionary of multiple future OTP is: otp_dict: %r - status: %r - error %r" % (ret, error, otp_dict))
        return (ret, error, otp_dict)

    def getInitDetail(self, params , user=None):
        '''
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        '''
        response_detail = {}

        info = self.getInfo()
        response_detail.update(info)
        response_detail['serial'] = self.getSerial()

        tok_type = self.type.lower()

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
            try:
                p = {}
                p.update(params)
                p['otpkey'] = otpkey
                p['serial'] = self.getSerial()
                # label
                goo_url = create_google_authenticator(p, user=user)

                response_detail["googleurl"] = {
                      "order"      : '0',
                      "description": _("OTPAuth Url"),
                      "value" :     goo_url,
                      "img"   :     create_img(goo_url, width=250)
                      }

            except NoOtpAuthTokenException as exx:
                log.warning("%r" % exx)

            if user is not None:
                try:

                    oath_url = create_oathtoken_url(user.login, user.realm,
                                                    otpkey, tok_type,
                                                    serial=self.getSerial())
                    response_detail["oathurl"] = {
                           "order"      : '2',
                           "description" : _("URL for OATH token"),
                           "value" : oath_url,
                           "img"   : create_img(oath_url, width=250)
                           }
                except Exception as ex:
                    log.info('failed to set oath or google url: %r' % ex)

        return response_detail

