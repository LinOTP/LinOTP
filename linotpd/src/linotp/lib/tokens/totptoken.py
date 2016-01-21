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
"""This file containes the dynamic time based hmac token implementation"""

import logging
import time
import math
import datetime

import traceback


from linotp.lib.HMAC    import HmacOtp
from linotp.lib.util    import getParam
from linotp.lib.util    import generate_otpkey
from linotp.lib.config  import getFromConfig


optional = True
required = False

from linotp.lib.tokenclass import TokenClass
from linotp.lib.tokens.hmactoken import HmacTokenClass

keylen = {'sha1' : 20,
          'sha256' : 32,
          'sha512' : 64
          }

log = logging.getLogger(__name__)



###############################################
###############################################
"""
TOTP Algorithm

   This variant of the HOTP algorithm specifies the calculation of a
   one-time password value, based on a representation of the counter as
   a time factor.

4.1.  Notations

   - X represents the time step in seconds (default value X = 30
   seconds) and is a system parameter;

   - T0 is the Unix time to start counting time steps (default value is
   0, Unix epoch) and is also a system parameter.

4.2.  Description

   Basically, we define TOTP as TOTP = HOTP(K, T) where T is an integer
   and represents the number of time steps between the initial counter
   time T0 and the current Unix time (i.e. the number of seconds elapsed
   since midnight UTC of January 1, 1970).

   More specifically T = (Current Unix time - T0) / X where:

   - X represents the time step in seconds (default value X = 30
   seconds) and is a system parameter;

   - T0 is the Unix time to start counting time steps (default value is
   0, Unix epoch) and is also a system parameter;

   - The default floor function is used in the computation.  For
   example, with T0 = 0 and time step X = 30, T = 1 if the current Unix
   time is 59 seconds and T = 2 if the current Unix time is 60 seconds.

M'Raihi, et al.          Expires March 12, 2011                 [Page 5]

Internet-Draft                HOTPTimeBased               September 2010


"""

###############################################
class TimeHmacTokenClass(HmacTokenClass):

    resyncDiffLimit = 3

    def __init__(self, aToken):
        '''
        constructor - create a token object

        :param aToken: instance of the orm db object
        :type aToken:  orm object

        '''
        log.debug("[init]  begin. Create a token object with: a_token %r" % (aToken))

        TokenClass.__init__(self, aToken)
        self.setType(u"TOTP")
        self.hKeyRequired = True

        ''' timeStep defines the granularity: '''
        self.timeStep = getFromConfig("totp.timeStep", 30) or 30

        ''' window size in seconds:
            30 seconds with as step width of 30 seconds results
            in a window of 1  which is one attempt
        '''
        self.timeWindow = getFromConfig("totp.timeWindow", 180) or 180


        '''the time shift is specified in seconds  - and could be
        positive and negative
        '''
        self.timeShift = getFromConfig("totp.timeShift", 0)

        '''we support various hashlib methods, but only on create
        which is effectively set in the update
        '''
        self.hashlibStr = getFromConfig("totp.hashlib", u'sha1') or 'sha1'

        log.debug("[init]  end. Token object created")
        return
    @classmethod
    def getClassType(cls):
        '''
        getClassType - return the token type shortname

        :return: 'totp'
        :rtype: string

        '''
        return "totp"

    @classmethod
    def getClassPrefix(cls):
        return "TOTP"


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
               'type'           : 'totp',
               'title'          : 'HMAC Time Token',
               'description'    : ('time based otp token using the hmac algorithm'),

               'init'         : {'page' : {'html'      : 'totptoken.mako',
                                            'scope'      : 'enroll', },
                                   'title'  : {'html'      : 'totptoken.mako',
                                             'scope'     : 'enroll.title', },
                                   },

               'config'        : { 'page' : {'html'      : 'totptoken.mako',
                                            'scope'      : 'config', },
                                   'title'  : {'html'      : 'totptoken.mako',
                                             'scope'     : 'config.title', },
                                 },

               'selfservice'   :  { 'enroll' : {'page' : {'html'       : 'totptoken.mako',
                                                          'scope'      : 'selfservice.enroll', },
                                               'title'  : { 'html'      : 'totptoken.mako',
                                                         'scope'      : 'selfservice.title.enroll', },
                                                  },
                                  },
               'policy' : {
                    'selfservice' : {
                        'totp_timestep': {
                            'type':'int',
                            'value' : [30, 60],
                            'desc' : 'Specify the time step of the timebased OTP token.'
                                  },
                       'totp_hashlib' : {'type':'int',
                          'value' : [1, 2],
                          'desc' : 'Specify the hashlib to be used. Can be sha1 (1) or sha2-256 (2).'
                            },


                           },
                        },
               }

        if key is not None and res.has_key(key):
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        log.debug("[getClassInfo] end. Returned the configuration section: ret %r " % (ret))
        return ret



    def update(self, param):
        '''
        update - process the initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing
        '''
        log.debug("[update] begin. Process the initialization parameters: param %r" % (param))

        ## check for the required parameters
        val = getParam(param, "hashlib", optional)
        if val is not None:
            self.hashlibStr = val
        else:
            self.hashlibStr = 'sha1'

        otpKey = ''

        if (self.hKeyRequired == True):
            genkey = int(getParam(param, "genkey", optional) or 0)
            if 1 == genkey:
                # if hashlibStr not in keylen dict, this will raise an Exception
                otpKey = generate_otpkey(keylen.get(self.hashlibStr))
                del param['genkey']
            else:
                # genkey not set: check otpkey is given
                # this will raise an exception if otpkey is not present
                otpKey = getParam(param, "otpkey", required)

        # finally set the values for the update
        param['otpkey'] = otpKey
        param['hashlib'] = self.hashlibStr

        val = getParam(param, "otplen", optional)
        if val is not None:
            self.setOtpLen(int(val))
        else:
            self.setOtpLen(getFromConfig("DefaultOtpLen"))

        val = getParam(param, "timeStep", optional)
        if val is not None:
            self.timeStep = val

        val = getParam(param, "timeWindow", optional)
        if val is not None:
            self.timeWindow = val

        val = getParam(param, "timeShift", optional)
        if val is not None:
            self.timeShift = val

        HmacTokenClass.update(self, param)

        if self.timeWindow is not None and self.timeWindow != '':
            self.addToTokenInfo("timeWindow", self.timeWindow)
        if self.timeShift is not None and self.timeShift != '':
            self.addToTokenInfo("timeShift", self.timeShift)
        if self.timeStep is not None and self.timeStep != '':
            self.addToTokenInfo("timeStep", self.timeStep)
        if self.hashlibStr:
            self.addToTokenInfo("hashlib", self.hashlibStr)

        log.debug("[update]  end. Processing the initialization parameters done.")
        return

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
            counter = int(self.token.LinOtpCount)
        except ValueError as ex:
            log.warning("[check_otp_exist] a value error occurred while converting: counter %r : ValueError: %r ret: %r "
                      % (self.token.LinOtpCount, ex, res))
            return res

        res = self.checkOtp(otp, counter, range)

        return res

    def _time2counter_(self, T0, timeStepping=60):
        rnd = 0.5
        counter = int((T0 / timeStepping) + rnd)
        return counter

    def _counter2time_(self, counter, timeStepping=60):
        rnd = 0.5
        T0 = (float(counter) - rnd) * timeStepping
        return T0

    def _getTimeFromCounter(self, counter, timeStepping=30, rnd=1):
        idate = int(counter - rnd) * timeStepping
        ddate = datetime.datetime.fromtimestamp(idate / 1.0)
        return ddate

    def time2float(self, curTime):
        '''
        time2float - convert a datetime object or an datetime sting into a float
        s. http://bugs.python.org/issue12750

        :param curTime: time in datetime format
        :type curTime: datetime object

        :return: time as float
        :rtype: float
        '''
        log.debug("[time2float] begin. Convert a datetime object: curTime %r" %
                  (curTime))

        dt = datetime.datetime.now()
        if type(curTime) == datetime.datetime:
            dt = curTime
        elif type(curTime) == unicode:
            if '.' in curTime:
                tFormat = "%Y-%m-%d %H:%M:%S.%f"
            else:
                tFormat = "%Y-%m-%d %H:%M:%S"
            try:
                dt = datetime.datetime.strptime(curTime, tFormat)
            except Exception as ex:
                log.exception('[time2float] Error during conversion of datetime: %r' % (ex))
                raise Exception(ex)
        else:
            log.error("[time2float] invalid curTime: %s. You need to specify a datetime.datetime" % type(curTime))
            raise Exception("[time2float] invalid curTime: %s. You need to specify a datetime.datetime" % type(curTime))

        td = (dt - datetime.datetime(1970, 1, 1))
        ## for python 2.6 compatibility, we have to implement 2.7 .total_seconds()::
        ## TODO: fix to float!!!!
        tCounter = ((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) * 1.0) / 10 ** 6

        log.debug("[time2float] end. Datetime object converted: tCounter %r" %
                  (tCounter))
        return tCounter



    def checkOtp(self, anOtpVal, counter, window, options=None):
        '''
        checkOtp - validate the token otp against a given otpvalue

        :param anOtpVal: the to be verified otpvalue
        @type anOtpVal:  string

        :param counter: the counter state, that should be verified
        :type counter: int

        :param window: the counter +window, which should be checked
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or -1
        :rtype: int

        '''

        log.debug("[checkOtp] begin. Validate the token otp: anOtpVal: %r ,\
                    counter: %r,window: %r, options: %r " %
                    (anOtpVal, counter, window, options))

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as e:
            raise e

        secretHOtp = self.token.getHOtpKey()
        self.hashlibStr = self.getFromTokenInfo("hashlib", self.hashlibStr) or 'sha1'

        timeStepping = int(self.getFromTokenInfo("timeStep", self.timeStep) or 30)
        window = int(self.getFromTokenInfo("timeWindow", self.timeWindow) or 180)
        shift = int(self.getFromTokenInfo("timeShift", self.timeShift) or 0)

        ## oldCounter we have to remove one, as the normal otp handling will increment
        oCount = self.getOtpCount() - 1

        initTime = -1
        if options != None and type(options) == dict:
            initTime = int(options.get('initTime', -1))

        if oCount < 0: oCount = 0
        log.debug("[checkOTP] timestep: %i, timeWindow: %i, timeShift: %i" %
                  (timeStepping, window, shift))
        inow = int(time.time())

        T0 = time.time() + shift
        if initTime != -1: T0 = int(initTime)


        log.debug("[checkOTP] T0 : %i" % T0)
        counter = self._time2counter_(T0, timeStepping=timeStepping)


        otime = self._getTimeFromCounter(oCount, timeStepping=timeStepping)
        ttime = self._getTimeFromCounter(counter, timeStepping=timeStepping)

        log.debug("[checkOTP] last log: %r :: %r" % (oCount, otime))
        log.debug("[checkOTP] counter : %r :: %r <==> %r" %
                  (counter, ttime, datetime.datetime.now()))


        log.debug("[checkOTP] shift   : %r " % (shift))

        hmac2Otp = HmacOtp(secretHOtp, counter, otplen, self.getHashlib(self.hashlibStr))
        res = hmac2Otp.checkOtp(anOtpVal, int (window / timeStepping), symetric=True)

        log.debug("[checkOTP] comparing the result %i to the old counter %i." % (res, oCount))
        if res != -1 and oCount != 0 and res <= oCount:
            if initTime == -1:
                log.warning("[checkOTP] a previous OTP value was used again!\n former tokencounter: %i, presented counter %i" %
                        (oCount, res))
                res = -1
                return res

        if -1 == res :
            ## autosync: test if two consecutive otps have been provided
            res = self.autosync(hmac2Otp, anOtpVal)


        if res != -1:
            ## on success, we have to save the last attempt
            self.setOtpCount(counter)

            #
            # here we calculate the new drift/shift between the server time and the tokentime
            #
            tokentime = self._counter2time_(res, timeStepping)
            tokenDt = datetime.datetime.fromtimestamp(tokentime / 1.0)

            nowDt = datetime.datetime.fromtimestamp(inow / 1.0)

            lastauth = self._counter2time_(oCount, timeStepping)
            lastauthDt = datetime.datetime.fromtimestamp(lastauth / 1.0)

            log.debug("[checkOTP] last auth : %r" % (lastauthDt))
            log.debug("[checkOTP] tokentime : %r" % (tokenDt))
            log.debug("[checkOTP] now       : %r" % (nowDt))
            log.debug("[checkOTP] delta     : %r" % (tokentime - inow))

            new_shift = (tokentime - inow)
            log.debug("[checkOTP] the counter %r matched. New shift: %r" %
                      (res, new_shift))
            self.addToTokenInfo('timeShift', new_shift)

        log.debug("[checkOtp] end. otp verification result was: res %r" % (res))
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

        try:
            async = getFromConfig("AutoResync")
            if async is None:
                autosync = False
            elif "true" == async.lower():
                autosync = True
            elif "false" == async.lower():
                autosync = False
        except Exception as e:
            log.exception('autosync check failed %r' % e)
            return res

        ' if autosync is not enabled: do nothing '
        if False == autosync:
            return res

        info = self.getTokenInfo();
        syncWindow = self.getSyncWindow()

        #check if the otpval is valid in the sync scope
        res = hmac2Otp.checkOtp(anOtpVal, syncWindow, symetric=True)
        log.debug("[autosync] found otpval %r in syncwindow (%r): %r" %
                  (anOtpVal, syncWindow, res))

        #if yes:
        if res != -1:
            # if former is defined
            if (info.has_key("otp1c")):
                #check if this is consecutive
                otp1c = info.get("otp1c");
                otp2c = res
                log.debug("[autosync] otp1c: %r, otp2c: %r" % (otp1c, otp2c))
                diff = math.fabs(otp2c - otp1c)
                if (diff > self.resyncDiffLimit):
                    res = -1
                else:
                    T0 = time.time()
                    timeStepping = int(self.getFromTokenInfo("timeStep"))
                    counter = int((T0 / timeStepping) + 0.5)

                    shift = otp2c - counter
                    info["timeShift"] = shift
                    self.setTokenInfo(info)


                ## now clean the resync data
                del info["otp1c"]
                self.setTokenInfo(info)

            else:
                log.debug("[autosync] setting otp1c: %s" % res)
                info["otp1c"] = res
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
        except ValueError:
            return ret


        secretHOtp = self.token.getHOtpKey()

        self.hashlibStr = self.getFromTokenInfo("hashlib", 'sha1')
        timeStepping = int(self.getFromTokenInfo("timeStep", 30))
        shift = int(self.getFromTokenInfo("timeShift", 0))

        try:
            window = int(self.token.LinOtpSyncWindow) * timeStepping
        except:
            window = 10 * timeStepping

        log.debug("[resync] timestep: %r, syncWindow: %r, timeShift: %r"
                  % (timeStepping, window, shift))


        T0 = time.time() + shift

        log.debug("[resync] T0 : %i" % T0)
        counter = int((T0 / timeStepping) + 0.5)  # T = (Current Unix time - T0) / timeStepping
        log.debug("[resync] counter (current time): %i" % counter)

        oCount = self.getOtpCount()

        log.debug("[resync] tokenCounter: %r" % oCount)
        log.debug("[resync] now checking window %s, timeStepping %s" % (window, timeStepping))
        # check 2nd value
        hmac2Otp = HmacOtp(secretHOtp, counter, otplen, self.getHashlib(self.hashlibStr))
        log.debug("[resync] %s in otpkey: %s " % (otp2, secretHOtp))
        res2 = hmac2Otp.checkOtp(otp2, int (window / timeStepping), symetric=True)  #TEST -remove the 10
        log.debug("[resync] res 2: %r" % res2)
        # check 1st value
        hmac2Otp = HmacOtp(secretHOtp, counter - 1, otplen, self.getHashlib(self.hashlibStr))
        log.debug("[resync] %s in otpkey: %s " % (otp1, secretHOtp))
        res1 = hmac2Otp.checkOtp(otp1, int (window / timeStepping), symetric=True)  #TEST -remove the 10
        log.debug("[resync] res 1: %r" % res1)

        if res1 < oCount:
            # A previous OTP value was used again!
            log.warning("[resync] a previous OTP value was used again! tokencounter: %i, presented counter %i" %
                        (oCount, res1))
            res1 = -1

        if res1 != -1 and res1 + 1 == res2:
            # here we calculate the new drift/shift between the server time and the tokentime
            tokentime = (res2 + 0.5) * timeStepping
            currenttime = T0 - shift
            new_shift = (tokentime - currenttime)
            log.debug("[resync] the counters %r and %r matched. New shift: %r"
                       % (res1, res2, new_shift))
            self.addToTokenInfo('timeShift', new_shift)

            # The OTP value that was used for resync must not be used again!
            self.setOtpCount(res2 + 1)

            ret = True

        if ret == True:
            msg = "resync was successful"
        else:
            msg = "resync was not successful"

        log.debug("[resync] end. %s: ret: %r" % (msg, ret))
        return ret

    def getSyncTimeOut(self):
        '''
        get the token sync timeout value

        :return: timeout value in seconds
        :rtype:  int
        '''

        timeOut = int(getFromConfig("AutoResyncTimeout", 5 * 60))
        return timeOut


    def getOtp(self, curTime=None):
        '''
        get the next OTP value

        :return: next otp value
        :rtype: string
        '''
        log.debug("[getOtp] begin. Get the next OTP value for: curTime: %r" % (curTime))

        res = (-1, 0, 0, 0)

        otplen = int(self.token.LinOtpOtpLen)
        secretHOtp = self.token.getHOtpKey()
        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1") or 'sha1'
        timeStepping = int(self.getFromTokenInfo("timeStep", 30) or 30)
        shift = int(self.getFromTokenInfo("timeShift", 0) or 0)

        hmac2Otp = HmacOtp(secretHOtp, self.getOtpCount(), otplen, self.getHashlib(self.hashlibStr))

        tCounter = self.time2float(datetime.datetime.now())
        if curTime:
            tCounter = self.time2float(curTime)

        ## we don't need to round here as we have alread float
        counter = int(((tCounter - shift) / timeStepping))
        otpval = hmac2Otp.generate(counter=counter, inc_counter=False)

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

        otp_dict = {"type" : "TOTP", "otp": {}}
        ret = False
        error = "No count specified"
        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError:
            return ret

        secretHOtp = self.token.getHOtpKey()

        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1") or 'sha1'
        timeStepping = int(self.getFromTokenInfo("timeStep", 30) or 30)
        shift = int(self.getFromTokenInfo("timeShift", 0) or 0)

        hmac2Otp = HmacOtp(secretHOtp, self.getOtpCount(),
                           otplen, self.getHashlib(self.hashlibStr))

        tCounter = self.time2float(datetime.datetime.now())
        if curTime:
            tCounter = self.time2float(curTime)

        ## we don't need to round here as we have alread float
        counter = int(((tCounter - shift) / timeStepping))


        otp_dict["shift"] = shift
        otp_dict["timeStepping"] = timeStepping

        if count > 0:
            for i in range(0, count):
                otpval = hmac2Otp.generate(counter=counter + i, inc_counter=False)
                timeCounter = ((counter + i) * timeStepping) + shift
                otp_dict["otp"][ counter + i] = {
                     'otpval' : otpval,
                     'time'  : datetime.datetime.fromtimestamp(timeCounter).strftime("%Y-%m-%d %H:%M:%S"),
                    }
            ret = True

        log.debug("[get_multi_otp] end. dictionary of multiple future OTP is: otp_dict: %r - status: %r - error %r" % (ret, error, otp_dict))
        return (ret, error, otp_dict)


