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
'''lib to handle mobileOTP - Implementation inspired by:
      https://github.com/neush/otpn900/blob/master/src/test_motp.c
'''

import logging
import time

from hashlib import md5

from linotp.lib.crypt import zerome



log = logging.getLogger(__name__)



class mTimeOtp(object):
    '''
    implements the motp timebased check_otp
    - s. https://github.com/neush/otpn900/blob/master/src/test_motp.c
    '''

    def __init__(self, secObj=None, secPin=None, oldtime=0, digits=6,
                 key=None, pin=None):
        '''
        constructor for the mOtp class

        :param secObj:    secretObject, which covers the encrypted secret
        :param secPin:    secretObject, which covers the encrypted pin
        :param oldtime:   the previously detected otp counter/time
        :param digits:    length of otp chars to be tested
        :param key:       direct key provider (for selfTest)
        :param pin:       direct pin provider (for selfTest)

        :return:          nothing
        '''
        self.secretObject = secObj
        self.key = key

        self.secPin = secPin
        self.pin = pin

        self.oldtime = oldtime  ## last time access
        self.digits = digits

    def checkOtp(self, anOtpVal, window=10, options=None):
        '''
        check a provided otp value

        :param anOtpVal: the to be tested otp value
        :param window: the +/- window around the test time
        :param options: generic container for additional values \
                        here only used for seltest: setting the initTime

        :return: -1 for fail else the identified counter/time
        '''

        log.debug("[checkOtp] begin. checking the otpvalue %s window:%r, \
                            options:%r" % (anOtpVal, window, options))
        res = -1
        window = window * 2

        initTime = 0
        if options is not None and type(options) == dict:
            initTime = int(options.get('initTime', 0))

        if (initTime == 0):
            otime = int(time.time() / 10)
        else:
            otime = int(initTime)


        if self.secretObject is None:
            key = self.key
            pin = self.pin
        else:
            key = self.secretObject.getKey()
            pin = self.secPin.getKey()


        for i in range(otime - window, otime + window):
            otp = unicode(self.calcOtp(i, key, pin))
            if unicode(anOtpVal) == otp:
                res = i
                log.debug("[checkOtp] otpvalue %r found at: %r" %
                            (anOtpVal, res))
                break

        if self.secretObject is not None:
            zerome(key)
            zerome(pin)
            del key
            del pin

        ## prevent access twice with last motp
        if res <= self.oldtime:
            log.warning("[checkOtp] otpvalue %s checked once before (%r<=%r)" %
                        (anOtpVal, res, self.oldtime))
            res = -1
        if res == -1:
            msg = 'checking motp failed'
        else:
            msg = 'checking motp sucess'

        log.debug("[checkOtp] end. %s : returning result: %r, " % (msg, res))
        return res

    def calcOtp(self, counter, key=None, pin=None):
        '''
        calculate an otp value from counter/time, key and pin

        :param counter:    counter/time to be checked
        :param key:        the secret key
        :param pin:        the secret pin

        :return:           the otp value
        :rtype:            string
        '''
        ## ref impl from https://github.com/szimszon/motpy/blob/master/motpy
        if pin is None:
            pin = self.pin
        if key is None:
            key = self.key

        vhash = "%d%s%s" % (counter, key, pin)
        motp = md5(vhash).hexdigest()[:self.digits]
        return motp


def motp_test():
    '''
    Testvector from
       https://github.com/neush/otpn900/blob/master/src/test_motp.c
    '''

    key = "0123456789abcdef"
    epoch = [ 129612120, 129612130, 0, 4, 129612244, 129612253]
    pins = ["6666", "6666", "1", "1", "77777777", "77777777"]
    otps = ["6ed4e4", "502a59", "bd94a4", "fb596e", "7abf75", "4d4ac4"]

    i = 0
    motp1 = mTimeOtp(key=key, pin=pins[0])
    for e in epoch:
        pin = pins[i]
        otp = otps[i]
        sotp = motp1.calcOtp(e, key, pin)

        if sotp != otp:
            print "error"
        else:
            print "ok"

        i = i + 1

    ### test our unit test values
    key = "1234567890123456"
    pin = "1234"

    timeOtp2 = mTimeOtp(key=key, pin=pin)
    ntime = timeOtp2.checkOtp("7215e7", 18, options={'iniTime':126753360})
    #expecting true
    print "result: ", ntime, " should be 126753370"

    return

if __name__ == '__main__':
    motp_test()
