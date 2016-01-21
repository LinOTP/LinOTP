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
"""
 This file contains the database definition / database model for linotp objects
"""


import binascii
import logging
import traceback
from datetime import datetime

try:
    import json
except ImportError:
    import simplejson as json


"""The application's model objects"""
import sqlalchemy as sa

from sqlalchemy import orm
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relation

import linotp

from linotp.model import meta
from linotp.model.meta import Session
from linotp.model.meta import MetaData

from linotp.lib.crypt import geturandom
from linotp.lib.crypt import encrypt, hash, SecretObj
from linotp.lib.crypt import encryptPin
from linotp.lib.crypt import decryptPin
from linotp.lib.crypt import get_rand_digit_str


from pylons import config
log = logging.getLogger(__name__)

implicit_returning = config.get('linotpSQL.implicit_returning', True)

## for oracle we need a mapping of columns
## due to reserved keywords 'session' and 'timestamp'
COL_PREFIX = ""
SQLU = config.get("sqlalchemy.url", "")
if SQLU.startswith("oracle:"):
    COL_PREFIX = config.get("oracle.sql.column_prefix", "lino")


session_column = "%ssession" % COL_PREFIX
timestamp_column = "%stimestamp" % COL_PREFIX

def init_model(engine):
    """
    init_model binds the table objects to the class objects
    - to be called before using any of the tables or classes in the model!!!

    :param engine: the sql engine
    """
    log.debug('model init: init_model')

    meta.engine = engine
    meta.Session.configure(bind=engine)

    log.debug('model init: init_model')
    return

token_table = sa.Table('Token', meta.metadata,
                sa.Column('LinOtpTokenId', sa.types.Integer(), sa.Sequence('token_seq_id', optional=True), primary_key=True, nullable=False),
                sa.Column('LinOtpTokenDesc', sa.types.Unicode(80), default=u''),
                sa.Column('LinOtpTokenSerialnumber', sa.types.Unicode(40), default=u'', unique=True, nullable=False, index=True),

                sa.Column('LinOtpTokenType', sa.types.Unicode(30), default=u'HMAC', index=True),
                sa.Column('LinOtpTokenInfo', sa.types.Unicode(2000), default=u''),
                sa.Column('LinOtpTokenPinUser', sa.types.Unicode(512), default=u''),  ## encrypt
                sa.Column('LinOtpTokenPinUserIV', sa.types.Unicode(32), default=u''),  ## encrypt
                sa.Column('LinOtpTokenPinSO', sa.types.Unicode(512), default=u''),  ## encrypt
                sa.Column('LinOtpTokenPinSOIV', sa.types.Unicode(32), default=u''),  ## encrypt

                sa.Column('LinOtpIdResolver', sa.types.Unicode(120), default=u'', index=True),
                sa.Column('LinOtpIdResClass', sa.types.Unicode(120), default=u''),
                sa.Column('LinOtpUserid', sa.types.Unicode(320), default=u'', index=True),


                sa.Column('LinOtpSeed', sa.types.Unicode(32), default=u''),
                sa.Column('LinOtpOtpLen', sa.types.Integer(), default=6),
                sa.Column('LinOtpPinHash', sa.types.Unicode(512), default=u''),  ## hashed
                sa.Column('LinOtpKeyEnc', sa.types.Unicode(1024), default=u''),  ## encrypt
                sa.Column('LinOtpKeyIV', sa.types.Unicode(32), default=u''),

                sa.Column('LinOtpMaxFail', sa.types.Integer(), default=10),
                sa.Column('LinOtpIsactive', sa.types.Boolean(), default=True),
                sa.Column('LinOtpFailCount', sa.types.Integer(), default=0),
                sa.Column('LinOtpCount', sa.types.Integer(), default=0),
                sa.Column('LinOtpCountWindow', sa.types.Integer(), default=10),
                sa.Column('LinOtpSyncWindow', sa.types.Integer(), default=1000),
                implicit_returning=implicit_returning,
                )

TOKEN_ENCODE = ["LinOtpTokenDesc", "LinOtpTokenSerialnumber",
                "LinOtpTokenInfo", "LinOtpUserid", "LinOtpIdResClass",
                "LinOtpIdResolver"]

class Token(object):

    def __init__(self, serial):

        log.debug(' __init__(%s)' % serial)

        ## self.LinOtpTokenId - will be generated DBType serial
        self.LinOtpTokenSerialnumber = u'' + serial

        self.LinOtpTokenType = u''

        self.LinOtpCount = 0
        self.LinOtpFailCount = 0
        # get maxFail should have a configurable default
        self.LinOtpMaxFail = 10
        self.LinOtpIsactive = True
        self.LinOtpCountWindow = 10
        self.LinOtpOtpLen = 6
        self.LinOtpSeed = u''

        self.LinOtpIdResolver = None
        self.LinOtpIdResClass = None
        self.LinOtpUserid = None

        # will be assigned automaticaly
        # self.LinOtpTokenId      = 0
        log.debug('Token init done')

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the assci encode default

        :param name: db column name or class memeber
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in TOKEN_ENCODE:
            ## encode data
            if value:
                value = linotp.lib.crypt.uencode(value)
        super(Token, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the assci decode default

        :param name: db column name or class memeber

        :return: the corresponding value
        """
        #Default behaviour
        value = object.__getattribute__(self, name)
        if name in TOKEN_ENCODE:
            if value:
                value = linotp.lib.crypt.udecode(value)
            else:
                value = ""
        # port of the 2.6. resolver to 2.7
        if name in ['LinOtpIdResClass']:
            if value[:len('useridresolveree.')] == 'useridresolveree.':
                value = "useridresolver.%s" % value[len('useridreseolveree.') - 1:]

        return value


    def _fix_spaces(self, data):
        '''
        On MS SQL server empty fields ("") like the LinOtpTokenInfo
        are returned as a string with a space (" ").
        This functions helps fixing this.
        Also avoids running into errors, if the data is a None Type.

        :param data: a string from teh database
        :type data: usually a string
        :return: a stripped string
        '''
        if data:
            data = data.strip()

        return data

    def getSerial(self):
        return self.LinOtpTokenSerialnumber

    def setHKey(self, hOtpKey, reset_failcount=True):
        log.debug('setHKey()')
        iv = geturandom(16)
        #bhOtpKey            = binascii.unhexlify(hOtpKey)
        enc_otp_key = encrypt(hOtpKey, iv)
        self.LinOtpKeyEnc = unicode(binascii.hexlify(enc_otp_key))
        self.LinOtpKeyIV = unicode(binascii.hexlify(iv))
        self.LinOtpCount = 0
        if True == reset_failcount:
            self.LinOtpFailCount = 0

    def setUserPin(self, userPin):
        log.debug('setUserPin()')
        iv = geturandom(16)
        enc_userPin = encrypt(userPin, iv)
        self.LinOtpTokenPinUser = unicode(binascii.hexlify(enc_userPin))
        self.LinOtpTokenPinUserIV = unicode(binascii.hexlify(iv))


    def getHOtpKey(self):
        log.debug('getHOtpKey()')
        key = binascii.unhexlify(self.LinOtpKeyEnc or '')
        iv = binascii.unhexlify(self.LinOtpKeyIV or '')
        secret = SecretObj(key, iv)
        return secret

    def getOtpCounter(self):
        return self.LinOtpCount or 0

    def getUserPin(self):
        log.debug('getHOtpKey()')
        pu = self.LinOtpTokenPinUser or ''
        puiv = self.LinOtpTokenPinUserIV or ''
        key = binascii.unhexlify(pu)
        iv = binascii.unhexlify(puiv)
        secret = SecretObj(key, iv)
        return secret

    def setHashedPin(self, pin):
        log.debug('setHashedPin()')
        seed = geturandom(16)
        self.LinOtpSeed = unicode(binascii.hexlify(seed))
        self.LinOtpPinHash = unicode(binascii.hexlify(hash(pin, seed)))
        return self.LinOtpPinHash

    def getHashedPin(self, pin):
        # TODO: we could log the PIN here.
        log.debug('getHashedPin()')

        ## calculate a hash from a pin
        # Fix for working with MS SQL servers
        # MS SQL servers sometimes return a '<space>' when the column is empty: ''
        seed_str = self._fix_spaces(self.LinOtpSeed or '')
        seed = binascii.unhexlify(seed_str)
        hPin = hash(pin, seed)
        log.debug("[getHashedPin] hPin: %s, pin: %s, seed: %s" %
                  (binascii.hexlify(hPin), pin, self.LinOtpSeed or ''))
        return binascii.hexlify(hPin)

    def setDescription(self, desc):
        log.debug('setDescription(%s)' % desc)
        if desc is None:
            desc = ""
        self.LinOtpTokenDesc = unicode(desc)
        return self.LinOtpTokenDesc

    def setOtpLen(self, otplen):
        log.debug('setOtpLen %i' % int(otplen))
        self.LinOtpOtpLen = int(otplen)

    def setPin(self, pin, hashed=True):
        # TODO: we could log the PIN here
        log.debug("setPin()")

        upin = ""
        if pin != "" and pin is not None:
            upin = pin
        if hashed == True:
            self.setHashedPin(upin)
            log.debug("setPin(HASH:%r)" % self.LinOtpPinHash)
        elif hashed == False:
            self.LinOtpPinHash = "@@" + encryptPin(upin)
            log.debug("setPin(ENCR:%r)" % self.LinOtpPinHash)
        return self.LinOtpPinHash

    def comparePin(self, pin):
        log.debug("[comparePin] entering comparePin")
        res = False

        ## check for a valid input
        if pin is None:
            log.error("[comparePin] no valid PIN!")
            return res

        if self.LinOtpPinHash:
            if self.isPinEncrypted():
                log.debug("[comparePin] we got an encrypted PIN!")
                tokenPin = self.LinOtpPinHash[2:]
                decryptTokenPin = decryptPin(tokenPin)
                if decryptTokenPin == pin:
                    res = True
            else:
                log.debug("[comparePin] we got a hashed PIN!")
                ## is there a hashed pin
                hashed_pin = self.getHashedPin(pin)
                if hashed_pin == self.LinOtpPinHash:
                    res = True

        else: ## token hashed pin is empyt or none
            log.debug("[comparePin] there is no pin for this token!")
            if pin == '':
                res = True

        return res

    def deleteToken(self):
        log.debug('deleteToken()')
        ## some dbs (eg. DB2) runs in deadlock, if the TokenRealm entry
        ## is deleteted via foreign key relation
        ## so we delete it explicit
        Session.query(TokenRealm).filter(TokenRealm.token_id == self.LinOtpTokenId).delete()
        Session.delete(self)
        log.debug('delete token success')
        return True


    def isPinEncrypted(self, pin=None):
        ret = False
        if pin is None:
            pin = self.LinOtpPinHash
        if pin and pin.startswith("@@"):
            ret = True
        return ret

    def getPin(self):
        ret = -1
        if self.isPinEncrypted() == True:
            tokenPin = self.LinOtpPinHash[2:]
            ret = decryptPin(tokenPin)
        return ret

    def setSoPin(self, soPin):
        # TODO: we could log the PIN here
        log.debug('setSoPin()')
        iv = geturandom(16)
        enc_soPin = encrypt(soPin, iv)
        self.LinOtpTokenPinSO = unicode(binascii.hexlify(enc_soPin))
        self.LinOtpTokenPinSOIV = unicode(binascii.hexlify(iv))


    def __unicode__(self):
        return self.LinOtpTokenDesc

    def get(self, key=None, fallback=None, save=False):
        '''
        simulate the dict behaviour to make challenge processing
        easier, as this will have to deal as well with
        'dict only challenges'

        :param key: the attribute name - in case of key is not provided, a dict
                    of all class attributes are returned
        :param fallback: if the attribute is not found, the fallback is returned
        :param save: in case of all attributes and save==True, the timestamp is
                     converted to a string representation
        '''
        if key == None:
            return self.get_vars(save=save)

        if hasattr(self, key):
            kMethod = "get" + key.capitalize()
            if hasattr(self, kMethod):
                return getattr(self, kMethod)()
            else:
                return getattr(self, key) or ''
        else:
            return fallback


    def get_vars(self, save=False):
        log.debug('get_vars()')

        ret = {}
        ret['LinOtp.TokenId'] = self.LinOtpTokenId or ''
        ret['LinOtp.TokenDesc'] = self.LinOtpTokenDesc or ''
        ret['LinOtp.TokenSerialnumber'] = self.LinOtpTokenSerialnumber or ''

        ret['LinOtp.TokenType'] = self.LinOtpTokenType or 'hmac'
        ret['LinOtp.TokenInfo'] = self._fix_spaces(self.LinOtpTokenInfo or '')
        # ret['LinOtpTokenPinUser']   = self.LinOtpTokenPinUser
        # ret['LinOtpTokenPinSO']     = self.LinOtpTokenPinSO

        ret['LinOtp.IdResolver'] = self.LinOtpIdResolver or ''
        ret['LinOtp.IdResClass'] = self.LinOtpIdResClass or ''
        ret['LinOtp.Userid'] = self.LinOtpUserid or ''
        ret['LinOtp.OtpLen'] = self.LinOtpOtpLen or 6
        # ret['LinOtp.PinHash']        = self.LinOtpPinHash

        ret['LinOtp.MaxFail'] = self.LinOtpMaxFail
        ret['LinOtp.Isactive'] = self.LinOtpIsactive
        ret['LinOtp.FailCount'] = self.LinOtpFailCount
        ret['LinOtp.Count'] = self.LinOtpCount
        ret['LinOtp.CountWindow'] = self.LinOtpCountWindow
        ret['LinOtp.SyncWindow'] = self.LinOtpSyncWindow

        # list of Realm names
        ret['LinOtp.RealmNames'] = self.getRealmNames()

        return ret

    __str__ = __unicode__

    def __repr__(self):
        '''
        return the token state as text

        :return: token state as string representation
        :rtype:  string
        '''
        ldict = {}
        for attr in self.__dict__:
            key = "%r" % attr
            val = "%r" % getattr(self, attr)
            ldict[key] = val
        res = "<%r %r>" % (self.__class__, ldict)
        return res

    def getSyncWindow(self):
        return self.LinOtpSyncWindow

    def setCountWindow(self, counter):
        self.LinOtpCountWindow = counter

    def getCountWindow(self):
        return self.LinOtpCountWindow

    def getInfo(self):
        # Fix for working with MS SQL servers
        # MS SQL servers sometimes return a '<space>' when the column is empty: ''
        return self._fix_spaces(self.LinOtpTokenInfo or '')

    def setInfo(self, info):
        self.LinOtpTokenInfo = info

    def _setPin(self, pin, hashed=True):
        log.debug("_setPin(%s)" % pin)
        if pin is None or pin == "":
            log.debug("Token pin was None")
        else:
            self.setPin(pin, hashed)

    def storeToken(self):
        if self.LinOtpUserid is None:
            self.LinOtpUserid = u''
        if self.LinOtpIdResClass is None:
            self.LinOtpIdResClass = ''
        if self.LinOtpIdResolver is None:
            self.LinOtpIdResolver = ''

        log.debug('storeToken()')
        Session.add(self)
        Session.flush()
        Session.commit()
        log.debug('store token success')
        return True

    def setType(self, typ):
        self.LinOtpTokenType = typ
        return

    def getType(self):
        return self.LinOtpTokenType or 'hmac'

    def updateType(self, typ):
        #in case the prevoius has been different type
        # we must reset the counters
        # But be aware, ray, this could also be upper and lower case mixing...
        if self.LinOtpTokenType.lower() != typ.lower() :
            self.LinOtpCount = 0
            self.LinOtpFailCount = 0

        self.LinOtpTokenType = typ
        return

    def updateOtpKey(self, otpKey):
        #in case of a new hOtpKey we have to do some more things
        if (otpKey is not None):
            secretObj = self.getHOtpKey()
            if secretObj.compare(otpKey) == False:
                log.debug('update token OtpKey - counter reset')
                self.setHKey(otpKey)

    def updateToken(self, tokenDesc, otpKey, pin):
        log.debug('updateToken()')

        self.setDescription(tokenDesc)
        self._setPin(pin)
        self.updateOtpKey(otpKey)

    def getRealms(self):
        return self.realms or ''

    def getRealmNames(self):
        r_list = []
        for r in self.realms:
            r_list.append(r.name)
        return r_list

    def addRealm(self, realm):
        if realm is not None:
            self.realms.append(realm)
        else:
            log.error("adding empty realm!")

    def setRealms(self, realms):
        if realms is not None:
            self.realms = realms
        else:
            log.error("assigning empty realm!")

def createToken(serial):
    log.debug('createToken(%s)' % serial)
    serial = u'' + serial
    token = Token(serial)
    log.debug('token object created')

    return token

###############################################################################

config_table = sa.Table('Config', meta.metadata,
                sa.Column('Key', sa.types.Unicode(255), primary_key=True, nullable=False),
                sa.Column('Value', sa.types.Unicode(2000), default=u''),
                sa.Column('Type', sa.types.Unicode(2000), default=u''),
                sa.Column('Description', sa.types.Unicode(2000), default=u''),
                implicit_returning=implicit_returning,
                )

log.debug('config table append_column')

CONFIG_ENCODE = ["Key", "Value", "Description"]

class Config(object):

    def __init__(self, Key, Value, Type=u'', Description=u''):
        log.debug('__init__')


        if (not Key.startswith("linotp.") and not Key.startswith("enclinotp.")):
            Key = "linotp." + Key

        self.Key = unicode(Key)
        self.Value = unicode(Value)
        self.Type = unicode(Type)
        self.Description = unicode(Description)

        log.debug('Config init')

    def __unicode__(self):
        return self.Description

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the assci encode default

        :param name: db column name or class memeber
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in CONFIG_ENCODE:
            ## encode data
            if value:
                value = linotp.lib.crypt.uencode(value)
        super(Config, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the assci decode default

        :param name: db column name or class memeber

        :return: the corresponding value
        """
        #Default behaviour
        value = object.__getattribute__(self, name)
        if name in CONFIG_ENCODE:
            if value:
                value = linotp.lib.crypt.udecode(value)
            else:
                value = ""

        return value

    __str__ = __unicode__


# This table connect a token to several realms
tokenrealm_table = sa.Table('TokenRealm', meta.metadata,
                sa.Column('id', sa.types.Integer(), sa.Sequence('tokenrealm_seq_id', optional=True), primary_key=True, nullable=False),
                sa.Column('token_id', sa.types.Integer(), ForeignKey('Token.LinOtpTokenId')),
                #sa.Column('realm_id', sa.types.Integer())
                sa.Column('realm_id', sa.types.Integer(), ForeignKey('Realm.id')),
                implicit_returning=implicit_returning,
                )

class TokenRealm(object):

    def __init__(self, realmid):
        log.debug("setting realm_id to %i" % realmid)
        self.realm_id = realmid
        self.token_id = 0


realm_table = sa.Table('Realm', meta.metadata,
                sa.Column('id', sa.types.Integer(), sa.Sequence('realm_seq_id', optional=True), primary_key=True, nullable=False),
                sa.Column('name', sa.types.Unicode(255), default=u'', unique=True, nullable=False),
                sa.Column('default', sa.types.Boolean(), default=False),
                sa.Column('option', sa.types.Unicode(40), default=u''),
                implicit_returning=implicit_returning,
                )

REALM_ENCODE = ["name", "option"]

class Realm(object):

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the assci encode default

        :param name: db column name or class memeber
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in REALM_ENCODE:
            ## encode data
            if value:
                value = linotp.lib.crypt.uencode(value)
        super(Realm, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the assci decode default

        :param name: db column name or class memeber

        :return: the corresponding value
        """
        #Default behaviour
        value = object.__getattribute__(self, name)
        if name in REALM_ENCODE:
            if value:
                value = linotp.lib.crypt.udecode(value)
            else:
                value = ""

        return value

    def __init__(self, realm):
        log.debug("setting realm name to %s" % realm)
        self.name = realm
        if realm is not None:
            self.name = realm.lower()
        #self.id     = 0

    def storeRealm(self):
        if self.name is None:
            self.name = ''
        self.name = self.name.lower()
        log.debug('storeRealm()')
        Session.add(self)
        Session.commit()
        log.debug('store realm success')
        return True


''' ''' '''
ocra challenges are stored
''' ''' '''

log.debug('creating ocra table')


ocra_table = sa.Table('ocra', meta.metadata,
                sa.Column('id', sa.types.Integer(), sa.Sequence('token_seq_id', optional=True), primary_key=True, nullable=False),
                sa.Column('transid', sa.types.Unicode(20), unique=True,
                                                nullable=False, index=True),
                sa.Column('data', sa.types.Unicode(512), default=u''),
                sa.Column('challenge', sa.types.Unicode(256), default=u''),
                sa.Column(session_column, sa.types.Unicode(512), default=u''),
                sa.Column('tokenserial', sa.types.Unicode(64), default=u''),
                sa.Column(timestamp_column, sa.types.DateTime, default=datetime.now()),
                sa.Column('received_count', sa.types.Integer(), default=0),
                sa.Column('received_tan', sa.types.Boolean, default=False),
                sa.Column('valid_tan', sa.types.Boolean, default=False),
                implicit_returning=implicit_returning,
                )

OCRA_ENCODE = ["data", "challenge", "tokenserial"]

class OcraChallenge(object):
    '''
    '''
    def __init__(self, transId, challenge, tokenserial, data, session=u''):
        log.debug('OcraChallenge: __init__ ')

        self.transid = u'' + transId
        self.challenge = u'' + challenge
        self.tokenserial = u'' + tokenserial
        self.data = u'' + data
        self.timestamp = datetime.now()
        self.session = u'' + session
        self.received_count = 0
        self.received_tan = False
        self.valid_tan = False

        log.debug('OcraChallenge: init done!')

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the assci encode default

        :param name: db column name or class memeber
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in OCRA_ENCODE:
            ## encode data
            if value:
                value = linotp.lib.crypt.uencode(value)
        super(OcraChallenge, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the assci decode default

        :param name: db column name or class memeber

        :return: the corresponding value
        """
        #Default behaviour
        value = object.__getattribute__(self, name)
        if name in OCRA_ENCODE:
            if value:
                value = linotp.lib.crypt.udecode(value)
            else:
                value = ""

        return value

    def setData(self, data):
        self.data = unicode(data)

    def getData(self):
        return self.data

    def getSession(self):
        return self.session

    def setSession(self, session):
        self.session = unicode(session)

    def setChallenge(self, challenge):
        self.challenge = unicode(challenge)

    def setTanStatus(self, received=False, valid=False):
        self.received_tan = received
        self.received_count += 1
        self.valid_tan = valid

    def getTanStatus(self):
        return (self.received_tan, self.valid_tan)

    def getChallenge(self):
        return self.challenge

    def getTransactionId(self):
        return self.transid


    def save(self):
        log.debug('save ocra challenge')
        Session.add(self)
        Session.commit()
        log.debug('save ocra challenge : success')
        return self.transid


    def __unicode__(self):
        descr = {}
        descr['id'] = self.id
        descr['transid'] = self.transid
        descr['challenge'] = self.challenge
        descr['tokenserial'] = self.tokenserial
        descr['data'] = self.data
        descr['timestamp'] = self.timestamp
        descr['received_tan'] = self.received_tan
        descr['valid_tan'] = self.valid_tan

        return "%s" % unicode(descr)


    __str__ = __unicode__



''' ''' '''
challenges are stored
''' ''' '''

log.debug('creating challenges table')

challenges_table = sa.Table('challenges', meta.metadata,
                sa.Column('id', sa.types.Integer(),
                          sa.Sequence('token_seq_id', optional=True),
                          primary_key=True, nullable=False),
                sa.Column('transid', sa.types.Unicode(64),
                                                unique=True, nullable=False,
                                                index=True),
                sa.Column('data', sa.types.Unicode(512), default=u''),
                sa.Column('challenge', sa.types.Unicode(512), default=u''),
                sa.Column(session_column, sa.types.Unicode(512), default=u''),
                sa.Column('tokenserial', sa.types.Unicode(64), default=u''),
                sa.Column(timestamp_column, sa.types.DateTime,
                                                    default=datetime.now()),
                sa.Column('received_count', sa.types.Integer(), default=0),
                sa.Column('received_tan', sa.types.Boolean, default=False),
                sa.Column('valid_tan', sa.types.Boolean, default=False),
                implicit_returning=implicit_returning,
                )

CHALLENGE_ENCODE = ["data", "challenge", 'tokenserial']

class Challenge(object):
    '''
    the generic challange handling
    '''
    def __init__(self, transid, tokenserial, challenge=u'', data=u'', session=u''):
        log.debug('Challenge: __init__ ')

        self.transid = u'' + transid
        self.challenge = u'' + challenge
        self.tokenserial = u'' + tokenserial
        self.data = u'' + data
        self.timestamp = datetime.now()
        self.session = u'' + session
        self.received_count = 0
        self.received_tan = False
        self.valid_tan = False

        log.debug('Challenge: init done!')

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the assci encode default

        :param name: db column name or class memeber
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in CHALLENGE_ENCODE:
            ## encode data
            if value:
                value = linotp.lib.crypt.uencode(value)
        super(Challenge, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the assci decode default

        :param name: db column name or class memeber

        :return: the corresponding value
        """
        #Default behaviour
        value = object.__getattribute__(self, name)
        if name in CHALLENGE_ENCODE:
            if value:
                value = linotp.lib.crypt.udecode(value)
            else:
                value = ""

        return value



    @classmethod
    def createTransactionId(cls , length=20):
        return get_rand_digit_str(length)

    def setData(self, data):
        if type(data) in [dict, list]:
            self.data = json.dumps(data)
        else:
            self.data = unicode(data)

    def getData(self):
        data = {}
        try:
            data = json.loads(self.data)
        except:
            data = self.data
        return data


    def get(self, key=None, fallback=None, save=False):
        '''
        simulate the dict behaviour to make challenge processing
        easier, as this will have to deal as well with
        'dict only challenges'

        :param key: the attribute name - in case of key is not provided, a dict
                    of all class attributes are returned
        :param fallback: if the attribute is not found, the fallback is returned
        :param save: in case of all attributes and save==True, the timestamp is
                     converted to a string representation
        '''
        if key == None:
            return self.get_vars(save=save)

        if hasattr(self, key):
            kMethod = "get" + key.capitalize()
            if hasattr(self, kMethod):
                return getattr(self, kMethod)()
            else:
                return getattr(self, key)
        else:
            return fallback

    def getId(self):
        return self.id


    def getSession(self):
        return self.session

    def setSession(self, session):
        self.session = unicode(session)

    def setChallenge(self, challenge):
        self.challenge = unicode(challenge)

    def setTanStatus(self, received=False, valid=False):
        self.received_tan = received
        self.received_count += 1
        self.valid_tan = valid

    def getTanStatus(self):
        return (self.received_tan, self.valid_tan)

    def getTanCount(self):
        return self.received_count

    def getChallenge(self):
        return self.challenge

    def getTransactionId(self):
        return self.transid

    def getTokenSerial(self):
        return self.tokenserial

    def save(self):
        '''
        enforce the saveing of a challenge
        - will guarentee the uniqness of the transaction id

        :return: transaction id of the stored challeng
        '''
        log.debug('[save] save challenge')
        try:
            Session.add(self)
            Session.commit()
            log.debug('save challenge : success')

        except Exception as exce:
            log.exception('[save]Error during saving challenge: %r' % exce)

        return self.transid

    def get_vars(self, save=False):
        '''
        return a dictionary of all vars in the challenge class

        :return: dict of vars
        '''
        descr = {}
        descr['id'] = self.id
        descr['transid'] = self.transid
        descr['challenge'] = self.challenge
        descr['tokenserial'] = self.tokenserial
        descr['data'] = self.getData()
        if save is True:
            descr['timestamp'] = "%s" % self.timestamp
        else:
            descr['timestamp'] = self.timestamp
        descr['received_tan'] = self.received_tan
        descr['valid_tan'] = self.valid_tan
        return descr

    def __unicode__(self):
        descr = self.get_vars()
        return "%s" % unicode(descr)

    __str__ = __unicode__






log.debug('calling ORM Mapper')

# config_table.append_column( sa.Column('IV', sa.types.Unicode(2000), default=u''),)
# see: http://www.sqlalchemy.org/docs/orm/relationships.html#sqlalchemy.orm.relationship
#      http://www.sqlalchemy.org/docs/05/reference/orm/mapping.html
# The realms of a token will be stored in the additional attribute "realms"
# and the token, to which the realms belong will be stored in the backed "token"
#orm.mapper(Token, token_table, properties={
#    #'realms':relation(Realm, secondary=tokenrealm_table)
#    'realms':relation(TokenRealm, backref=backref('token'))
#    })

orm.mapper(Token, token_table, properties={
    'realms':relation(Realm, secondary=tokenrealm_table,
        primaryjoin=token_table.c.LinOtpTokenId == tokenrealm_table.c.token_id,
        secondaryjoin=tokenrealm_table.c.realm_id == realm_table.c.id)
    })
orm.mapper(Realm, realm_table)
orm.mapper(TokenRealm, tokenrealm_table)
orm.mapper(Config, config_table)


## for oracle and the SQLAlchemy 0.7 we need a mapping of columns
## due to reserved keywords session and timestamp
mapping = {}
mapping['session'] = "%ssession" % COL_PREFIX
mapping['timestamp'] = "%stimestamp" % COL_PREFIX

## create challenges ORM mapping to the Challenge class

challenge_properties = {}
if len(COL_PREFIX) > 0:
    for key, value in mapping.items():
        challenge_properties[key] = challenges_table.columns[value]

orm.mapper(Challenge, challenges_table, properties=challenge_properties)

## create Ocra ORM mapping to the Ocra class
ocra_properties = {}
if len(COL_PREFIX) > 0:
    for key, value in mapping.items():
        ocra_properties[key] = ocra_table.columns[value]

orm.mapper(OcraChallenge, ocra_table, properties=ocra_properties)

##eof#########################################################################
