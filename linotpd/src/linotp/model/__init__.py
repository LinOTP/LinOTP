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
 This file contains the database definition / database model for linotp objects

wrt. the column name limitations see:
    http://www.gplivna.eu/papers/naming_conventions.htm

Common rules
1. Only letters, numbers, and the underscore are allowed in names. Although
    Oracle allows $ and #, they are not necessary and may cause unexpected
    problems.
2. All names are in UPPERCASE. Or at least of no importance which case.
    Ignoring this rule usually leads referencing to tables and columns very
    clumsy because all names must be included in double quotes.
3. The first character in the name must be letter.
4. Keep the names meaningful, but in the same time don't use
    long_names_describing_every_single_detail_of_particular_object.

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

from linotp.lib.crypto import geturandom
from linotp.lib.crypto import hash_digest
# from linotp.lib.crypto import encryptPin
# from linotp.lib.crypto import decryptPin
from linotp.lib.crypto import get_rand_digit_str


from pylons import config
log = logging.getLogger(__name__)

implicit_returning = config.get('linotpSQL.implicit_returning', True)

# # for oracle we need a mapping of columns
# # due to reserved keywords 'session' and 'timestamp'
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

    meta.engine = engine
    meta.Session.configure(bind=engine)

    return

token_table = sa.Table('Token', meta.metadata,
                       sa.Column('LinOtpTokenId', sa.types.Integer(), sa.Sequence(
                           'token_seq_id', optional=True), primary_key=True, nullable=False),
                       sa.Column(
                           'LinOtpTokenDesc', sa.types.Unicode(80), default=u''),
                       sa.Column('LinOtpTokenSerialnumber', sa.types.Unicode(
                           40), default=u'', unique=True, nullable=False, index=True),

                       sa.Column(
                           'LinOtpTokenType', sa.types.Unicode(30), default=u'HMAC', index=True),
                       sa.Column(
                           'LinOtpTokenInfo', sa.types.Unicode(2000), default=u''),
                       # # encrypt
                       sa.Column(
                           'LinOtpTokenPinUser', sa.types.Unicode(512), default=u''),
                       # # encrypt
                       sa.Column(
                           'LinOtpTokenPinUserIV', sa.types.Unicode(32), default=u''),
                       # # encrypt
                       sa.Column(
                           'LinOtpTokenPinSO', sa.types.Unicode(512), default=u''),
                       # # encrypt
                       sa.Column(
                           'LinOtpTokenPinSOIV', sa.types.Unicode(32), default=u''),

                       sa.Column(
                           'LinOtpIdResolver', sa.types.Unicode(120), default=u'', index=True),
                       sa.Column(
                           'LinOtpIdResClass', sa.types.Unicode(120), default=u''),
                       sa.Column(
                           'LinOtpUserid', sa.types.Unicode(320), default=u'', index=True),


                       sa.Column(
                           'LinOtpSeed', sa.types.Unicode(32), default=u''),
                       sa.Column(
                           'LinOtpOtpLen', sa.types.Integer(), default=6),
                       # # hashed
                       sa.Column(
                           'LinOtpPinHash', sa.types.Unicode(512), default=u''),
                       # # encrypt
                       sa.Column(
                           'LinOtpKeyEnc', sa.types.Unicode(1024), default=u''),
                       sa.Column(
                           'LinOtpKeyIV', sa.types.Unicode(32), default=u''),

                       sa.Column(
                           'LinOtpMaxFail', sa.types.Integer(), default=10),
                       sa.Column(
                           'LinOtpIsactive', sa.types.Boolean(), default=True),
                       sa.Column(
                           'LinOtpFailCount', sa.types.Integer(), default=0),
                       sa.Column('LinOtpCount', sa.types.Integer(), default=0),
                       sa.Column(
                           'LinOtpCountWindow', sa.types.Integer(), default=10),
                       sa.Column(
                           'LinOtpSyncWindow', sa.types.Integer(), default=1000),
                       implicit_returning=implicit_returning,
                       )

TOKEN_ENCODE = ["LinOtpTokenDesc", "LinOtpTokenSerialnumber",
                "LinOtpTokenInfo", "LinOtpUserid", "LinOtpIdResClass",
                "LinOtpIdResolver"]


class Token(object):

    def __init__(self, serial):

        # # self.LinOtpTokenId - will be generated DBType serial
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

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the ASCII encode default

        :param name: db column name or class member
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in TOKEN_ENCODE:
            # # encode data
            if value:
                value = linotp.lib.crypto.uencode(value)
        super(Token, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the ASCII decode default

        :param name: db column name or class member

        :return: the corresponding value
        """
        # Default behaviour
        value = object.__getattribute__(self, name)
        if name in TOKEN_ENCODE:
            if value:
                value = linotp.lib.crypto.udecode(value)
            else:
                value = ""
        # port of the 2.6. resolver to 2.7
        if name in ['LinOtpIdResClass']:
            if value[:len('useridresolveree.')] == 'useridresolveree.':
                value = "useridresolver.%s" % value[
                    len('useridreseolveree.') - 1:]

        return value

    def _fix_spaces(self, data):
        '''
        On MS SQL server empty fields ("") like the LinOtpTokenInfo
        are returned as a string with a space (" ").
        This functions helps fixing this.
        Also avoids running into errors, if the data is a None Type.

        :param data: a string from the database
        :type data: usually a string
        :return: a stripped string
        '''
        if data:
            data = data.strip()

        return data

    def getSerial(self):
        return self.LinOtpTokenSerialnumber

    def set_encrypted_seed(self, encrypted_seed, iv, reset_failcount=True,
                           reset_counter=True):
        """
        set_encrypted_seed - save the encrypted token seed / secret

        :param encrypted_seed: the encrypted seed / secret
        :param iv: the initialization value / salt
        :param reset_failcount: reset the failcount on token update
        :param reset_counter: reset the otp counter on token update
        """
        log.debug('set_seed()')

        if reset_counter:
            self.LinOtpCount = 0

        if reset_failcount:
            self.LinOtpFailCount = 0

        self.LinOtpKeyEnc = unicode(binascii.hexlify(encrypted_seed))
        self.LinOtpKeyIV = unicode(binascii.hexlify(iv))

    def get_encrypted_seed(self):
        key = binascii.unhexlify(self.LinOtpKeyEnc or '')
        iv = binascii.unhexlify(self.LinOtpKeyIV or '')
        return key, iv

    def setUserPin(self, enc_userPin, iv):
        self.LinOtpTokenPinUser = unicode(binascii.hexlify(enc_userPin))
        self.LinOtpTokenPinUserIV = unicode(binascii.hexlify(iv))

    def getUserPin(self):
        pu = self._fix_spaces(self.LinOtpTokenPinUser or '')
        puiv = self._fix_spaces(self.LinOtpTokenPinUserIV or '')
        key = binascii.unhexlify(pu)
        iv = binascii.unhexlify(puiv)
        return key, iv

    def getOtpCounter(self):
        return self.LinOtpCount or 0

    def set_hashed_pin(self, pin, iv):
        self.LinOtpSeed = unicode(binascii.hexlify(iv))
        self.LinOtpPinHash = unicode(binascii.hexlify(pin))

    def get_hashed_pin(self):
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash)
        return iv, pin

    @staticmethod
    def copy_pin(src, target):
        target.LinOtpSeed = src.LinOtpSeed
        target.LinOtpPinHash = src.LinOtpPinHash

    def set_encrypted_pin(self, pin, iv):
        self.LinOtpSeed = unicode(binascii.hexlify(iv))
        self.LinOtpPinHash = unicode(binascii.hexlify(pin))
        self.LinOtpPinHash = "@@" + self.LinOtpPinHash

    def get_encrypted_pin(self):
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash[2:])
        return iv, pin

    def setHashedPin(self, pin):
        seed = geturandom(16)
        self.LinOtpSeed = unicode(binascii.hexlify(seed))
        self.LinOtpPinHash = unicode(binascii.hexlify(hash_digest(pin, seed)))
        return self.LinOtpPinHash

    def getHashedPin(self, pin):
        # TODO: we could log the PIN here.

        # # calculate a hash from a pin
        # Fix for working with MS SQL servers
        # MS SQL servers sometimes return a '<space>' when the column is empty:
        # ''
        seed_str = self._fix_spaces(self.LinOtpSeed or '')
        seed = binascii.unhexlify(seed_str)
        hPin = hash(pin, seed)
        log.debug("[getHashedPin] hPin: %s, pin: %s, seed: %s" %
                  (binascii.hexlify(hPin), pin, self.LinOtpSeed or ''))
        return binascii.hexlify(hPin)

    def setDescription(self, desc):
        if desc is None:
            desc = ""
        self.LinOtpTokenDesc = unicode(desc)
        return self.LinOtpTokenDesc

    def setOtpLen(self, otplen):
        self.LinOtpOtpLen = int(otplen)

    def deleteToken(self):
        # some dbs (eg. DB2) runs in deadlock, if the TokenRealm entry
        # is deleteted via foreign key relation
        # so we delete it explicitly
        token_realm_entries = Session.query(TokenRealm).filter(
                            TokenRealm.token_id == self.LinOtpTokenId).all()

        for token_realm_entry in token_realm_entries:
            Session.delete(token_realm_entry)

        Session.delete(self)
        return True

    def isPinEncrypted(self, pin=None):
        ret = False
        if pin is None:
            pin = self.LinOtpPinHash
        if pin and pin.startswith("@@"):
            ret = True
        return ret

    def setSoPin(self, enc_soPin, iv):
        self.LinOtpTokenPinSO = unicode(binascii.hexlify(enc_soPin))
        self.LinOtpTokenPinSOIV = unicode(binascii.hexlify(iv))

    def __unicode__(self):
        return self.LinOtpTokenDesc

    def get(self, key=None, fallback=None, save=False):
        '''
        simulate the dict behaviour to make challenge processing
        easier, as this will have to deal as well with
        'dict only challenges'

        :param key: the attribute name - in case key is not provided, a dict
                    of all class attributes is returned
        :param fallback: if the attribute is not found, the fallback is returned
        :param save: in case all attributes are returned and save==True, the timestamp is
                     converted to a string representation
        '''
        if key is None:
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
        # MS SQL servers sometimes return a '<space>' when the column is empty:
        # ''
        return self._fix_spaces(self.LinOtpTokenInfo or '')

    def setInfo(self, info):
        self.LinOtpTokenInfo = info

    def storeToken(self):
        if self.LinOtpUserid is None:
            self.LinOtpUserid = u''
        if self.LinOtpIdResClass is None:
            self.LinOtpIdResClass = ''
        if self.LinOtpIdResolver is None:
            self.LinOtpIdResolver = ''

        Session.add(self)
        Session.flush()

        return True

    def setType(self, typ):
        self.LinOtpTokenType = typ
        return

    def getType(self):
        return self.LinOtpTokenType or 'hmac'

    def updateType(self, typ):
        # in case the previous type is not the same type
        # we must reset the counters.
        # Remark: comparison must be made case insensitiv
        if self.LinOtpTokenType.lower() != typ.lower():
            self.LinOtpCount = 0
            self.LinOtpFailCount = 0

        self.LinOtpTokenType = typ
        return

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
                        sa.Column(
                            'Key', sa.types.Unicode(255), primary_key=True, nullable=False),
                        sa.Column(
                            'Value', sa.types.Unicode(2000), default=u''),
                        sa.Column('Type', sa.types.Unicode(2000), default=u''),
                        sa.Column(
                            'Description', sa.types.Unicode(2000), default=u''),
                        implicit_returning=implicit_returning,
                        )

CONFIG_ENCODE = ["Key", "Value", "Description"]


class Config(object):

    def __init__(self, Key, Value, Type=u'', Description=u''):

        if (not Key.startswith("linotp.") and not Key.startswith("enclinotp.")):
            Key = "linotp." + Key

        self.Key = unicode(Key)
        self.Value = unicode(Value)
        self.Type = unicode(Type)
        self.Description = unicode(Description)


    def __unicode__(self):
        return self.Description

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the ASCII encode default

        :param name: db column name or class member
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in CONFIG_ENCODE:
            # # encode data
            if value:
                value = linotp.lib.crypto.uencode(value)
        super(Config, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the ASCII decode default

        :param name: db column name or class member

        :return: the corresponding value
        """
        # Default behaviour
        value = object.__getattribute__(self, name)
        if name in CONFIG_ENCODE:
            if value:
                value = linotp.lib.crypto.udecode(value)
            else:
                value = ""

        return value

    __str__ = __unicode__


# This table connects a token to several realms
tokenrealm_table = sa.Table('TokenRealm', meta.metadata,
                            sa.Column('id', sa.types.Integer(), sa.Sequence(
                                'tokenrealm_seq_id', optional=True), primary_key=True, nullable=False),
                            sa.Column(
                                'token_id', sa.types.Integer(), ForeignKey('Token.LinOtpTokenId')),
                            # sa.Column('realm_id', sa.types.Integer())
                            sa.Column(
                                'realm_id', sa.types.Integer(), ForeignKey('Realm.id')),
                            implicit_returning=implicit_returning,
                            )


class TokenRealm(object):

    def __init__(self, realmid):
        self.realm_id = realmid
        self.token_id = 0


realm_table = sa.Table('Realm', meta.metadata,
                       sa.Column('id', sa.types.Integer(), sa.Sequence(
                           'realm_seq_id', optional=True), primary_key=True, nullable=False),
                       sa.Column(
                           'name', sa.types.Unicode(255), default=u'', unique=True, nullable=False),
                       sa.Column('default', sa.types.Boolean(), default=False),
                       sa.Column('option', sa.types.Unicode(40), default=u''),
                       implicit_returning=implicit_returning,
                       )

REALM_ENCODE = ["name", "option"]


class Realm(object):

    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the ASCII encode default

        :param name: db column name or class member
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in REALM_ENCODE:
            # # encode data
            if value:
                value = linotp.lib.crypto.uencode(value)
        super(Realm, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the ASCII decode default

        :param name: db column name or class member

        :return: the corresponding value
        """
        # Default behaviour
        value = object.__getattribute__(self, name)
        if name in REALM_ENCODE:
            if value:
                value = linotp.lib.crypto.udecode(value)
            else:
                value = ""

        return value

    def __init__(self, realm):
        self.name = realm
        if realm is not None:
            self.name = realm.lower()
        # self.id     = 0

    def storeRealm(self):
        if self.name is None:
            self.name = ''
        self.name = self.name.lower()

        Session.add(self)
        Session.flush()

        return True


''' ''' '''
ocra challenges are stored
''' ''' '''

ocra_table = sa.Table('ocra', meta.metadata,
                      sa.Column('id', sa.types.Integer(), sa.Sequence(
                          'token_seq_id', optional=True), primary_key=True, nullable=False),
                      sa.Column('transid', sa.types.Unicode(20), unique=True,
                                nullable=False, index=True),
                      sa.Column('data', sa.types.Unicode(512), default=u''),
                      sa.Column(
                          'challenge', sa.types.Unicode(256), default=u''),
                      sa.Column(
                          session_column, sa.types.Unicode(512), default=u''),
                      sa.Column(
                          'tokenserial', sa.types.Unicode(64), default=u''),
                      sa.Column(
                          timestamp_column, sa.types.DateTime, default=datetime.now()),
                      sa.Column(
                          'received_count', sa.types.Integer(), default=0),
                      sa.Column(
                          'received_tan', sa.types.Boolean, default=False),
                      sa.Column('valid_tan', sa.types.Boolean, default=False),
                      implicit_returning=implicit_returning,
                      )

OCRA_ENCODE = ["data", "challenge", "tokenserial"]


class OcraChallenge(object):
    '''
    '''

    def __init__(self, transId, challenge, tokenserial, data, session=u''):

        self.transid = u'' + transId
        self.challenge = u'' + challenge
        self.tokenserial = u'' + tokenserial
        self.data = u'' + data
        self.timestamp = datetime.now()
        self.session = u'' + session
        self.received_count = 0
        self.received_tan = False
        self.valid_tan = False


    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the ASCII encode default

        :param name: db column name or class member
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in OCRA_ENCODE:
            # # encode data
            if value:
                value = linotp.lib.crypto.uencode(value)
        super(OcraChallenge, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the ASCII decode default

        :param name: db column name or class member

        :return: the corresponding value
        """
        # Default behaviour
        value = object.__getattribute__(self, name)
        if name in OCRA_ENCODE:
            if value:
                value = linotp.lib.crypto.udecode(value)
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

        Session.add(self)
        Session.flush()

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


challenges_table = sa.Table('challenges', meta.metadata,
                            sa.Column('id', sa.types.Integer(),
                                      sa.Sequence(
                                          'token_seq_id', optional=True),
                                      primary_key=True, nullable=False),
                            sa.Column('transid', sa.types.Unicode(64),
                                      unique=True, nullable=False,
                                      index=True),
                            sa.Column('ptransid', sa.types.Unicode(64),
                                      index=True),
                            sa.Column('data',
                                      sa.types.Unicode(512), default=u''),
                            sa.Column('challenge',
                                      sa.types.Unicode(512), default=u''),
                            sa.Column('lchallenge',
                                      sa.types.Unicode(2000), default=u''),
                            sa.Column(session_column,
                                      sa.types.Unicode(512), default=u''),
                            sa.Column('tokenserial',
                                      sa.types.Unicode(64), default=u'',
                                      index=True),
                            sa.Column(timestamp_column, sa.types.DateTime,
                                      default=datetime.now()),
                            sa.Column('received_count',
                                      sa.types.Integer(), default=0),
                            sa.Column('received_tan',
                                      sa.types.Boolean, default=False),
                            sa.Column('valid_tan',
                                      sa.types.Boolean, default=False),
                            implicit_returning=implicit_returning,
                            )

CHALLENGE_ENCODE = ["data", "challenge", 'tokenserial']


class Challenge(object):
    '''
    the generic challange handling
    '''

    def __init__(self, transid, tokenserial, challenge=u'', data=u'', session=u''):

        self.transid = u'' + transid

        #
        # for future use: subtransactions will refer to their parent

        self.ptransid = u''

        #
        # for migration of the challenge column to a new format
        # we require a new target for the old challenge in the orm mapping

        self.challenge = u'' + challenge
        self.ochallenge = ''

        self.tokenserial = u'' + tokenserial
        self.data = u'' + data
        self.timestamp = datetime.now()
        self.session = u'' + session
        self.received_count = 0
        self.received_tan = False
        self.valid_tan = False


    def __setattr__(self, name, value):
        """
        to support unicode on all backends, we use the json encoder with
        the ASCII encode default

        :param name: db column name or class member
        :param value: the corresponding value

        :return: - nothing -
        """
        if name in CHALLENGE_ENCODE:
            # # encode data
            if value:
                value = linotp.lib.crypto.uencode(value)
        super(Challenge, self).__setattr__(name, value)

    def __getattribute__(self, name):
        """
        to support unicode on all backends, we use the json decoder with
        the ASCII decode default

        :param name: db column name or class member

        :return: the corresponding value
        """
        # Default behaviour
        value = object.__getattribute__(self, name)
        if name in CHALLENGE_ENCODE:
            if value:
                value = linotp.lib.crypto.udecode(value)
            else:
                value = ""

        return value

    @classmethod
    def createTransactionId(cls, length=20):
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

        :param key: the attribute name - in case key is not provided, a dict
                    of all class attributes is returned
        :param fallback: if the attribute is not found, the fallback is returned
        :param save: in case of all attributes and save==True, the timestamp is
                     converted to a string representation
        '''
        if key is None:
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

    def signChallenge(self, hsm):
        """
        create a challenge signature and preserve it

        :param hsm: security module, which is able to calc the signature
        :return: - nothing -
        """

        challenge_dict = self.get_vars(save=True)
        challenge_data = json.dumps(challenge_dict)

        mac = hsm.signMessage(challenge_data)

        status = challenge_dict.get('session').get('status', 'open')
        session = {'status': status, 'mac': mac}
        self.setSession(json.dumps(session))

        res = self.checkChallengeSignature(hsm)

    def checkChallengeSignature(self, hsm):
        """
        check the integrity of a challenge

        :param hsm: security module
        :return: success - boolean
        """

        # and calculate the mac for this token data
        challenge_dict = self.get_vars(save=True)
        challenge_data = json.dumps(challenge_dict)

        session = json.loads(self.getSession())
        stored_mac = session.get('mac')
        result = hsm.verfiyMessageSignature(message=challenge_data,
                                            hex_mac=stored_mac)

        return result

    def setChallenge(self, challenge):
        self.challenge = unicode(challenge)

    def setTanStatus(self, received=False, valid=False, increment=True):
        self.received_tan = received
        if increment:
            self.received_count += 1
        self.valid_tan = valid

    def getTanStatus(self):
        return (self.received_tan, self.valid_tan)

    def close(self):
        """
        close a session and make it invisible to the validation

        remarks:
         we introduce the challenge status 'closed'. It is set after a first
         successful authentication. The status is required, as we don't remove
         the challenges after validation anymore

        """
        session_info = json.loads(self.session) or {}
        if not session_info:
            session_info = {'status': 'open'}
        session_info['status'] = 'closed'
        self.session = json.dumps(session_info)

    def is_open(self):
        """
        check if the session is already closed

        :return: success - boolean
        """
        if self.session == '':
            self.session = '{}'
        session = json.loads(self.session)
        status = session.get('status', 'open')
        ret = status == 'open'
        return ret

    def getStatus(self):
        """
        check if the session is already closed

        :return: success - boolean
        """
        session = json.loads(self.session) or {}
        status = session.get('status', 'open')
        return status

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
        enforce the saving of a challenge
        - will guarantee the uniqness of the transaction id

        :return: transaction id of the stored challenge
        '''
        try:
            Session.add(self)
            Session.flush()

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
            descr['timestamp'] = "%s" % self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        else:
            descr['timestamp'] = self.timestamp
        descr['received_tan'] = self.received_tan
        descr['valid_tan'] = self.valid_tan

        # for the vars, only the session status is of interest
        session_info = {'status': 'open'}
        if self.session:
            try:
                session_info = json.loads(self.session)
            except Exception as exx:
                pass
        status = session_info.get('status', 'open')
        descr['session'] = {'status': status}
        return descr

    def __unicode__(self):
        descr = self.get_vars()
        return "%s" % unicode(descr)

    __str__ = __unicode__


#
# with the orm.mapper, we can overwrite the
# implicit mappings to point to a different class members

challenge_mapping = {}
challenge_mapping['ptransid'] = challenges_table.c.ptransid

# old challenge column maps to ochallenge member
challenge_mapping['ochallenge'] = challenges_table.c.challenge

# new challenge column point now to the challenge member
challenge_mapping['challenge'] = challenges_table.c.lchallenge
orm.mapper(Challenge, challenges_table, properties=challenge_mapping,)


#############################################################################
"""
Reporting Table:
"""

reporting_table =\
    sa.Table('REPORTING', meta.metadata,
             sa.Column('R_ID', sa.types.Integer(),
                       sa.Sequence('reporting_seq_id', optional=True),
                       primary_key=True, nullable=False),
             sa.Column('R_TIMESTAMP', sa.types.DateTime, default=datetime.now()),
             sa.Column('R_EVENT', sa.types.Unicode(250), default=u''),
             sa.Column('R_REALM', sa.types.Unicode(250), default=u''),
             sa.Column('R_PARAMETER', sa.types.Unicode(250), default=u''),
             sa.Column('R_VALUE', sa.types.Unicode(250), default=u''),
             sa.Column('R_COUNT', sa.types.Integer(), default=0),
             sa.Column('R_DETAIL', sa.types.Unicode(2000), default=u''),
             sa.Column('R_SESSION', sa.types.Unicode(250), default=u''),
             sa.Column('R_DESCRIPTION', sa.types.Unicode(2000), default=u''),
             implicit_returning=implicit_returning,)


class Reporting(object):

    def __init__(self, event, realm, parameter=u'', value=u'', count=0,
                 detail=u'', session=u'', description=u'', timestamp=None):

        self.event = unicode(event)
        self.realm = unicode(realm)
        self.parameter = unicode(parameter)
        self.value = unicode(value)
        self.count = count
        self.detail = unicode(detail)
        self.session = unicode(session)
        self.description = unicode(description)
        self.timestamp = datetime.now()
        if timestamp:
            self.timestamp = timestamp

    def get_vars(self):
        ret = {}

        ret['timestamp'] = str(self.timestamp)
        ret['event'] = self.event
        ret['realm'] = self.realm
        ret['parameter'] = self.parameter
        ret['value'] = self.value
        ret['count'] = self.count
        ret['detail'] = self.detail
        ret['session'] = self.session
        ret['description'] = self.description

        return ret

reporting_mapping = {}
reporting_mapping['id'] = reporting_table.c.R_ID
reporting_mapping['session'] = reporting_table.c.R_SESSION
reporting_mapping['timestamp'] = reporting_table.c.R_TIMESTAMP
reporting_mapping['event'] = reporting_table.c.R_EVENT
reporting_mapping['realm'] = reporting_table.c.R_REALM
reporting_mapping['parameter'] = reporting_table.c.R_PARAMETER
reporting_mapping['value'] = reporting_table.c.R_VALUE
reporting_mapping['count'] = reporting_table.c.R_COUNT
reporting_mapping['detail'] = reporting_table.c.R_DETAIL
reporting_mapping['description'] = reporting_table.c.R_DESCRIPTION

orm.mapper(Reporting,
           reporting_table,
           properties=reporting_mapping,
           )

#############################################################################

# logging configuration

logging_config_table =\
    sa.Table('logging_config', meta.metadata,
             sa.Column('name', sa.types.String(200),
                       primary_key=True, nullable=False),
             sa.Column('level', sa.types.Integer(), default=0),
             implicit_returning=implicit_returning,)


class LoggingConfig(object):

    def __init__(self, name, level):
        self.name = name
        self.level = level

logging_config_mapping = {}
logging_config_mapping['name'] = logging_config_table.c.name
logging_config_mapping['level'] = logging_config_table.c.level

orm.mapper(LoggingConfig,
           logging_config_table,
           properties=logging_config_mapping,
           )

#############################################################################

# config_table.append_column( sa.Column('IV', sa.types.Unicode(2000), default=u''),)
# see: http://www.sqlalchemy.org/docs/orm/relationships.html#sqlalchemy.orm.relationship
#      http://www.sqlalchemy.org/docs/05/reference/orm/mapping.html
# The realms of a token will be stored in the additional attribute "realms"
# and the token, to which the realms belong will be stored in the backed "token"
# orm.mapper(Token, token_table, properties={
#    #'realms':relation(Realm, secondary=tokenrealm_table)
#    'realms':relation(TokenRealm, backref=backref('token'))
#    })

orm.mapper(Token, token_table, properties={
    'realms': relation(Realm, secondary=tokenrealm_table,
                       primaryjoin=token_table.c.LinOtpTokenId == tokenrealm_table.c.token_id,
                       secondaryjoin=tokenrealm_table.c.realm_id == realm_table.c.id)
})
orm.mapper(Realm, realm_table)
orm.mapper(TokenRealm, tokenrealm_table)
orm.mapper(Config, config_table)


# for oracle and the SQLAlchemy 0.7 we need a mapping of columns
# due to reserved keywords session and timestamp
mapping = {}
mapping['session'] = "%ssession" % COL_PREFIX
mapping['timestamp'] = "%stimestamp" % COL_PREFIX


# # create Ocra ORM mapping to the Ocra class
ocra_properties = {}
if len(COL_PREFIX) > 0:
    for key, value in mapping.items():
        ocra_properties[key] = ocra_table.columns[value]

orm.mapper(OcraChallenge, ocra_table, properties=ocra_properties)

##eof#########################################################################
