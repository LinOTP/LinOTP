# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

from linotp.lib.type_utils import DEFAULT_TIMEFORMAT

import json

import sqlalchemy as sa

from sqlalchemy import create_engine, orm
from sqlalchemy import ForeignKey
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import relation

from linotp.model import meta
from linotp.model.migrate import run_data_model_migration

from linotp.lib.crypto.utils import geturandom
from linotp.lib.crypto.utils import hash_digest

from linotp.lib.crypto.utils import get_rand_digit_str

Session = meta.Session

log = logging.getLogger(__name__)

implicit_returning = True
# TODO: Implicit returning from config
# implicit_returning = config.get('linotpSQL.implicit_returning', True)

# # for oracle we need a mapping of columns
# # due to reserved keywords 'session' and 'timestamp'
COL_PREFIX = ""

# TODO: Get from app config
# SQLU = config.get("sqlalchemy.url", "")
# if SQLU.startswith("oracle:"):
#     COL_PREFIX = config.get("oracle.sql.column_prefix", "lino")


def setup_db(app, drop_data=False):
    """Set up the database for LinOTP.

    This method is used during create_app() phase and as a separate
    flask command `init-db` in init_db_command() to initialize and setup
    the linotp database.

    FIXME: This is not how we would do this in Flask. We want to
    rewrite it once we get Flask-SQLAlchemy and Flask-Migrate
    working properly.

    :param drop_data: If True, all data will be cleared. Use with caution!
    """

    # Initialise the SQLAlchemy engine

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    # sqlite in-memory databases require special sqlalchemy setup:
    # https://docs.sqlalchemy.org/en/13/dialects/sqlite.html#using-a-memory-database-in-multiple-threads

    if sql_uri == "sqlite://":
        engine = create_engine(sql_uri,
                               connect_args={'check_same_thread': False},
                               poolclass=StaticPool)
    else:
        engine = create_engine(sql_uri)

    # Initialise database table model

    init_model(engine)

    # (Re)create and setup database tables if they don't already exist

    app.echo(f"Setting up database... (drop_data={drop_data})", v=1)

    try:
        if drop_data:
            app.echo("Dropping tables to erase all data...", v=1)
            meta.metadata.drop_all(bind=meta.engine)

        meta.metadata.create_all(bind=meta.engine)

        run_data_model_migration(meta)
        set_defaults(app)

        # For the cloud mode, we require the `admin_user` table to
        # manage the admin users to allow password setting

        admin_username = app.config['ADMIN_USERNAME']
        admin_password = app.config['ADMIN_PASSWORD']

        if admin_username and admin_password:
            app.echo("Setting up cloud admin user...", v=1)
            from .lib.tools.set_password import (
                SetPasswordHandler, DataBaseContext
            )
            db_context = DataBaseContext(sql_url=meta.engine.url)
            SetPasswordHandler.create_table(db_context)
            SetPasswordHandler.create_admin_user(
                db_context,
                username=admin_username, crypted_password=admin_password)

    except Exception as exx:
        app.echo(
            f"Exception occured during database setup: {exx!r}")
        meta.Session.rollback()
        raise exx

    meta.Session.commit()


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


token_table = sa.Table(
    'Token', meta.metadata,
    sa.Column('LinOtpTokenId', sa.types.Integer(), sa.Sequence(
        'token_seq_id', optional=True), primary_key=True, nullable=False),
    sa.Column(
        'LinOtpTokenDesc', sa.types.Unicode(80), default=''),
    sa.Column('LinOtpTokenSerialnumber', sa.types.Unicode(
        40), default='', unique=True, nullable=False, index=True),

    sa.Column(
        'LinOtpTokenType', sa.types.Unicode(30), default='HMAC', index=True),
    sa.Column(
        'LinOtpTokenInfo', sa.types.Unicode(2000), default=''),
    # # encrypt
    sa.Column(
        'LinOtpTokenPinUser', sa.types.Unicode(512), default=''),
    # # encrypt
    sa.Column(
        'LinOtpTokenPinUserIV', sa.types.Unicode(32), default=''),
    # # encrypt
    sa.Column(
        'LinOtpTokenPinSO', sa.types.Unicode(512), default=''),
    # # encrypt
    sa.Column(
        'LinOtpTokenPinSOIV', sa.types.Unicode(32), default=''),

    sa.Column(
        'LinOtpIdResolver', sa.types.Unicode(120), default='', index=True),
    sa.Column(
        'LinOtpIdResClass', sa.types.Unicode(120), default=''),
    sa.Column(
        'LinOtpUserid', sa.types.Unicode(320), default='', index=True),


    sa.Column(
        'LinOtpSeed', sa.types.Unicode(32), default=''),
    sa.Column(
        'LinOtpOtpLen', sa.types.Integer(), default=6),
    # # hashed
    sa.Column(
        'LinOtpPinHash', sa.types.Unicode(512), default=''),
    # # encrypt
    sa.Column(
        'LinOtpKeyEnc', sa.types.Unicode(1024), default=''),
    sa.Column(
        'LinOtpKeyIV', sa.types.Unicode(32), default=''),

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
    sa.Column('LinOtpCreationDate', sa.types.DateTime, index=True,
              default=datetime.now().replace(microsecond=0)),
    sa.Column('LinOtpLastAuthSuccess', sa.types.DateTime, index=True,
              default=None),
    sa.Column('LinOtpLastAuthMatch', sa.types.DateTime, index=True,
              default=None),
    implicit_returning=implicit_returning,
)

TOKEN_ENCODE = ["LinOtpTokenDesc", "LinOtpTokenSerialnumber",
                "LinOtpTokenInfo", "LinOtpUserid", "LinOtpIdResClass",
                "LinOtpIdResolver"]


class Token(object):

    def __init__(self, serial):

        # # self.LinOtpTokenId - will be generated DBType serial
        self.LinOtpTokenSerialnumber = '' + serial

        self.LinOtpTokenType = ''

        self.LinOtpCount = 0
        self.LinOtpFailCount = 0
        # get maxFail should have a configurable default
        self.LinOtpMaxFail = 10
        self.LinOtpIsactive = True
        self.LinOtpCountWindow = 10
        self.LinOtpOtpLen = 6
        self.LinOtpSeed = ''

        self.LinOtpIdResolver = None
        self.LinOtpIdResClass = None
        self.LinOtpUserid = None

        # when the token is created all time stamps are set to utc now

        self.LinOtpCreationDate = datetime.utcnow().replace(microsecond=0)
        self.LinOtpLastAuthMatch = None
        self.LinOtpLastAuthSuccess = None

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

        self.LinOtpKeyEnc = binascii.hexlify(encrypted_seed).decode('utf-8')
        self.LinOtpKeyIV = binascii.hexlify(iv).decode('utf-8')

    def get_encrypted_seed(self):
        key = binascii.unhexlify(self.LinOtpKeyEnc or '')
        iv = binascii.unhexlify(self.LinOtpKeyIV or '')
        return key, iv

    def setUserPin(self, enc_userPin, iv):
        self.LinOtpTokenPinUser = binascii.hexlify(enc_userPin).decode('utf-8')
        self.LinOtpTokenPinUserIV = binascii.hexlify(iv).decode('utf-8')

    def getUserPin(self):
        pu = self._fix_spaces(self.LinOtpTokenPinUser or '')
        puiv = self._fix_spaces(self.LinOtpTokenPinUserIV or '')
        key = binascii.unhexlify(pu)
        iv = binascii.unhexlify(puiv)
        return key, iv

    def getOtpCounter(self):
        return self.LinOtpCount or 0

    def set_hashed_pin(self, pin, iv):
        self.LinOtpSeed = binascii.hexlify(iv).decode('utf-8')
        self.LinOtpPinHash = binascii.hexlify(pin).decode('utf-8')

    def get_hashed_pin(self):
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash)
        return iv, pin

    @staticmethod
    def copy_pin(src, target):
        target.LinOtpSeed = src.LinOtpSeed
        target.LinOtpPinHash = src.LinOtpPinHash

    def set_encrypted_pin(self, pin, iv):
        self.LinOtpSeed = binascii.hexlify(iv).decode('utf-8')
        self.LinOtpPinHash = binascii.hexlify(pin).decode('utf-8')
        self.LinOtpPinHash = "@@" + self.LinOtpPinHash

    def get_encrypted_pin(self):
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash[2:])
        return iv, pin

    def setHashedPin(self, pin):
        seed = geturandom(16)
        self.LinOtpSeed = binascii.hexlify(seed).decode('utf-8')
        self.LinOtpPinHash = binascii.hexlify(
            hash_digest(pin, seed)).decode('utf-8')
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
        self.LinOtpTokenDesc = str(desc)
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
        self.LinOtpTokenPinSO = binascii.hexlify(enc_soPin).decode('utf-8')
        self.LinOtpTokenPinSOIV = binascii.hexlify(iv).decode('utf-8')

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
        # ------------------------------------------------------------------ --

        # handle representation of created, accessed and verified:

        # - could be None, if not (newly) created  / accessed / verified
        # - if type is datetime it must be converted to a string as the result
        #   will be used as part of a json output

        created = ''
        if self.LinOtpCreationDate is not None:
            created = self.LinOtpCreationDate.strftime(DEFAULT_TIMEFORMAT)

        ret['LinOtp.CreationDate'] = created

        verified = ''
        if self.LinOtpLastAuthSuccess is not None:
            verified = self.LinOtpLastAuthSuccess.strftime(DEFAULT_TIMEFORMAT)

        ret['LinOtp.LastAuthSuccess'] = verified

        accessed = ''
        if self.LinOtpLastAuthMatch is not None:
            accessed = self.LinOtpLastAuthMatch.strftime(DEFAULT_TIMEFORMAT)

        ret['LinOtp.LastAuthMatch'] = accessed
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
            self.LinOtpUserid = ''
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
    serial = '' + serial
    token = Token(serial)
    log.debug('token object created')

    return token

###############################################################################


config_table = sa.Table('Config', meta.metadata,
                        sa.Column(
                            'Key', sa.types.Unicode(255), primary_key=True, nullable=False),
                        sa.Column(
                            'Value', sa.types.Unicode(2000), default=''),
                        sa.Column('Type', sa.types.Unicode(2000), default=''),
                        sa.Column(
                            'Description', sa.types.Unicode(2000), default=''),
                        implicit_returning=implicit_returning,
                        )

CONFIG_ENCODE = ["Key", "Value", "Description"]


class Config(object):

    def __init__(self, Key, Value, Type='', Description=''):

        if (not Key.startswith("linotp.") and not Key.startswith("enclinotp.")):
            Key = "linotp." + Key

        self.Key = str(Key)
        self.Value = str(Value)
        self.Type = str(Type)
        self.Description = str(Description)

    def __unicode__(self):
        return self.Description

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
                           'name', sa.types.Unicode(255), default='', unique=True, nullable=False),
                       sa.Column('default', sa.types.Boolean(), default=False),
                       sa.Column('option', sa.types.Unicode(40), default=''),
                       implicit_returning=implicit_returning,
                       )

REALM_ENCODE = ["name", "option"]


class Realm(object):

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
                                      sa.types.Unicode(512), default=''),
                            sa.Column('bdata',
                                      sa.types.LargeBinary, default=None),
                            sa.Column('challenge',
                                      sa.types.Unicode(512), default=''),
                            sa.Column('lchallenge',
                                      sa.types.Unicode(2000), default=''),
                            sa.Column('bchallenge',
                                      sa.types.LargeBinary, default=None),
                            sa.Column(session_column,
                                      sa.types.Unicode(512), default=''),
                            sa.Column('tokenserial',
                                      sa.types.Unicode(64), default='',
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

    def __init__(self, transid, tokenserial, challenge='', data='', session=''):

        self.transid = '' + transid

        #
        # for future use: subtransactions will refer to their parent

        self.ptransid = ''

        # adjust challenge to be binary compatible

        if isinstance(challenge, str):
            challenge = challenge.encode('utf-8')
        self.challenge = challenge

        self.ochallenge = ''

        self.tokenserial = '' + tokenserial

        # adjust data to be binary compatible

        if isinstance(data, str):
            data = data.encode('utf-8')
        self.data = data

        self.timestamp = datetime.now()
        self.session = '' + session
        self.received_count = 0
        self.received_tan = False
        self.valid_tan = False

    @classmethod
    def createTransactionId(cls, length=20):
        return get_rand_digit_str(length)

    def setData(self, data):
        if type(data) in [dict, list]:
            save_data = json.dumps(data)
        else:
            save_data = data

        self.data = save_data.encode('utf-8')

    def getData(self):
        data = {}
        saved_data = self.data.decode('utf-8')
        try:
            data = json.loads(saved_data)
        except:
            data = saved_data
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
        """
        set the session state information like open or closed
        - contains in addition the mac of the whole challenge entry

        :param session: dictionary of the session info
        """
        self.session = str(session)

    def add_session_info(self, info):
        session_dict = {}

        if self.session:
            session_dict = json.loads(self.session)

        session_dict.update(info)

        self.session = str(json.dumps(session_dict))

    def signChallenge(self, hsm):
        """
        create a challenge signature and preserve it

        :param hsm: security module, which is able to calc the signature
        :return: - nothing -
        """

        # calculate the new mac for the challenge

        challenge_dict = self.get_vars(save=True)
        challenge_data = json.dumps(challenge_dict)

        mac = hsm.signMessage(challenge_data)

        # ------------------------------------------------------------------ --

        # update the session info:

        session = challenge_dict.get('session', {})

        session['status'] = session.get('status', 'open')
        session['mac'] = mac

        self.setSession(json.dumps(session))

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
        self.challenge = challenge.encode('utf8')

    def getChallenge(self):

        if not isinstance(self.challenge, str):
            return self.challenge.decode()

        return self.challenge

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

        if 'reject' in session_info:
            self.valid_tan = False

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

        except Exception as _exce:
            log.exception('[save]Error during saving challenge')

        return self.transid

    def get_vars(self, save=False):
        '''
        return a dictionary of all vars in the challenge class

        :return: dict of vars
        '''
        descr = {}
        descr['id'] = self.id
        descr['transid'] = self.transid
        descr['challenge'] = self.getChallenge()
        descr['tokenserial'] = self.tokenserial
        descr['data'] = self.getData()
        if save is True:
            descr['timestamp'] = "%s" % self.timestamp.strftime(
                '%Y-%m-%d %H:%M:%S')
        else:
            descr['timestamp'] = self.timestamp
        descr['received_tan'] = self.received_tan
        descr['valid_tan'] = self.valid_tan

        # for the vars, session is of interest but without mac

        session_info = {'status': 'open'}
        if self.session:
            try:
                session_info = json.loads(self.session)
                if 'mac' in session_info:
                    del session_info['mac']
            except Exception as _exx:
                pass

        descr['session'] = session_info

        return descr

    def __unicode__(self):
        descr = self.get_vars()
        return "%s" % str(descr)

    __str__ = __unicode__


#
# with the orm.mapper, we can overwrite the
# implicit mappings to point to a different class members

challenge_mapping = {}
challenge_mapping['ptransid'] = challenges_table.c.ptransid

# old challenge / data column maps to ochallenge / odata member
challenge_mapping['oochallenge'] = challenges_table.c.challenge
challenge_mapping['ochallenge'] = challenges_table.c.lchallenge
challenge_mapping['odata'] = challenges_table.c.data

# new challenge / data column point now to the bchallenge / bdata member
challenge_mapping['challenge'] = challenges_table.c.bchallenge
challenge_mapping['data'] = challenges_table.c.bdata

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
             sa.Column('R_TIMESTAMP', sa.types.DateTime,
                       default=datetime.now()),
             sa.Column('R_EVENT', sa.types.Unicode(250), default=''),
             sa.Column('R_REALM', sa.types.Unicode(250), default=''),
             sa.Column('R_PARAMETER', sa.types.Unicode(250), default=''),
             sa.Column('R_VALUE', sa.types.Unicode(250), default=''),
             sa.Column('R_COUNT', sa.types.Integer(), default=0),
             sa.Column('R_DETAIL', sa.types.Unicode(2000), default=''),
             sa.Column('R_SESSION', sa.types.Unicode(250), default=''),
             sa.Column('R_DESCRIPTION', sa.types.Unicode(2000), default=''),
             implicit_returning=implicit_returning,)


class Reporting(object):

    def __init__(self, event, realm, parameter='', value='', count=0,
                 detail='', session='', description='', timestamp=None):

        self.event = str(event)
        self.realm = str(realm)
        self.parameter = str(parameter)
        self.value = str(value)
        self.count = count
        self.detail = str(detail)
        self.session = str(session)
        self.description = str(description)
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


# The following used to be in `linotp/defaults.py`, but we want to avoid
# issues with circular `import` dependencies.

def _set_config(key, value, typ, description=None, update=False):
    '''
    create an intial config entry, if it does not exist

    :param key: the key
    :param value: the value
    :param description: the description of the key

    :return: nothing
    '''

    count = Session.query(Config).filter(
        Config.Key == "linotp." + key).count()

    if count == 0:
        config_entry = Config(key, value, Type=typ, Description=description)
        Session.add(config_entry)

    elif update:
        config_entry = Session.query(Config).filter(
            Config.Key == "linotp." + key).first()

        if not key.startswith('linotp.'):
            key = 'linotp.' + key

        if isinstance(key, str):
            key = key.encode()

        config_entry.Key = key

        if isinstance(value, str):
            value = value.encode()

        config_entry.Value = value

        if isinstance(typ, str):
            typ = typ.encode()

        config_entry.Type = typ

        if isinstance(description, str):
            description = description.encode()

        config_entry.Description = description

        Session.add(config_entry)

    return


def set_defaults(app):
    '''
    add linotp default config settings

    :return: - nothing -
    '''

    is_upgrade = 0 != Session.query(Config).filter(
        Config.Key == "Config").count()

    if is_upgrade:
        # if it is an upgrade and no welcome screen was shown before,
        # make sure an upgrade screen is shown
        _set_config(key="welcome_screen.version",
                    value="0", typ="text")
        _set_config(key="welcome_screen.last_shown",
                    value="0", typ="text")
        _set_config(key="welcome_screen.opt_out",
                    value="false", typ="text")

    app.logger.info("Adding config default data...")

    _set_config(key="DefaultMaxFailCount",
                value="10", typ="int",
                description=("The default maximum count for"
                             " unsuccessful logins"))

    _set_config(key="DefaultCountWindow",
                value="10", typ="int",
                description=("The default lookup window for tokens "
                             "out of sync "))

    _set_config(key="DefaultSyncWindow",
                value="1000", typ="int",
                description=("The default lookup window for tokens "
                             "out of sync "))

    _set_config(key="DefaultChallengeValidityTime",
                value="120", typ="int",
                description=("The default time, a challenge is regarded"
                             " as valid."))

    _set_config(key="DefaultResetFailCount",
                value="True", typ="bool",
                description="The default maximum count for unsucessful logins")

    _set_config(key="DefaultOtpLen",
                value="6", typ="int",
                description="The default len of the otp values")

    _set_config(key="QRTokenOtpLen",
                value="8", typ="int",
                description="The default len of the otp values")

    _set_config(key="QRChallengeValidityTime",
                value="150", typ="int",
                description=("The default qrtoken time, a challenge is "
                             "regarded as valid."))

    _set_config(key="QRMaxChallenges",
                value="4", typ="int",
                description="Maximum open QRToken challenges")

    _set_config(key="PushChallengeValidityTime",
                value="150", typ="int",
                description=("The pushtoken default time, a challenge is "
                             "regarded as valid."))

    _set_config(key="PushMaxChallenges",
                value="4", typ="int",
                description="Maximum open pushtoken challenges")

    _set_config(key="PrependPin",
                value="True", typ="bool",
                description="is the pin prepended - most cases")

    _set_config(key="FailCounterIncOnFalsePin",
                value="True", typ="bool",
                description="increment the FailCounter, if pin did not match")

    _set_config(key="SMSProvider",
                value="smsprovider.HttpSMSProvider.HttpSMSProvider",
                typ="text",
                description="SMS Default Provider via HTTP")

    _set_config(key="SMSProviderTimeout",
                value="300", typ="int",
                description="Timeout until registration must be done")

    _set_config(key="SMSBlockingTimeout",
                value="30", typ="int",
                description="Delay until next challenge is created")

    _set_config(key="DefaultBlockingTimeout",
                value="0", typ="int",
                description="Delay until next challenge is created")

    # setup for totp defaults
    # "linotp.totp.timeStep";"60";"None";"None"
    # "linotp.totp.timeWindow";"600";"None";"None"
    # "linotp.totp.timeShift";"240";"None";"None"

    _set_config(key="totp.timeStep",
                value="30", typ="int",
                description="Time stepping of the time based otp token ")

    _set_config(key="totp.timeWindow",
                value="300", typ="int",
                description=("Lookahead time window of the time based "
                             "otp token "))

    _set_config(key="totp.timeShift",
                value="0", typ="int",
                description="Shift between server and totp token")

    _set_config(key="AutoResyncTimeout",
                value="240", typ="int",
                description="Autosync timeout for an totp token")

    # emailtoken defaults
    _set_config(key="EmailProvider",
                value="linotp.provider.emailprovider.SMTPEmailProvider",
                typ="string",
                description="Default EmailProvider class")

    _set_config(key="EmailChallengeValidityTime",
                value="600", typ="int",
                description=("Time that an e-mail token challenge stays valid"
                             " (seconds)"))
    _set_config(key="EmailBlockingTimeout",
                value="120", typ="int",
                description="Time during which no new e-mail is sent out")

    _set_config(key='OATHTokenSupport',
                value="False", typ="bool",
                description="support for hmac token in oath format")

    # use the system certificate handling, especially for ldaps
    _set_config(key="certificates.use_system_certificates",
                value="False", typ="bool",
                description="use system certificate handling")

    _set_config(key="user_lookup_cache.enabled",
                value="False", typ="bool",
                description="enable user loookup caching")

    _set_config(key="resolver_lookup_cache.enabled",
                value="False", typ="bool",
                description="enable realm resolver caching")

    _set_config(key='user_lookup_cache.expiration',
                value="64800", typ="int",
                description="expiration of user caching entries")

    _set_config(key='resolver_lookup_cache.expiration',
                value="64800", typ="int",
                description="expiration of resolver caching entries")

    if not is_upgrade:
        _set_config(key='NewPolicyEvaluation',
                    value="True", typ="boolean",
                    description="use the new policy engine")

        _set_config(key='NewPolicyEvaluation.compare',
                    value="False", typ="boolean",
                    description=("compare the new policy engine with "
                                 "the old one"))

##eof#########################################################################
