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
import json
import logging
import sys
from datetime import datetime

import sqlalchemy as sa
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine

from linotp.lib.crypto.utils import get_rand_digit_str, geturandom, hash_digest
from linotp.lib.type_utils import DEFAULT_TIMEFORMAT
from linotp.model.migrate import Migration, run_data_model_migration

log = logging.getLogger(__name__)

db = SQLAlchemy()

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


def fix_db_encoding(app) -> None:
    """Fix the python2+mysql iso8859 encoding by conversion to utf-8."""

    try:
        migration = Migration(db.engine)
        success, response = migration.iso8859_to_utf8_conversion()

        if success:
            db.session.commit()
        else:
            db.session.rollback()

    except Exception:
        raise

    finally:
        db.session.close()

    return success, response


def setup_db(app) -> None:
    """Set up the database for LinOTP.

    This method is used to set up a SQLAlchemy database engine for the
    main LinOTP database. It does NOT generate a table structure if
    the database doesn't have one (see `init_db_tables()` below for that).

    This method is called during `create_app()`, which means that it
    happens pretty much always (during CLI commands and also when running
    from a WSGI application server), even before our own code really gets
    control. This is a hassle because we want to make sure that the
    database is properly initialised before going on our merry way, except
    when we know the database isn't properly initialised and the next
    thing we're about to do is to initialise it. This is why we have
    the revolting `app.cli_cmd` mechanism that is used below. It lets us
    skip the database setup when we're doing `linotp init` or `linotp config`,
    both of which don't touch the database, except for `linotp init database`,
    which skips the database setup during `create_app()` but then comes
    back to it in its own code after deviously setting `app.cli_cmd` to
    `init-database` so it goes into the `if` below after all. But in
    this case we still need to make an exception for it when it doesn't
    find the `Config` table, because rather than croak with a fatal error
    we want to *create* the `Config` table.

    FIXME: This is not how we would do this in Flask. We want to
    rewrite it once we get Flask-SQLAlchemy and Flask-Migrate
    working properly.

    """

    # Don't bother with all this database business when doing
    # `linotp init …`, because otherwise there will be chicken/egg
    # issues galore.
    if not app.database_needed():
        return

    # Initialise the SQLAlchemy engine

    app.config["SQLALCHEMY_DATABASE_URI"] = app.config["DATABASE_URI"]

    audit_database_uri = app.config["AUDIT_DATABASE_URI"]

    if audit_database_uri == "SHARED":
        audit_database_uri = app.config["DATABASE_URI"]

    # Using the same sqlite database file for audit and LinOTP is not
    # possible due to database locking issues. If this is the case,
    # we add a suffix to the audit database file.
    if (
        audit_database_uri.startswith("sqlite")
        and audit_database_uri == app.config["DATABASE_URI"]
    ):
        temp_engine = create_engine(audit_database_uri)
        if (
            temp_engine.url.database is not None
            and temp_engine.url.database != ":memory:"
        ):
            audit_database_uri = audit_database_uri + "_audit"
            log.warning(
                "The audit database can not share the same"
                " sqlite database file with the LinOTP database."
                f' Using "{audit_database_uri}" instead.'
            )

    if audit_database_uri != "OFF":
        app.config["SQLALCHEMY_BINDS"] = {
            "auditdb": audit_database_uri,
        }

    db.init_app(app)

    table_names = db.engine.table_names()

    cli_cmd = getattr(app, "cli_cmd", "")
    if cli_cmd == "init-database":
        return

    if "Config" not in table_names:
        log.critical(
            "Database schema must be initialised, "
            "run `linotp init database`."
        )
        sys.exit(11)

    if audit_database_uri != "OFF":
        engine = db.get_engine(app=app, bind="auditdb")
        auditdb_table_names = engine.table_names()

        from linotp.lib.audit.SQLAudit import AuditTable

        if AuditTable.__tablename__ not in auditdb_table_names:
            log.critical(
                "Audit database schema must be initialised, "
                "run `linotp init database`."
            )
            sys.exit(11)

    if not Migration.is_db_model_current():
        log.critical(
            "Database schema is not current, run `linotp init database`."
        )
        sys.exit(11)


def init_db_tables(app, drop_data=False, add_defaults=True):
    """Initialise LinOTP database tables.

    This function initialises the LinOTP tables given an empty database
    (it also works if the database isn't empty).

    :param drop_data: If `True`, all data will be cleared. Use with caution!
    :param add_defaults: Adds default configuration variables if `True`.
       Don't set this to `False` unless you know what you are doing.
    """

    # Use `app.echo()` if available, otherwise standard logging.
    echo = getattr(
        app,
        "echo",
        lambda msg, v=0: log.log(logging.INFO if v else logging.ERROR, msg),
    )

    echo(f"Setting up database...", v=1)

    try:
        if app.config["AUDIT_DATABASE_URI"] != "OFF":
            # The audit table is created in the configured audit database
            # connection if audit is not turned off. The database model is
            # added to SQLAlchemy if the file is imported.
            import linotp.lib.audit.SQLAudit

        if drop_data:
            echo("Dropping tables to erase all data...", v=1)
            db.drop_all()

        echo(f"Creating tables...", v=1)
        db.create_all()

        run_data_model_migration(db.engine)
        if add_defaults:
            set_defaults(app)

        # For the cloud mode, we require the `admin_user` table to
        # manage the admin users to allow password setting

        admin_username = app.config["ADMIN_USERNAME"]
        admin_password = app.config["ADMIN_PASSWORD"]

        if admin_username and admin_password:
            echo("Setting up cloud admin user...", v=1)
            from .lib.tools.set_password import (
                DataBaseContext,
                SetPasswordHandler,
            )

            db_context = DataBaseContext(sql_url=db.engine.url)
            SetPasswordHandler.create_table(db_context)
            SetPasswordHandler.create_admin_user(
                db_context,
                username=admin_username,
                crypted_password=admin_password,
            )

    except Exception as exx:
        echo(f"Exception occured during database setup: {exx!r}")
        db.session.rollback()
        raise exx

    db.session.commit()


session_column = "%ssession" % COL_PREFIX
timestamp_column = "%stimestamp" % COL_PREFIX

# This table connects a token to several realms
tokenrealm_table = db.Table(
    "TokenRealm",
    db.metadata,
    db.Column(
        "id",
        db.Integer(),
        db.Sequence("tokenrealm_seq_id", optional=True),
        primary_key=True,
        nullable=False,
    ),
    db.Column("token_id", db.Integer(), db.ForeignKey("Token.LinOtpTokenId")),
    db.Column("realm_id", db.Integer(), db.ForeignKey("Realm.id")),
    implicit_returning=implicit_returning,
)

token_table = sa.Table(
    "Token",
    db.metadata,
    sa.Column(
        "LinOtpTokenId",
        sa.types.Integer(),
        sa.Sequence("token_seq_id", optional=True),
        primary_key=True,
        nullable=False,
    ),
    sa.Column("LinOtpTokenDesc", sa.types.Unicode(80), default=""),
    sa.Column(
        "LinOtpTokenSerialnumber",
        sa.types.Unicode(40),
        default="",
        unique=True,
        nullable=False,
        index=True,
    ),
    sa.Column(
        "LinOtpTokenType", sa.types.Unicode(30), default="HMAC", index=True
    ),
    sa.Column("LinOtpTokenInfo", sa.types.Unicode(2000), default=""),
    # # encrypt
    sa.Column("LinOtpTokenPinUser", sa.types.Unicode(512), default=""),
    # # encrypt
    sa.Column("LinOtpTokenPinUserIV", sa.types.Unicode(32), default=""),
    # # encrypt
    sa.Column("LinOtpTokenPinSO", sa.types.Unicode(512), default=""),
    # # encrypt
    sa.Column("LinOtpTokenPinSOIV", sa.types.Unicode(32), default=""),
    sa.Column(
        "LinOtpIdResolver", sa.types.Unicode(120), default="", index=True
    ),
    sa.Column("LinOtpIdResClass", sa.types.Unicode(120), default=""),
    sa.Column("LinOtpUserid", sa.types.Unicode(320), default="", index=True),
    sa.Column("LinOtpSeed", sa.types.Unicode(32), default=""),
    sa.Column("LinOtpOtpLen", sa.types.Integer(), default=6),
    # # hashed
    sa.Column("LinOtpPinHash", sa.types.Unicode(512), default=""),
    # # encrypt
    sa.Column("LinOtpKeyEnc", sa.types.Unicode(1024), default=""),
    sa.Column("LinOtpKeyIV", sa.types.Unicode(32), default=""),
    sa.Column("LinOtpMaxFail", sa.types.Integer(), default=10),
    sa.Column("LinOtpIsactive", sa.types.Boolean(), default=True),
    sa.Column("LinOtpFailCount", sa.types.Integer(), default=0),
    sa.Column("LinOtpCount", sa.types.Integer(), default=0),
    sa.Column("LinOtpCountWindow", sa.types.Integer(), default=10),
    sa.Column("LinOtpSyncWindow", sa.types.Integer(), default=1000),
    sa.Column(
        "LinOtpCreationDate",
        sa.types.DateTime,
        index=True,
        default=datetime.now().replace(microsecond=0),
    ),
    sa.Column(
        "LinOtpLastAuthSuccess", sa.types.DateTime, index=True, default=None
    ),
    sa.Column(
        "LinOtpLastAuthMatch", sa.types.DateTime, index=True, default=None
    ),
    implicit_returning=implicit_returning,
)

TOKEN_ENCODE = [
    "LinOtpTokenDesc",
    "LinOtpTokenSerialnumber",
    "LinOtpTokenInfo",
    "LinOtpUserid",
    "LinOtpIdResClass",
    "LinOtpIdResolver",
]


class Token(db.Model):

    __table__ = token_table

    realms = db.relationship(
        "Realm",
        secondary=tokenrealm_table,
        lazy="subquery",
        backref=db.backref("tokens", lazy=True),
    )

    def __init__(self, serial):
        super().__init__()

        # # self.LinOtpTokenId - will be generated DBType serial
        self.LinOtpTokenSerialnumber = "" + serial

        self.LinOtpTokenType = ""

        self.LinOtpCount = 0
        self.LinOtpFailCount = 0
        # get maxFail should have a configurable default
        self.LinOtpMaxFail = 10
        self.LinOtpIsactive = True
        self.LinOtpCountWindow = 10
        self.LinOtpOtpLen = 6
        self.LinOtpSeed = ""

        self.LinOtpIdResolver = None
        self.LinOtpIdResClass = None
        self.LinOtpUserid = None

        # when the token is created all time stamps are set to utc now

        self.LinOtpCreationDate = datetime.utcnow().replace(microsecond=0)
        self.LinOtpLastAuthMatch = None
        self.LinOtpLastAuthSuccess = None

    def _fix_spaces(self, data):
        """
        On MS SQL server empty fields ("") like the LinOtpTokenInfo
        are returned as a string with a space (" ").
        This functions helps fixing this.
        Also avoids running into errors, if the data is a None Type.

        :param data: a string from the database
        :type data: usually a string
        :return: a stripped string
        """
        if data:
            data = data.strip()

        return data

    def getSerial(self):
        return self.LinOtpTokenSerialnumber

    def set_encrypted_seed(
        self, encrypted_seed, iv, reset_failcount=True, reset_counter=True
    ):
        """
        set_encrypted_seed - save the encrypted token seed / secret

        :param encrypted_seed: the encrypted seed / secret
        :param iv: the initialization value / salt
        :param reset_failcount: reset the failcount on token update
        :param reset_counter: reset the otp counter on token update
        """
        log.debug("set_seed()")

        if reset_counter:
            self.LinOtpCount = 0

        if reset_failcount:
            self.LinOtpFailCount = 0

        self.LinOtpKeyEnc = binascii.hexlify(encrypted_seed).decode("utf-8")
        self.LinOtpKeyIV = binascii.hexlify(iv).decode("utf-8")

    def get_encrypted_seed(self):
        key = binascii.unhexlify(self.LinOtpKeyEnc or "")
        iv = binascii.unhexlify(self.LinOtpKeyIV or "")
        return key, iv

    def setUserPin(self, enc_userPin, iv):
        self.LinOtpTokenPinUser = binascii.hexlify(enc_userPin).decode("utf-8")
        self.LinOtpTokenPinUserIV = binascii.hexlify(iv).decode("utf-8")

    def getUserPin(self):
        pu = self._fix_spaces(self.LinOtpTokenPinUser or "")
        puiv = self._fix_spaces(self.LinOtpTokenPinUserIV or "")
        key = binascii.unhexlify(pu)
        iv = binascii.unhexlify(puiv)
        return key, iv

    def getOtpCounter(self):
        return self.LinOtpCount or 0

    def set_hashed_pin(self, pin, iv):
        self.LinOtpSeed = binascii.hexlify(iv).decode("utf-8")
        self.LinOtpPinHash = binascii.hexlify(pin).decode("utf-8")

    def get_hashed_pin(self):
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash)
        return iv, pin

    @staticmethod
    def copy_pin(src, target):
        target.LinOtpSeed = src.LinOtpSeed
        target.LinOtpPinHash = src.LinOtpPinHash

    def set_encrypted_pin(self, pin, iv):
        self.LinOtpSeed = binascii.hexlify(iv).decode("utf-8")
        self.LinOtpPinHash = binascii.hexlify(pin).decode("utf-8")
        self.LinOtpPinHash = "@@" + self.LinOtpPinHash

    def get_encrypted_pin(self):
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash[2:])
        return iv, pin

    def setHashedPin(self, pin):
        seed = geturandom(16)
        self.LinOtpSeed = binascii.hexlify(seed).decode("utf-8")
        self.LinOtpPinHash = binascii.hexlify(hash_digest(pin, seed)).decode(
            "utf-8"
        )
        return self.LinOtpPinHash

    def getHashedPin(self, pin):
        # TODO: we could log the PIN here.

        # # calculate a hash from a pin
        # Fix for working with MS SQL servers
        # MS SQL servers sometimes return a '<space>' when the column is empty:
        # ''
        seed_str = self._fix_spaces(self.LinOtpSeed or "")
        seed = binascii.unhexlify(seed_str)
        hPin = hash(pin, seed)
        log.debug(
            "[getHashedPin] hPin: %s, pin: %s, seed: %s",
            binascii.hexlify(hPin),
            pin,
            self.LinOtpSeed or "",
        )
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
        token_realm_entries = TokenRealm.query.filter_by(
            token_id=self.LinOtpTokenId
        ).all()

        for token_realm_entry in token_realm_entries:
            db.session.delete(token_realm_entry)

        db.session.delete(self)
        return True

    def isPinEncrypted(self, pin=None):
        ret = False
        if pin is None:
            pin = self.LinOtpPinHash
        if pin and pin.startswith("@@"):
            ret = True
        return ret

    def setSoPin(self, enc_soPin, iv):
        self.LinOtpTokenPinSO = binascii.hexlify(enc_soPin).decode("utf-8")
        self.LinOtpTokenPinSOIV = binascii.hexlify(iv).decode("utf-8")

    def __str__(self):
        return self.LinOtpTokenDesc

    def get(self, key=None, fallback=None, save=False):
        """
        simulate the dict behaviour to make challenge processing
        easier, as this will have to deal as well with
        'dict only challenges'

        :param key: the attribute name - in case key is not provided, a dict
                    of all class attributes is returned
        :param fallback: if the attribute is not found, the fallback is returned
        :param save: in case all attributes are returned and save==True, the timestamp is
                     converted to a string representation
        """
        if key is None:
            return self.get_vars(save=save)

        if hasattr(self, key):
            kMethod = "get" + key.capitalize()
            if hasattr(self, kMethod):
                return getattr(self, kMethod)()
            else:
                return getattr(self, key) or ""
        else:
            return fallback

    def get_vars(self, save=False):

        ret = {}
        ret["LinOtp.TokenId"] = self.LinOtpTokenId or ""
        ret["LinOtp.TokenDesc"] = self.LinOtpTokenDesc or ""
        ret["LinOtp.TokenSerialnumber"] = self.LinOtpTokenSerialnumber or ""

        ret["LinOtp.TokenType"] = self.LinOtpTokenType or "hmac"
        ret["LinOtp.TokenInfo"] = self._fix_spaces(self.LinOtpTokenInfo or "")
        # ret['LinOtpTokenPinUser']   = self.LinOtpTokenPinUser
        # ret['LinOtpTokenPinSO']     = self.LinOtpTokenPinSO

        ret["LinOtp.IdResolver"] = self.LinOtpIdResolver or ""
        ret["LinOtp.IdResClass"] = self.LinOtpIdResClass or ""
        ret["LinOtp.Userid"] = self.LinOtpUserid or ""
        ret["LinOtp.OtpLen"] = self.LinOtpOtpLen or 6
        # ret['LinOtp.PinHash']        = self.LinOtpPinHash

        ret["LinOtp.MaxFail"] = self.LinOtpMaxFail
        ret["LinOtp.Isactive"] = self.LinOtpIsactive
        ret["LinOtp.FailCount"] = self.LinOtpFailCount
        ret["LinOtp.Count"] = self.LinOtpCount
        ret["LinOtp.CountWindow"] = self.LinOtpCountWindow
        ret["LinOtp.SyncWindow"] = self.LinOtpSyncWindow
        # ------------------------------------------------------------------ --

        # handle representation of created, accessed and verified:

        # - could be None, if not (newly) created  / accessed / verified
        # - if type is datetime it must be converted to a string as the result
        #   will be used as part of a json output

        created = ""
        if self.LinOtpCreationDate is not None:
            created = self.LinOtpCreationDate.strftime(DEFAULT_TIMEFORMAT)

        ret["LinOtp.CreationDate"] = created

        verified = ""
        if self.LinOtpLastAuthSuccess is not None:
            verified = self.LinOtpLastAuthSuccess.strftime(DEFAULT_TIMEFORMAT)

        ret["LinOtp.LastAuthSuccess"] = verified

        accessed = ""
        if self.LinOtpLastAuthMatch is not None:
            accessed = self.LinOtpLastAuthMatch.strftime(DEFAULT_TIMEFORMAT)

        ret["LinOtp.LastAuthMatch"] = accessed
        # list of Realm names
        ret["LinOtp.RealmNames"] = self.getRealmNames()

        return ret

    def __repr__(self):
        """
        return the token state as text

        :return: token state as string representation
        :rtype:  string
        """
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
        return self._fix_spaces(self.LinOtpTokenInfo or "")

    def setInfo(self, info):
        self.LinOtpTokenInfo = info

    def storeToken(self):
        if self.LinOtpUserid is None:
            self.LinOtpUserid = ""
        if self.LinOtpIdResClass is None:
            self.LinOtpIdResClass = ""
        if self.LinOtpIdResolver is None:
            self.LinOtpIdResolver = ""

        db.session.add(self)
        db.session.flush()

        return True

    def setType(self, typ):
        self.LinOtpTokenType = typ
        return

    def getType(self):
        return self.LinOtpTokenType or "hmac"

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
        return self.realms or ""

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
    log.debug("createToken(%s)", serial)
    serial = "" + serial
    token = Token(serial)
    log.debug("token object created")

    return token


###############################################################################


config_table = sa.Table(
    "Config",
    db.metadata,
    sa.Column("Key", sa.types.Unicode(255), primary_key=True, nullable=False),
    sa.Column("Value", sa.types.Unicode(2000), default=""),
    sa.Column("Type", sa.types.Unicode(2000), default=""),
    sa.Column("Description", sa.types.Unicode(2000), default=""),
    implicit_returning=implicit_returning,
)

CONFIG_ENCODE = ["Key", "Value", "Description"]


class Config(db.Model):

    __table__ = config_table

    def __init__(self, Key, Value, **kwargs):
        if not Key.startswith("linotp.") and not Key.startswith("enclinotp."):
            Key = "linotp." + Key
        super().__init__(Key=Key, Value=Value, **kwargs)

    def __str__(self):
        return self.Description


class TokenRealm(db.Model):

    __table__ = tokenrealm_table  # See above, before `Token`

    def __init__(self, realmid):
        super().__init__()
        self.realm_id = realmid
        self.token_id = 0


realm_table = sa.Table(
    "Realm",
    db.metadata,
    sa.Column(
        "id",
        sa.types.Integer(),
        sa.Sequence("realm_seq_id", optional=True),
        primary_key=True,
        nullable=False,
    ),
    sa.Column(
        "name", sa.types.Unicode(255), default="", unique=True, nullable=False
    ),
    sa.Column("default", sa.types.Boolean(), default=False),
    sa.Column("option", sa.types.Unicode(40), default=""),
    implicit_returning=implicit_returning,
)

REALM_ENCODE = ["name", "option"]


class Realm(db.Model):

    __table__ = realm_table

    def __init__(self, realm):
        super().__init__()
        self.name = realm
        if realm is not None:
            self.name = realm.lower()
        # self.id     = 0

    def storeRealm(self):
        if self.name is None:
            self.name = ""
        self.name = self.name.lower()

        db.session.add(self)
        db.session.flush()

        return True


""" """ """
challenges are stored
""" """ """


CHALLENGE_ENCODE = ["data", "challenge", "tokenserial"]


def set_defaults(app):
    """
    add linotp default config settings

    :return: - nothing -
    """
    app.logger.info("Adding config default data...")

    is_upgrade = Config.query.filter_by(Key="Config").count() != 0

    if is_upgrade:
        # if it is an upgrade and no welcome screen was shown before,
        # make sure an upgrade screen is shown
        set_config(key="welcome_screen.version", value="0", typ="text")
        set_config(key="welcome_screen.last_shown", value="0", typ="text")
        set_config(key="welcome_screen.opt_out", value="false", typ="text")

    else:
        # we have a fresh new database, so we add some new defaults

        admin_realm_name = app.config["ADMIN_REALM_NAME"]
        admin_resolver_name = app.config["ADMIN_RESOLVER_NAME"]

        create_admin_resolver(admin_resolver_name)
        create_admin_realm(admin_realm_name, admin_resolver_name)

        set_config(
            key="NewPolicyEvaluation",
            value="True",
            typ="boolean",
            description="use the new policy engine",
        )

        set_config(
            key="NewPolicyEvaluation.compare",
            value="False",
            typ="boolean",
            description=("compare the new policy engine with the old one"),
        )

    set_config(
        key="DefaultMaxFailCount",
        value="10",
        typ="int",
        description=("The default maximum count for unsuccessful logins"),
    )

    set_config(
        key="DefaultCountWindow",
        value="10",
        typ="int",
        description=("The default lookup window for tokens out of sync "),
    )

    set_config(
        key="DefaultSyncWindow",
        value="1000",
        typ="int",
        description=("The default lookup window for tokens out of sync "),
    )

    set_config(
        key="DefaultChallengeValidityTime",
        value="120",
        typ="int",
        description=("The default time, a challenge is regarded as valid."),
    )

    set_config(
        key="DefaultResetFailCount",
        value="True",
        typ="bool",
        description="The default maximum count for unsucessful logins",
    )

    set_config(
        key="DefaultOtpLen",
        value="6",
        typ="int",
        description="The default len of the otp values",
    )

    set_config(
        key="QRTokenOtpLen",
        value="8",
        typ="int",
        description="The default len of the otp values",
    )

    set_config(
        key="QRChallengeValidityTime",
        value="150",
        typ="int",
        description=(
            "The default qrtoken time, a challenge is regarded as valid."
        ),
    )

    set_config(
        key="QRMaxChallenges",
        value="4",
        typ="int",
        description="Maximum open QRToken challenges",
    )

    set_config(
        key="PushChallengeValidityTime",
        value="150",
        typ="int",
        description=(
            "The pushtoken default time, a challenge is regarded as valid."
        ),
    )

    set_config(
        key="PushMaxChallenges",
        value="4",
        typ="int",
        description="Maximum open pushtoken challenges",
    )

    set_config(
        key="PrependPin",
        value="True",
        typ="bool",
        description="is the pin prepended - most cases",
    )

    set_config(
        key="FailCounterIncOnFalsePin",
        value="True",
        typ="bool",
        description="increment the FailCounter, if pin did not match",
    )

    set_config(
        key="SMSProvider",
        value="smsprovider.HttpSMSProvider.HttpSMSProvider",
        typ="text",
        description="SMS Default Provider via HTTP",
    )

    set_config(
        key="SMSProviderTimeout",
        value="300",
        typ="int",
        description="Timeout until registration must be done",
    )

    set_config(
        key="SMSBlockingTimeout",
        value="30",
        typ="int",
        description="Delay until next challenge is created",
    )

    set_config(
        key="DefaultBlockingTimeout",
        value="0",
        typ="int",
        description="Delay until next challenge is created",
    )

    # setup for totp defaults
    # "linotp.totp.timeStep";"60";"None";"None"
    # "linotp.totp.timeWindow";"600";"None";"None"
    # "linotp.totp.timeShift";"240";"None";"None"

    set_config(
        key="totp.timeStep",
        value="30",
        typ="int",
        description="Time stepping of the time based otp token ",
    )

    set_config(
        key="totp.timeWindow",
        value="300",
        typ="int",
        description=("Lookahead time window of the time based otp token "),
    )

    set_config(
        key="totp.timeShift",
        value="0",
        typ="int",
        description="Shift between server and totp token",
    )

    set_config(
        key="AutoResyncTimeout",
        value="240",
        typ="int",
        description="Autosync timeout for an totp token",
    )

    # emailtoken defaults
    set_config(
        key="EmailProvider",
        value="linotp.provider.emailprovider.SMTPEmailProvider",
        typ="string",
        description="Default EmailProvider class",
    )

    set_config(
        key="EmailChallengeValidityTime",
        value="600",
        typ="int",
        description=(
            "Time that an e-mail token challenge stays valid (seconds)"
        ),
    )
    set_config(
        key="EmailBlockingTimeout",
        value="120",
        typ="int",
        description="Time during which no new e-mail is sent out",
    )

    set_config(
        key="OATHTokenSupport",
        value="False",
        typ="bool",
        description="support for hmac token in oath format",
    )

    # use the system certificate handling, especially for ldaps
    set_config(
        key="certificates.use_system_certificates",
        value="False",
        typ="bool",
        description="use system certificate handling",
    )

    set_config(
        key="user_lookup_cache.enabled",
        value="False",
        typ="bool",
        description="enable user loookup caching",
    )

    set_config(
        key="resolver_lookup_cache.enabled",
        value="False",
        typ="bool",
        description="enable realm resolver caching",
    )

    set_config(
        key="user_lookup_cache.expiration",
        value="64800",
        typ="int",
        description="expiration of user caching entries",
    )

    set_config(
        key="resolver_lookup_cache.expiration",
        value="64800",
        typ="int",
        description="expiration of resolver caching entries",
    )


def create_admin_resolver(admin_resolver_name):
    """create the default managed admin resolver

    to ease the programming, we work on an sql query result
    """

    entries = [
        ("sqlresolver.Connect.admin_resolver", "", "text", "None"),
        ("sqlresolver.conParams.admin_resolver", "", "text", "None"),
        ("sqlresolver.Database.admin_resolver", "", "text", "None"),
        ("sqlresolver.Driver.admin_resolver", "", "text", "None"),
        ("sqlresolver.Encoding.admin_resolver", "utf-8", "text", "None"),
        ("sqlresolver.Limit.admin_resolver", "1000", "int", "None"),
        (
            "sqlresolver.Map.admin_resolver",
            '{"userid": "userid", "username": "username", "phone": "phone", "mobile": "mobile", "email": "email", "surname": "surname", "givenname": "givenname", "password": "password", "groupid": "groupid"}',
            "text",
            "None",
        ),
        (
            "sqlresolver.Password.admin_resolver",
            "a31b6178b78637d5e4fa5fb5f19d5493:599e786159a3f544d1bb0d810830587d",
            "encrypted_data",
            "None",
        ),
        ("sqlresolver.Port.admin_resolver", "", "text", "None"),
        ("sqlresolver.readonly.admin_resolver", "True", "boolean", "None"),
        ("sqlresolver.Server.admin_resolver", "", "text", "None"),
        ("sqlresolver.Table.admin_resolver", "imported_user", "text", "None"),
        ("sqlresolver.User.admin_resolver", "", "text", "None"),
        (
            "sqlresolver.Where.admin_resolver",
            "groupid = 'admin_resolver'",
            "text",
            "None",
        ),
    ]

    for key, value, typ, description in entries:
        key = key.replace("admin_resolver", admin_resolver_name)
        value = value.replace("admin_resolver", admin_resolver_name)

        # as this is a managed resolver, we can replace the data type as the
        # encrypted value is never used
        if typ.strip() == "encrypted_data":
            typ = "text"

        set_config(
            key=key,
            value=value,
            typ=typ,
            description=description,
        )


def create_admin_realm(admin_realm_name, admin_resolver_name):
    """
    create the default managed admin realm
    """
    admin_realm_name = admin_realm_name.lower()

    set_config(
        key=f"useridresolver.group.{admin_realm_name}",
        value=(
            f"useridresolver.SQLIdResolver.IdResolver.{admin_resolver_name}"
        ),
        typ="text",
        description="None",
    )

    if not Realm.query.filter_by(name=admin_realm_name).count():
        admin_realm = Realm(admin_realm_name)
        admin_realm.storeRealm()


##eof#########################################################################
