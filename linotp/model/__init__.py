# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
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


import logging
import sys

from flask_sqlalchemy import DeclarativeMeta, SQLAlchemy
from sqlalchemy import create_engine

log = logging.getLogger(__name__)

db: DeclarativeMeta = SQLAlchemy()


implicit_returning = True
# TODO: Implicit returning from config
# implicit_returning = config.get('linotpSQL.implicit_returning', True)

# # for oracle we need a mapping of columns
# # due to reserved keywords 'session' and 'timestamp'
COL_PREFIX = ""

# exit code 3 and 4 prevents gunicorn from restarting workers
# https://github.com/benoitc/gunicorn/blob/9802e21f779d9f1f208a1a3288218bd5b843ad46/gunicorn/arbiter.py#L528
SYS_EXIT_CODE = 4
EXIT_CODE_DB_NOT_CURRENT = 3

# TODO: Get from app config
# SQLU = config.get("sqlalchemy.url", "")
# if SQLU.startswith("oracle:"):
#     COL_PREFIX = config.get("oracle.sql.column_prefix", "lino")

from linotp.model.challange import Challenge  # noqa
from linotp.model.config import Config, set_config  # noqa
from linotp.model.db_logging import LoggingConfig  # noqa
from linotp.model.migrate import Migration, run_data_model_migration  # noqa
from linotp.model.realm import Realm  # noqa
from linotp.model.reporting import Reporting  # noqa
from linotp.model.token import Token, createToken  # noqa
from linotp.model.tokenRealm import TokenRealm  # noqa


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
        sys.exit(SYS_EXIT_CODE)

    if audit_database_uri != "OFF":
        engine = db.get_engine(app=app, bind="auditdb")
        auditdb_table_names = engine.table_names()

        from linotp.lib.audit.SQLAudit import AuditTable

        if AuditTable.__tablename__ not in auditdb_table_names:
            log.critical(
                "Audit database schema must be initialised, "
                "run `linotp init database`."
            )
            sys.exit(SYS_EXIT_CODE)

    if not Migration.is_db_model_current():
        log.critical(
            "Database schema is not current, run `linotp init database`."
        )
        sys.exit(EXIT_CODE_DB_NOT_CURRENT)


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

    echo("Setting up database...", v=1)

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
            from linotp.lib.tools.set_password import (
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


TOKEN_ENCODE = [
    "LinOtpTokenDesc",
    "LinOtpTokenSerialnumber",
    "LinOtpTokenInfo",
    "LinOtpUserid",
    "LinOtpIdResClass",
    "LinOtpIdResolver",
]


###############################################################################

CONFIG_ENCODE = ["Key", "Value", "Description"]


REALM_ENCODE = ["name", "option"]


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

    set_config(
        key="policy_action_validation",
        value="True",
        typ="bool",
        description="validate policy action values",
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
