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

"""Run migration step 4.0.0.2 against a real database.

The ALTER TABLE statement which changes the token info column type is dialect
specific, so it is exercised here against the database the tests run on.
"""

import json

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from linotp.model import db
from linotp.model.migrate import Migration
from linotp.model.token import Token
from linotp.tests import TestController

# the token info column type before migration step 4.0.0.2
OLD_TOKEN_INFO_TYPE = sa.types.Unicode(2000)

# bigger than the former 2000 characters limit of the token info column
LONG_CERT = "A" * 4000


def _set_token_info_type(new_type, existing_type):
    """Change the token info column type, e.g. back to the pre 4.0.0.2 type."""

    operations = Operations(MigrationContext.configure(db.session.connection()))
    with operations.batch_alter_table("Token") as batch_op:
        batch_op.alter_column(
            "LinOtpTokenInfo",
            type_=new_type,
            existing_type=existing_type,
            existing_nullable=True,
        )
    db.session.commit()


def _token_info_length():
    """Return the length limit of the token info column, None if unlimited."""

    columns = sa.inspect(db.engine).get_columns("Token")
    column = next(c for c in columns if c["name"] == "LinOtpTokenInfo")
    return getattr(column["type"], "length", None)


def _add_token(serial, token_info):
    token = Token(serial)
    token.LinOtpTokenType = "fido2"
    token.setInfo(json.dumps(token_info))
    db.session.add(token)
    return token


def _token_info(serial):
    token = Token.query.filter(Token.LinOtpTokenSerialnumber == serial).one()
    return json.loads(token.getInfo())


class TestMigrateTokenInfoColumn(TestController):
    @pytest.fixture(autouse=True)
    def clean_tokens(self):
        """Start and end with an empty token table."""

        def wipe():
            Token.query.delete()
            db.session.commit()

        wipe()
        yield
        wipe()

    def test_migration_keeps_existing_token_info(self):
        """Token info written before the migration is unchanged afterwards."""

        info = {"phase": "authentication", "rp_id": "localhost"}
        _add_token("FIDO2BEFORE", info)
        db.session.commit()

        success, _ = Migration(db.engine).migrate_4_0_0_2()
        db.session.commit()

        assert success is True
        assert _token_info("FIDO2BEFORE") == info

    def test_migration_from_old_column_type(self):
        """The migration converts the old 2000 characters column.

        The test database is created from the current model, so the column is
        put back to its pre 4.0.0.2 type first to run the actual conversion.
        """

        _set_token_info_type(OLD_TOKEN_INFO_TYPE, sa.types.UnicodeText())
        try:
            assert _token_info_length() == 2000

            # token info which fills the old column up to its limit
            full_info = {"fido2_credential": {"attestation_cert_b64": ""}}
            filler = 2000 - len(json.dumps(full_info))
            full_info["fido2_credential"]["attestation_cert_b64"] = "A" * filler
            assert len(json.dumps(full_info)) == 2000

            short_info = {"phase": "authentication", "rp_id": "localhost"}

            _add_token("FIDO2FULL", full_info)
            _add_token("FIDO2SHORT", short_info)
            db.session.commit()

            success, _ = Migration(db.engine).migrate_4_0_0_2()
            db.session.commit()

            assert success is True
            assert _token_info_length() is None

            # existing token info is unchanged
            assert _token_info("FIDO2FULL") == full_info
            assert _token_info("FIDO2SHORT") == short_info

            # token info beyond the former limit can be stored now
            long_info = {"fido2_credential": {"attestation_cert_b64": LONG_CERT}}
            _add_token("FIDO2LONG", long_info)
            db.session.commit()

            assert _token_info("FIDO2LONG") == long_info

        finally:
            # leave the column as the current model expects it
            db.session.rollback()
            if _token_info_length() is not None:
                _set_token_info_type(sa.types.UnicodeText(), OLD_TOKEN_INFO_TYPE)

    def test_migration_is_idempotent(self):
        """Running the migration twice does not fail or change the data."""

        info = {"phase": "authentication"}
        _add_token("FIDO2TWICE", info)
        db.session.commit()

        Migration(db.engine).migrate_4_0_0_2()
        db.session.commit()
        Migration(db.engine).migrate_4_0_0_2()
        db.session.commit()

        assert _token_info("FIDO2TWICE") == info
