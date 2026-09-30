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

"""Run migration step 4.0.0.1 against a real database.

The queries it uses - filtering tokens by type and deleting challenges via a
subquery over another table - behave differently across the databases LinOTP
supports, so they are exercised here rather than only through the pure helper.
"""

import json

import pytest

from linotp.model import db
from linotp.model.challange import Challenge
from linotp.model.migrate import Migration
from linotp.model.token import Token
from linotp.tests import TestController

CREDENTIAL = {
    "credential_id": "credential-id",
    "public_key": "public-key",
    "sign_count": 3,
    "rp_id": "localhost",
}
STATE = {"challenge": "Y2hhbGxlbmdl", "user_verification": "preferred"}


def _add_token(serial, token_type, token_info):
    token = Token(serial)
    token.LinOtpTokenType = token_type
    token.setInfo(json.dumps(token_info))
    db.session.add(token)
    return token


def _add_challenge(serial, data):
    challenge = Challenge(
        transid=f"transid-{serial}", tokenserial=serial, challenge="c"
    )
    challenge.setData(data)
    db.session.add(challenge)
    return challenge


def _token_info(serial):
    token = Token.query.filter(Token.LinOtpTokenSerialnumber == serial).one()
    return json.loads(token.getInfo())


class TestMigrateFido2TokenInfo(TestController):
    @pytest.fixture(autouse=True)
    def clean_tokens_and_challenges(self):
        """Start and end with an empty token and challenge table."""

        def wipe():
            Challenge.query.delete()
            Token.query.delete()
            db.session.commit()

        wipe()
        yield
        wipe()

    def test_migration_unwraps_and_drops_challenges(self):
        """The double-encoded values become objects, open challenges go away."""

        _add_token(
            "FIDO2LEGACY",
            "fido2",
            {
                "phase": "authentication",
                "fido2_credential": json.dumps(CREDENTIAL),
                "registration_challenge": json.dumps(STATE),
            },
        )
        _add_challenge("FIDO2LEGACY", {"challenge": json.dumps(STATE)})
        db.session.commit()

        success, message = Migration(db.engine).migrate_4_0_0_1()
        db.session.commit()

        assert success is True
        assert "1 fido2 token(s)" in message
        assert "1 open fido2 challenge(s)" in message

        info = _token_info("FIDO2LEGACY")
        assert info["fido2_credential"] == CREDENTIAL
        assert info["registration_challenge"] == STATE
        assert info["phase"] == "authentication"

        assert Challenge.query.count() == 0

    def test_migration_leaves_other_token_types_alone(self):
        """Only fido2 tokens and their challenges may be touched."""

        _add_token("HMAC0001", "hmac", {"hashlib": "sha1"})
        _add_token("QR000001", "qr", {"fido2_credential": json.dumps(CREDENTIAL)})
        _add_challenge("HMAC0001", {"challenge": "not-a-fido2-challenge"})
        db.session.commit()

        Migration(db.engine).migrate_4_0_0_1()
        db.session.commit()

        # the lookalike value on a non-fido2 token is left encoded
        assert _token_info("QR000001")["fido2_credential"] == json.dumps(CREDENTIAL)
        assert _token_info("HMAC0001") == {"hashlib": "sha1"}
        assert Challenge.query.count() == 1

    def test_migration_is_idempotent(self):
        """Running it again on already migrated data changes nothing."""

        _add_token(
            "FIDO2OK01",
            "fido2",
            {"fido2_credential": CREDENTIAL, "registration_challenge": STATE},
        )
        db.session.commit()

        _, message = Migration(db.engine).migrate_4_0_0_1()
        db.session.commit()

        assert "0 fido2 token(s)" in message
        assert _token_info("FIDO2OK01")["fido2_credential"] == CREDENTIAL
