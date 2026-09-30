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

import json

from linotp.model.migrate import Migration_4_0_0_1

CREDENTIAL = {
    "credential_id": "credential-id",
    "public_key": "public-key",
    "sign_count": 3,
    "rp_id": "localhost",
}
STATE = {"challenge": "Y2hhbGxlbmdl", "user_verification": "preferred"}


def _unwrap(info: dict) -> tuple[dict | None, bool]:
    result, changed = Migration_4_0_0_1.unwrap_json_encoded_values(json.dumps(info))
    return (json.loads(result) if result is not None else None), changed


def test_unwraps_both_encoded_keys():
    info = {
        "phase": "authentication",
        "fido2_credential": json.dumps(CREDENTIAL),
        "registration_challenge": json.dumps(STATE),
    }

    result, changed = _unwrap(info)

    assert changed is True
    assert result == {
        "phase": "authentication",
        "fido2_credential": CREDENTIAL,
        "registration_challenge": STATE,
    }


def test_unwraps_a_single_encoded_key():
    info = {"counter": "7", "fido2_credential": json.dumps(CREDENTIAL)}

    result, changed = _unwrap(info)

    assert changed is True
    assert result == {"counter": "7", "fido2_credential": CREDENTIAL}


def test_already_migrated_token_info_is_left_alone():
    info = {"fido2_credential": CREDENTIAL, "registration_challenge": STATE}

    assert _unwrap(info) == (None, False)


def test_unrelated_keys_are_not_unwrapped():
    """Only the keys that were ever double-encoded may be touched."""
    info = {"some_other_key": json.dumps({"a": 1})}

    assert _unwrap(info) == (None, False)


def test_unreadable_entry_is_skipped_but_the_rest_is_migrated():
    info = {
        "fido2_credential": "{ this is not json",
        "registration_challenge": json.dumps(STATE),
    }

    result, changed = _unwrap(info)

    assert changed is True
    assert result == {
        "fido2_credential": "{ this is not json",
        "registration_challenge": STATE,
    }


def test_non_object_value_is_left_alone():
    """A JSON string that does not decode to an object is not a credential."""
    info = {"fido2_credential": "[1, 2, 3]"}

    assert _unwrap(info) == (None, False)


def test_unreadable_token_info_is_skipped():
    assert Migration_4_0_0_1.unwrap_json_encoded_values("not json at all") == (
        None,
        False,
    )


def test_empty_token_info_is_skipped():
    assert Migration_4_0_0_1.unwrap_json_encoded_values("") == (None, False)
