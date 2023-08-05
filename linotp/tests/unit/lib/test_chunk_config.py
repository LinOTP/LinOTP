# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
Tests the chunked data handling in the config
"""


import unittest

import pytest
from mock import patch

from linotp.lib.config.db_api import (
    _retrieveConfigDB,
    _store_continous_entry_db,
    _storeConfigDB,
)
from linotp.model import Config, db

big_value = """-----BEGIN CERTIFICATE-----
MIIGlTCCBH2gAwIBAgIED////zANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJO
TDEXMBUGA1UECgwORGlnaU5vdGFyIEIuVi4xMjAwBgNVBAMMKURpZ2lOb3RhciBQ
S0lvdmVyaGVpZCBDQSBPcmdhbmlzYXRpZSAtIEcyMB4XDTEwMDUxMjA4NTEzOVoX
DTIwMDMyMzA5NTAwNVowWjELMAkGA1UEBhMCTkwxFzAVBgNVBAoMDkRpZ2lOb3Rh
ciBCLlYuMTIwMAYDVQQDDClEaWdpTm90YXIgUEtJb3ZlcmhlaWQgQ0EgT3JnYW5p
c2F0aWUgLSBHMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALETGQ8n
5mzUVYZL0OyJikWReKxHvUcr5PxF60+0JnNbN9PDf/bj3tej+C1oxQg+S5TW5Icl
NmuEtRh08yhYcy+bas+8BB723t2v/Euq9dtmYiUBJYLe8pdaEG7dXakisQSpI3M6
+HGtHc+EROtH0a9tyHwoq8fyN3p0X1/FAhSKo1rjG2wB412O2WjW9AkbMtyRtSz1
IOuMA20mSbiTxIVd2NKbr1ZqzAUzzKBCnjRVRJxroNQS0CtUzbeJDeX26+j7hQEz
T3pr8Z1yM5YO97KEpaUnxCfxUXMpd7pnbv5M3LTioaGBLzlJjUM4E87QpVzChzoA
Z2VCI/E2WQodo1HIvKOUKjHf4zzynRo8BLDvsQowE3O21/OjTAF1FIV4wNeKOViF
UPou5sW+z4s/r4821CUJLdIPrHKT8r+L1FCz+RVQm5n1FNn7i5GjMiYmoPjfO2CB
hoN5WyvrEz0pOsFt3b2ejofWSq40lwXuFKb23Dh+SukkVAc9l2g3RmsNx6ghrxNU
5Alq8U1GCsld+5tPvd77t1TLuDicpzn7ai3Ae42rpadX7EqSijPF4SBcc9iQkiuA
1Q+GGGl8OU+Ehrz3TFvz1bTKoMLwNyLKeVIfU+aq85CwO93yKP2s68UGJKDJ1C8P
WP21nuwPz7JZ0KIEejhqrnL7vfAlYpQJpwULAgMBAAGjggFhMIIBXTBIBgNVHSAE
QTA/MD0GBFUdIAAwNTAzBggrBgEFBQcCARYnaHR0cDovL3d3dy5kaWdpbm90YXIu
bmwvY3BzL3BraW92ZXJoZWlkMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgEGMIGFBgNVHSMEfjB8gBQ5EItJklzbYRIgzUmdGo7anGdAuaFepFwwWjELMAkG
A1UEBhMCTkwxHjAcBgNVBAoMFVN0YWF0IGRlciBOZWRlcmxhbmRlbjErMCkGA1UE
AwwiU3RhYXQgZGVyIE5lZGVybGFuZGVuIFJvb3QgQ0EgLSBHMoIEAJiW9DBJBgNV
HR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnBraW92ZXJoZWlkLm5sL0RvbU9yZ2Fu
aXNhdGllTGF0ZXN0Q1JMLUcyLmNybDAdBgNVHQ4EFgQUvF2UO9mrewMlc2HC2y3u
/KuPZaEwDQYJKoZIhvcNAQELBQADggIBAI/8LUy32S3VH73vy/S3aBd1nU7V992c
8Som7Z+ithwD1VOz7AjPNOLjw/S1Fi/Iw77X03OrADb5Gkp+1mPpXka6pbaOFbej
KthDHe9dyB+BhbOL9/889Nn0Rgg/nLwdoNmoTM0lUk4KsSD3H+lD2VRGgROawF50
bCqYMur8d7sNpaIxmCJ+fHzn2qSt7LcuGhlx+EhQ2kOPLITdwUAn47XwFU6W1Phc
44YpRivXOwfrOH/IhleX0+8qM8QXUNVkaWsra0VeXS8XylpOz8PXOTz1O59GuZvn
DkmXndbV4xsP6o8BTpoTlFkKAgdISxpgq39P7QvYVQ1ob1WcaWUVQuzA3N1srMMW
zgsdVpukxMTSLuAP4kQnK1BppNxi6IohKUJszAA6lnab70DApF53hDJsJio5Zq5d
47m5sixoHx6akAM58KqzpMxJixg06TfJeynHhHxvRBUv7GFZBMlFy6LWUqJ8fymS
1krFi0Ko1P7q2MeHIxjknXp9c0BSmKCubuMFPwUP4KXGbU3tgzeInMfz3EKaarbX
IUk2d/LvGE/FcNme6d63K4v0vH4o3w1AyYVcrp3FMf/QXA61qH7w6S+6r4iu5bXR
WKWvnHGnKQGQg2k3ggW6/AnBCG6MeDvDMwKAP0SFCB3fVVYIrSyFLV2xA+GuqnTF
MIIGlTCCBH2gAwIBAgIED////zANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJO
TDEXMBUGA1UECgwORGlnaU5vdGFyIEIuVi4xMjAwBgNVBAMMKURpZ2lOb3RhciBQ
S0lvdmVyaGVpZCBDQSBPcmdhbmlzYXRpZSAtIEcyMB4XDTEwMDUxMjA4NTEzOVoX
DTIwMDMyMzA5NTAwNVowWjELMAkGA1UEBhMCTkwxFzAVBgNVBAoMDkRpZ2lOb3Rh
ciBCLlYuMTIwMAYDVQQDDClEaWdpTm90YXIgUEtJb3ZlcmhlaWQgQ0EgT3JnYW5p
c2F0aWUgLSBHMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALETGQ8n
5mzUVYZL0OyJikWReKxHvUcr5PxF60+0JnNbN9PDf/bj3tej+C1oxQg+S5TW5Icl
NmuEtRh08yhYcy+bas+8BB723t2v/Euq9dtmYiUBJYLe8pdaEG7dXakisQSpI3M6
+HGtHc+EROtH0a9tyHwoq8fyN3p0X1/FAhSKo1rjG2wB412O2WjW9AkbMtyRtSz1
IOuMA20mSbiTxIVd2NKbr1ZqzAUzzKBCnjRVRJxroNQS0CtUzbeJDeX26+j7hQEz
T3pr8Z1yM5YO97KEpaUnxCfxUXMpd7pnbv5M3LTioaGBLzlJjUM4E87QpVzChzoA
Z2VCI/E2WQodo1HIvKOUKjHf4zzynRo8BLDvsQowE3O21/OjTAF1FIV4wNeKOViF
UPou5sW+z4s/r4821CUJLdIPrHKT8r+L1FCz+RVQm5n1FNn7i5GjMiYmoPjfO2CB
hoN5WyvrEz0pOsFt3b2ejofWSq40lwXuFKb23Dh+SukkVAc9l2g3RmsNx6ghrxNU
5Alq8U1GCsld+5tPvd77t1TLuDicpzn7ai3Ae42rpadX7EqSijPF4SBcc9iQkiuA
1Q+GGGl8OU+Ehrz3TFvz1bTKoMLwNyLKeVIfU+aq85CwO93yKP2s68UGJKDJ1C8P
WP21nuwPz7JZ0KIEejhqrnL7vfAlYpQJpwULAgMBAAGjggFhMIIBXTBIBgNVHSAE
QTA/MD0GBFUdIAAwNTAzBggrBgEFBQcCARYnaHR0cDovL3d3dy5kaWdpbm90YXIu
bmwvY3BzL3BraW92ZXJoZWlkMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgEGMIGFBgNVHSMEfjB8gBQ5EItJklzbYRIgzUmdGo7anGdAuaFepFwwWjELMAkG
A1UEBhMCTkwxHjAcBgNVBAoMFVN0YWF0IGRlciBOZWRlcmxhbmRlbjErMCkGA1UE
AwwiU3RhYXQgZGVyIE5lZGVybGFuZGVuIFJvb3QgQ0EgLSBHMoIEAJiW9DBJBgNV
HR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnBraW92ZXJoZWlkLm5sL0RvbU9yZ2Fu
aXNhdGllTGF0ZXN0Q1JMLUcyLmNybDAdBgNVHQ4EFgQUvF2UO9mrewMlc2HC2y3u
/KuPZaEwDQYJKoZIhvcNAQELBQADggIBAI/8LUy32S3VH73vy/S3aBd1nU7V992c
8Som7Z+ithwD1VOz7AjPNOLjw/S1Fi/Iw77X03OrADb5Gkp+1mPpXka6pbaOFbej
KthDHe9dyB+BhbOL9/889Nn0Rgg/nLwdoNmoTM0lUk4KsSD3H+lD2VRGgROawF50
bCqYMur8d7sNpaIxmCJ+fHzn2qSt7LcuGhlx+EhQ2kOPLITdwUAn47XwFU6W1Phc
44YpRivXOwfrOH/IhleX0+8qM8QXUNVkaWsra0VeXS8XylpOz8PXOTz1O59GuZvn
DkmXndbV4xsP6o8BTpoTlFkKAgdISxpgq39P7QvYVQ1ob1WcaWUVQuzA3N1srMMW
zgsdVpukxMTSLuAP4kQnK1BppNxi6IohKUJszAA6lnab70DApF53hDJsJio5Zq5d
47m5sixoHx6akAM58KqzpMxJixg06TfJeynHhHxvRBUv7GFZBMlFy6LWUqJ8fymS
1krFi0Ko1P7q2MeHIxjknXp9c0BSmKCubuMFPwUP4KXGbU3tgzeInMfz3EKaarbX
IUk2d/LvGE/FcNme6d63K4v0vH4o3w1AyYVcrp3FMf/QXA61qH7w6S+6r4iu5bXR
WKWvnHGnKQGQg2k3ggW6/AnBCG6MeDvDMwKAP0SFCB3fVVYIrSyFLV2xA+GuqnTF
MIIGlTCCBH2gAwIBAgIED////zANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJO
TDEXMBUGA1UECgwORGlnaU5vdGFyIEIuVi4xMjAwBgNVBAMMKURpZ2lOb3RhciBQ
S0lvdmVyaGVpZCBDQSBPcmdhbmlzYXRpZSAtIEcyMB4XDTEwMDUxMjA4NTEzOVoX
DTIwMDMyMzA5NTAwNVowWjELMAkGA1UEBhMCTkwxFzAVBgNVBAoMDkRpZ2lOb3Rh
ciBCLlYuMTIwMAYDVQQDDClEaWdpTm90YXIgUEtJb3ZlcmhlaWQgQ0EgT3JnYW5p
c2F0aWUgLSBHMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALETGQ8n
5mzUVYZL0OyJikWReKxHvUcr5PxF60+0JnNbN9PDf/bj3tej+C1oxQg+S5TW5Icl
NmuEtRh08yhYcy+bas+8BB723t2v/Euq9dtmYiUBJYLe8pdaEG7dXakisQSpI3M6
+HGtHc+EROtH0a9tyHwoq8fyN3p0X1/FAhSKo1rjG2wB412O2WjW9AkbMtyRtSz1
IOuMA20mSbiTxIVd2NKbr1ZqzAUzzKBCnjRVRJxroNQS0CtUzbeJDeX26+j7hQEz
T3pr8Z1yM5YO97KEpaUnxCfxUXMpd7pnbv5M3LTioaGBLzlJjUM4E87QpVzChzoA
Z2VCI/E2WQodo1HIvKOUKjHf4zzynRo8BLDvsQowE3O21/OjTAF1FIV4wNeKOViF
UPou5sW+z4s/r4821CUJLdIPrHKT8r+L1FCz+RVQm5n1FNn7i5GjMiYmoPjfO2CB
hoN5WyvrEz0pOsFt3b2ejofWSq40lwXuFKb23Dh+SukkVAc9l2g3RmsNx6ghrxNU
5Alq8U1GCsld+5tPvd77t1TLuDicpzn7ai3Ae42rpadX7EqSijPF4SBcc9iQkiuA
1Q+GGGl8OU+Ehrz3TFvz1bTKoMLwNyLKeVIfU+aq85CwO93yKP2s68UGJKDJ1C8P
WP21nuwPz7JZ0KIEejhqrnL7vfAlYpQJpwULAgMBAAGjggFhMIIBXTBIBgNVHSAE
QTA/MD0GBFUdIAAwNTAzBggrBgEFBQcCARYnaHR0cDovL3d3dy5kaWdpbm90YXIu
bmwvY3BzL3BraW92ZXJoZWlkMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgEGMIGFBgNVHSMEfjB8gBQ5EItJklzbYRIgzUmdGo7anGdAuaFepFwwWjELMAkG
A1UEBhMCTkwxHjAcBgNVBAoMFVN0YWF0IGRlciBOZWRlcmxhbmRlbjErMCkGA1UE
AwwiU3RhYXQgZGVyIE5lZGVybGFuZGVuIFJvb3QgQ0EgLSBHMoIEAJiW9DBJBgNV
HR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnBraW92ZXJoZWlkLm5sL0RvbU9yZ2Fu
aXNhdGllTGF0ZXN0Q1JMLUcyLmNybDAdBgNVHQ4EFgQUvF2UO9mrewMlc2HC2y3u
/KuPZaEwDQYJKoZIhvcNAQELBQADggIBAI/8LUy32S3VH73vy/S3aBd1nU7V992c
8Som7Z+ithwD1VOz7AjPNOLjw/S1Fi/Iw77X03OrADb5Gkp+1mPpXka6pbaOFbej
KthDHe9dyB+BhbOL9/889Nn0Rgg/nLwdoNmoTM0lUk4KsSD3H+lD2VRGgROawF50
bCqYMur8d7sNpaIxmCJ+fHzn2qSt7LcuGhlx+EhQ2kOPLITdwUAn47XwFU6W1Phc
44YpRivXOwfrOH/IhleX0+8qM8QXUNVkaWsra0VeXS8XylpOz8PXOTz1O59GuZvn
DkmXndbV4xsP6o8BTpoTlFkKAgdISxpgq39P7QvYVQ1ob1WcaWUVQuzA3N1srMMW
zgsdVpukxMTSLuAP4kQnK1BppNxi6IohKUJszAA6lnab70DApF53hDJsJio5Zq5d
47m5sixoHx6akAM58KqzpMxJixg06TfJeynHhHxvRBUv7GFZBMlFy6LWUqJ8fymS
1krFi0Ko1P7q2MeHIxjknXp9c0BSmKCubuMFPwUP4KXGbU3tgzeInMfz3EKaarbX
IUk2d/LvGE/FcNme6d63K4v0vH4o3w1AyYVcrp3FMf/QXA61qH7w6S+6r4iu5bXR
WKWvnHGnKQGQg2k3ggW6/AnBCG6MeDvDMwKAP0SFCB3fVVYIrSyFLV2xA+GuqnTF
pPNOujeYe4K5
-----END CERTIFICATE-----"""

TestConfigEntries = {}


def storeConfigEntryDB(key, val, typ=None, desc=None):
    TestConfigEntries[key] = {"type": typ, "value": val, "desc": desc}


class ContEntries(object):
    """
    mock class for db config entries
    """

    def delete(self, synchronize_session=False):
        return None

    def count(self):
        return 0

    def __iter__(self):
        return iter([])


@pytest.fixture
def deleteconfig(app):
    # Clear all config entries before starting each test
    Config.query.delete(synchronize_session="fetch")
    db.session.commit()


@pytest.mark.usefixtures("app")
class TestChunkConfigCase(unittest.TestCase):
    @patch("linotp.lib.config.db_api._storeConfigEntryDB", storeConfigEntryDB)
    def test_chunked_config(self):
        """
        test for storing long values
        """

        from linotp.lib.config.db_api import MAX_VALUE_LEN
        from linotp.lib.text_utils import simple_slice

        key_name = "linotp.chunk_test"
        key_type = "text"
        key_desc = "description"

        chunks = []
        for cont_value in simple_slice(big_value, MAX_VALUE_LEN):
            chunks.append(cont_value)

        _store_continous_entry_db(
            chunks, key=key_name, val=big_value, typ=key_type, desc=key_desc
        )

        conf_keys = list(TestConfigEntries.keys())

        # ------------------------------------------------------------------ --

        # make sure that the first key entry 'test' is avaliable
        # and that the keys are representing the calculated number

        assert key_name in conf_keys, TestConfigEntries

        entry = TestConfigEntries[key_name]
        value = entry["value"]
        from_, to_ = entry["desc"].split(":")

        # we count from 0 to eg 3 so we have 4 entries
        assert len(conf_keys) == int(to_) + 1, conf_keys

        # ------------------------------------------------------------------ --

        # check that all entries have the extended key format

        for i in range(int(from_) + 1, int(to_) + 1):
            entry_key = "%s__[%d:%d]" % (key_name, i, int(to_))
            assert entry_key in TestConfigEntries

            value += TestConfigEntries[entry_key]["value"]

        assert value == big_value

        # finally we check if the original type and description is in the
        # last entry

        entry_key = "%s__[%d:%d]" % (key_name, int(to_), int(to_))
        entry_type = TestConfigEntries[entry_key]["type"]
        entry_desc = TestConfigEntries[entry_key]["desc"]

        assert entry_type == key_type
        assert entry_desc == key_desc

        # --------------------------------------------------------------------

        # cleanup the shared dictionary

        for key in list(TestConfigEntries.keys()):
            del TestConfigEntries[key]

        return

    @patch("linotp.lib.config.db_api._storeConfigEntryDB", storeConfigEntryDB)
    @patch("linotp.model.db.session")
    def test__storeConfigDB_text(self, mock_session):
        """
        test for storing long text entries
        """

        key = "linotp.test_data"
        val = big_value
        typ = "text"
        desc = None

        continous_entries = ContEntries()

        mock_session.query.return_value.filter.return_value = continous_entries
        _storeConfigDB(key, val, typ=typ, desc=desc)

        conf_keys = list(TestConfigEntries.keys())

        assert key in conf_keys, TestConfigEntries

        entry = TestConfigEntries[key]
        _from_, to_ = entry["desc"].split(":")

        # we count from 0 to eg 3 so we have 4 entries
        assert len(conf_keys) == int(to_) + 1, conf_keys

        # --------------------------------------------------------------------

        # cleanup the shared dictionary

        for key in list(TestConfigEntries.keys()):
            del TestConfigEntries[key]

        return

    @patch("linotp.lib.config.db_api.encryptPassword")
    @patch("linotp.lib.config.db_api._storeConfigEntryDB", storeConfigEntryDB)
    @patch("linotp.model.db.session")
    def test__storeConfigDB_password(self, mock_session, mock_encryptPassword):
        """
        test for storing long crypted password entries
        """

        key = "linotp.test_data"
        val = big_value
        typ = "password"
        desc = None

        mock_encryptPassword.return_value = big_value
        continous_entries = ContEntries()

        mock_session.query.return_value.filter.return_value = continous_entries
        _storeConfigDB(key, val, typ=typ, desc=desc)

        # check that the value is realy stored

        conf_keys = list(TestConfigEntries.keys())

        assert key in conf_keys, TestConfigEntries

        entry = TestConfigEntries[key]
        _from_, to_ = entry["desc"].split(":")

        # we count from 0 to eg 3 so we have 4 entries
        assert len(conf_keys) == int(to_) + 1, conf_keys

        # --------------------------------------------------------------------

        # cleanup the shared dictionary

        for key in list(TestConfigEntries.keys()):
            del TestConfigEntries[key]

        return

    @patch("linotp.lib.config.db_api._storeConfigEntryDB", storeConfigEntryDB)
    @patch("linotp.model.db.session")
    def test__storeConfigDB_int(self, mock_session):
        """
        test for storing int values
        """

        key = "linotp.test_data"
        val = 1313123131231231313213
        typ = "int"
        desc = "long int"

        continous_entries = ContEntries()

        mock_session.query.return_value.filter.return_value = continous_entries
        _storeConfigDB(key, val, typ=typ, desc=desc)

        # check that the value is realy stored

        conf_keys = list(TestConfigEntries.keys())

        assert key in conf_keys, TestConfigEntries

        assert len(TestConfigEntries) == 1

        entry = TestConfigEntries["linotp.test_data"]
        assert entry["value"] == val

        # --------------------------------------------------------------------

        # cleanup the shared dictionary

        for key in list(TestConfigEntries.keys()):
            del TestConfigEntries[key]

        return


@pytest.mark.usefixtures("app")
@pytest.mark.usefixtures("deleteconfig")
class TestConfigStoreCase(unittest.TestCase):
    def test_storeConfigDB_encoding(self):
        # Test round trip of _storeConfigDB with entries that require
        # encoding of special characters
        conf = {
            "Key": "linotp.TËST",
            "Value": "VALUEÄ",
            "Type": "TYPEß",
            "Description": "DESCRIPTIÖN",
        }

        _storeConfigDB(
            conf["Key"], conf["Value"], conf["Type"], conf["Description"]
        )

        # Check value is correctly returned
        stored_value = _retrieveConfigDB(conf["Key"])
        assert conf["Value"] == stored_value

        # Check type, description in database
        entries = Config.query.all()

        assert len(entries) == 1
        stored_conf = entries[0]

        for key in list(conf.keys()):
            assert conf[key] == getattr(
                stored_conf, key
            ), "Key should match key:%s - expected %r, recevied %r" % (
                key,
                conf[key],
                getattr(stored_conf, key),
            )

    def test_updateExisting(self):
        # Test the following conditions:
        # - An entry is created with chunklength > 1
        # - The type and description are not set
        # - The entry is reduced to one chunk
        # Verify that the resulting config entry has
        # correctly set the type and description

        key = "linotp.testupdate"
        longvalue = "*" * 2000
        value = "value"
        typ = None
        description = None

        _storeConfigDB(key, longvalue, typ, description)
        assert Config.query.count() == 2
        oldentries = Config.query.all()
        assert len(oldentries) == 2

        _storeConfigDB(key, value, typ, description)
        entries = Config.query.all()
        assert len(entries) == 1

        entry = entries[0]
        assert entry.Key == key
        assert entry.Value == value
        assert entry.Description == description
        assert entry.Type == typ


# eof #
