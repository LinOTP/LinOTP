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
Test SMS sending via SMPP.
"""

import threading
import time

import pytest

from linotp.provider import ProviderNotAvailable
from linotp.provider.smsprovider import SMPPSMSProvider
from linotp.tests.tools.dummy_smpp_server import DummySMPPServer

SMPP_HOST = "localhost"
SMPP_PORT = "9123"
SMPP_SYSTEMID = "smsclient"
SMPP_PASSWORD = "foobar"


@pytest.fixture
def smpp_sms_provider():
    prov = SMPPSMSProvider.SMPPSMSProvider()
    prov.config = {
        "server": SMPP_HOST,
        "port": int(SMPP_PORT),
        "system_id": SMPP_SYSTEMID,
        "password": SMPP_PASSWORD,
        "system_type": "",
        "source_addr": "123456",
        "source_addr_npi": 1,
        "source_addr_ton": 1,
        "dest_addr_npi": 1,
        "dest_addr_ton": 1,
        "target_encoding": "ISO8859-1",
    }
    for k, v in prov.config.items():
        setattr(prov, k, v)
    yield prov


@pytest.fixture(scope="module")
def dummy_smpp_server():
    smpp_server = DummySMPPServer(
        host=SMPP_HOST,
        port=SMPP_PORT,
        system_id=SMPP_SYSTEMID,
        password=SMPP_PASSWORD,
    )
    thread = threading.Thread(target=smpp_server.run_server)
    thread.daemon = True
    thread.start()
    time.sleep(1)  # Make sure server is ready
    yield smpp_server


def test_submitMessage(smpp_sms_provider, dummy_smpp_server):
    dummy_smpp_server.reset()
    assert smpp_sms_provider._submitMessage("987654", "Hello world")
    assert [pdu.command for pdu in dummy_smpp_server.pdus] == [
        "bind_transceiver",
        "bind_transceiver_resp",
        "submit_sm",
        "submit_sm_resp",
        "unbind",
        "unbind_resp",
    ]
    assert dummy_smpp_server.messages == ["Hello world"]


def test_submitMessageMulti(smpp_sms_provider, dummy_smpp_server):
    dummy_smpp_server.reset()
    assert smpp_sms_provider._submitMessage("987654", "Hello world" * 20)
    assert [pdu.command for pdu in dummy_smpp_server.pdus] == [
        "bind_transceiver",
        "bind_transceiver_resp",
        "submit_sm",
        "submit_sm_resp",
        "submit_sm",
        "submit_sm_resp",
        "unbind",
        "unbind_resp",
    ]
    msg = "Hello world" * 20
    assert dummy_smpp_server.messages == [msg[:153], msg[153:]]


def test_submitMessageError(smpp_sms_provider, dummy_smpp_server, caplog):
    dummy_smpp_server.reset()
    assert not smpp_sms_provider._submitMessage("987654", "SUBMITFAIL")
    assert (
        "('(69) submit_sm_resp: submit_sm or submit_multi failed', 69)"
        in caplog.messages
    )
    assert not dummy_smpp_server.messages  # No SMS was sent


def test_submitMessageNoConnection(smpp_sms_provider):
    smpp_sms_provider.port = "29999"
    with pytest.raises(ProviderNotAvailable) as ex:
        smpp_sms_provider._submitMessage("987654", "Hello world")
    assert "Failed to connect to server" in str(ex)


def test_submitMessageBadCredentials(smpp_sms_provider, dummy_smpp_server, caplog):
    dummy_smpp_server.reset()
    smpp_sms_provider.password = "bazquux"
    assert not smpp_sms_provider._submitMessage("987654", "Hello world")
    assert "('(13) bind_transceiver_resp: Bind Failed', 13)" in caplog.messages
    assert [pdu.command for pdu in dummy_smpp_server.pdus] == [
        "bind_transceiver",
        "bind_transceiver_resp",
    ]
    assert not dummy_smpp_server.messages  # No SMS was sent
