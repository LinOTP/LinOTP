# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2021 KeyIdentity GmbH
#
#    This file is part of LinOTP.
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

"""This is a very simple SMPP server which can be used to check
whether an SMPPSMSProvider works correctly. It understands the three
SMPP operations `bind_transceiver`, `unbind`, and `submit_sm`, which
are incidentally exactly the ones that the SMPPSMSProvider uses. It
can only talk to at most one client at any one time.

Use a command like::

    python3 linotp/tests/tools/dummy_smpp_server.py 192.168.56.1 9123

to start the server and have it listen on IP address 192.168.56.1, TCP
port 9123 (this is reasonable if you're using VirtualBox to run a
LinOTP SVA on the default host-only network; other addresses and ports
are available). Use the LinOTP management interface to configure an
SMS provider using the same IP address and port number. You can
optionally use the `--systemid` and `--password` options to set up a
system ID (what otherwise would be called a "user name") and password,
in which case whatever the client supplies must match the configured
values, or else an `ESME_RBINDFAIL` error will occur upon
`bind_transceiver`. (To be exact, the test occurs if and only if
`password` is non-null; the system ID defaults to `smsclient` but
isn't used at all unless a password has been explicitly set.)

The server sends plausible replies to incoming PDUs and logs its
activities to the console. Don't mistake this for a general SMPP
testing framework; it is written under the assumption that it will
talk to LinOTP only.

"""

import logging
import socket
import struct

from smpplib import consts, exceptions, smpp
from smpplib.client import SimpleSequenceGenerator

MC_ID = "MC001"


class DummySMPPServer:

    """This class provides a very simple-minded SMPP server, for basic
    testing. It understands only the commands that the
    `SMPPSMSProvider` class is sending (via `smpplib`), and can give
    sensible replies.

    """

    def __init__(
        self,
        host="127.0.0.1",
        port="9123",
        system_id="smsclient",
        password=None,
        loglevel="WARNING",
    ):
        self.host = host
        self.port = int(port)
        self.system_id = system_id
        self.password = password
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(loglevel)
        self.sequence_generator = SimpleSequenceGenerator()
        self.reset()

    def reset(self):
        """Reset the internal stores for PDUs and sent SMSes."""
        self.pdus = []
        self.messages = []

    # The following two methods are needed to make
    # `smpplib.smpp.make_pdu()` happy. They aren't actually used in
    # anger because all we do is echo the sequence numbers provided by
    # the client, but the code complains if they're not there.

    @property
    def sequence(self):
        return self.sequence_generator.sequence

    def next_sequence(self):
        return self.sequence_generator.next_sequence()

    # The following two methods are needed to make the
    # `DummySMPPServer()` class work as a context manager.

    def __enter__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()

    def run_server(self):
        """Start the server. This is suitable as the `target` argument to
        `threading.Thread()` if you want to run the dummy server from
        pytest, and it ensures that all the socket stuff happens in
        the thread, which avoids nasty errors.

        """

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self.listen()
        self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()

    def read_raw_pdu(self, sock):
        """Read a SMPP PDU from the client and return it as a `bytes` object."""
        # This part of the code is inspired by^W^Wlargely cribbed from
        # `smpplib.Client.read_pdu()`.

        try:
            pdu_bytes = sock.recv(4)
        except socket.timeout:
            raise
        except socket.error as e:
            self.logger.warning(e)
            raise exceptions.ConnectionError()
        if not pdu_bytes:
            raise exceptions.ConnectionError()

        try:
            length = struct.unpack(">L", pdu_bytes)[0]
        except struct.error:
            bad_pdu_msg = "Bad PDU: %r"
            self.logger.warning(bad_pdu_msg, pdu_bytes)
            raise exceptions.PDUError(bad_pdu_msg.format(pdu_bytes))

        while len(pdu_bytes) < length:
            try:
                more_bytes = sock.recv(length - len(pdu_bytes))
            except socket.timeout:
                raise
            except socket.error as e:
                self.logger.warning(e)
                raise exceptions.ConnectionError()
            if not pdu_bytes:
                raise exceptions.ConnectionError()
            pdu_bytes += more_bytes
        # self.logger.debug(f'>> {pdu_bytes.hex(" ", -4)}')  # Python >=3.8
        self.logger.debug(">> %s", pdu_bytes.hex())

        return pdu_bytes

    def listen(self):
        """This method implements the actual SMPP server. Note that we can
        only talk to one client at a time; removing that restriction
        would make the code much more complicated and we don't really
        need it.

        """

        msg_count = 0
        while True:
            self._sock.listen()
            sock, address = self._sock.accept()
            done = False
            while not done:
                # Note how we're leveraging `smpplib` to avoid the –
                # considerable – inconvenience of parsing (and
                # generating) SMPP PDUs ourselves.

                try:
                    pdu = smpp.parse_pdu(
                        self.read_raw_pdu(sock),
                        client=self,
                        allow_unknown_opt_params=None,
                    )
                    self.pdus.append(pdu)
                except exceptions.ConnectionError:
                    break

                # Do something with the PDU.

                print(f"> {pdu.command}", end="")
                if pdu.command == "bind_transceiver":
                    status = consts.SMPP_ESME_ROK
                    if self.password is not None:
                        if (
                            pdu.system_id.decode() != self.system_id
                            or pdu.password.decode() != self.password
                        ):
                            status = consts.SMPP_ESME_RBINDFAIL

                    res_pdu = smpp.make_pdu(
                        "bind_transceiver_resp",
                        status=status,
                        sequence=pdu._sequence,
                    )
                    print("\n< OK")
                elif pdu.command == "submit_sm":
                    text = pdu.short_message.decode()
                    print(
                        f": from={pdu.source_addr.decode()} "
                        f"to={pdu.destination_addr.decode()} "
                        f'text="{text}"'
                    )

                    # You can get the server to return any of a bunch
                    # of error codes simply by including the (textual
                    # representation of the) error code in the
                    # message. E.g., send the message `Ahoy SUBMITFAIL
                    # Ahoy` to elicit the error code,
                    # `ESME_RSUBMITFAIL`.

                    data = {
                        "status": pdu.status,
                        "sequence": pdu._sequence,
                    }
                    for err in (
                        "SYSERR",
                        "MSGQFUL",
                        "SUBMITFAIL",
                        "THROTTLED",
                        "X_T_APPN",
                        "DELIVERYFAILURE",
                    ):
                        if err in text:
                            data["status"] = getattr(
                                consts, "SMPP_ESME_R" + err
                            )
                            out_msg = f"ERR {err}"
                            break
                    else:
                        msg_count += 1
                        msg_id = f"{MC_ID}:{msg_count:04d}"
                        data["message_id"] = msg_id
                        out_msg = f"OK {msg_id}"
                        self.messages.append(text)

                    res_pdu = smpp.make_pdu("submit_sm_resp", **data)
                    print(f"< {out_msg}")
                elif pdu.command == "unbind":
                    res_pdu = smpp.make_pdu(
                        "unbind_resp",
                        status=pdu.status,
                        sequence=pdu._sequence,
                    )
                    done = True
                    print("\n< OK")
                else:
                    raise ValueError(f"Unsupported SMPP command {pdu.command}")
                self.pdus.append(res_pdu)
                response = res_pdu.generate()
                # self.logger.debug(f'<< {response.hex(" ", -4)}')  # Python 3.8
                self.logger.debug("<< %s", response.hex())
                sock.send(response)
            sock.close()
            done = False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--systemid",
        default="smsclient",
        help="Client system ID for authentication",
    )
    parser.add_argument(
        "--password", default=None, help="Client password for authentication"
    )
    parser.add_argument(
        "--loglevel", default="DEBUG", help="Log level for Python logging"
    )
    parser.add_argument(
        "ipaddr",
        default="127.0.0.1",
        help="IP address that the server listens on",
    )
    parser.add_argument(
        "port", default="9123", help="TCP port that the server listens on"
    )
    args = parser.parse_args()

    with DummySMPPServer(
        host=args.ipaddr,
        port=args.port,
        system_id=args.systemid,
        password=args.password,
        loglevel=args.loglevel,
    ) as srv:
        srv.listen()
