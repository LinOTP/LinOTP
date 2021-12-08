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

import json
import logging
from datetime import datetime
from typing import Any, Tuple, Union

from linotp.lib.crypto.utils import get_rand_digit_str
from linotp.lib.security.default import DefaultSecurityModule
from linotp.model import db
from linotp.model.schema import ChallengeSchema

log = logging.getLogger(__name__)


class Challenge(ChallengeSchema):
    def __init__(
        self,
        transid: str,
        tokenserial: str,
        challenge: Union[str, bytes] = "",
        data: Union[str, bytes] = "",
        session: str = "",
    ):
        super().__init__()

        self.transid = "" + transid

        #
        # for future use: subtransactions will refer to their parent

        self.ptransid = ""

        # adjust challenge to be binary compatible

        if isinstance(challenge, str):
            challenge = challenge.encode("utf-8")
        self.challenge = challenge

        self.ochallenge = ""

        self.tokenserial = "" + tokenserial

        # adjust data to be binary compatible

        if isinstance(data, str):
            data = data.encode("utf-8")
        self.data = data

        self.timestamp = datetime.now()
        self.session = "" + session
        self.received_count = 0
        self.received_tan = False
        self.valid_tan = False

    @classmethod
    def createTransactionId(cls, length: int = 20) -> str:
        return get_rand_digit_str(length)

    def setData(self, data: Any) -> None:
        if type(data) in [dict, list]:
            save_data = json.dumps(data)
        else:
            save_data = data

        self.data = save_data.encode("utf-8")

    def getData(self) -> Union[dict, str]:
        data: Union[dict, str] = {}
        saved_data = (
            self.data
            if isinstance(self.data, str)
            else self.data.decode("utf-8")
        )
        try:
            data = json.loads(saved_data)
        except BaseException:
            data = saved_data
        return data

    def get(
        self,
        key: str = None,
        fallback: Any = None,
        save: bool = False,
    ) -> Union[None, dict]:
        """
        simulate the dict behaviour to make challenge processing
        easier, as this will have to deal as well with
        'dict only challenges'

        :param key: the attribute name - in case key is not provided, a dict
                    of all class attributes is returned
        :param fallback: if the attribute is not found, the fallback is
                         returned
        :param save: in case of all attributes and save==True, the timestamp is
                     converted to a string representation
        """
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

    def getId(self) -> int:
        return self.id

    def getSession(self) -> str:
        return self.session

    def setSession(self, session: str) -> None:
        """
        set the session state information like open or closed
        - contains in addition the mac of the whole challenge entry

        :param session: dictionary of the session info
        """
        self.session = str(session)

    def add_session_info(self, info: Any) -> None:
        session_dict = {}

        if self.session:
            session_dict = json.loads(self.session)

        session_dict.update(info)

        self.session = str(json.dumps(session_dict))

    def signChallenge(self, hsm: DefaultSecurityModule) -> None:
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

        session = challenge_dict.get("session", {})

        session["status"] = session.get("status", "open")
        session["mac"] = mac

        self.setSession(json.dumps(session))

    def checkChallengeSignature(self, hsm: DefaultSecurityModule) -> bool:
        """
        check the integrity of a challenge

        :param hsm: security module
        :return: success - boolean
        """

        # and calculate the mac for this token data
        challenge_dict = self.get_vars(save=True)
        challenge_data = json.dumps(challenge_dict)

        session = json.loads(self.getSession())
        stored_mac = session.get("mac")
        result = hsm.verfiyMessageSignature(
            message=challenge_data, hex_mac=stored_mac
        )

        if not result:
            log.warning(
                "[checkChallengeSignature] integrity violation for challenge %s, token %s",
                challenge_dict["transid"],
                challenge_dict["tokenserial"],
            )
        return result

    def setChallenge(self, challenge: str) -> None:
        self.challenge = challenge.encode("utf8")

    def getChallenge(self) -> str:

        if not isinstance(self.challenge, str):
            return self.challenge.decode()

        return self.challenge

    def setTanStatus(
        self,
        received: bool = False,
        valid: bool = False,
        increment: bool = True,
    ) -> None:
        self.received_tan = received
        if increment:
            self.received_count += 1
        self.valid_tan = valid

    def getTanStatus(self) -> Tuple[bool, bool]:
        return (self.received_tan, self.valid_tan)

    def close(self) -> None:
        """
        close a session and make it invisible to the validation

        remarks:
         we introduce the challenge status 'closed'. It is set after a first
         successful authentication. The status is required, as we don't remove
         the challenges after validation anymore

        """
        session_info = json.loads(self.session) or {}

        if not session_info:
            session_info = {"status": "open"}
        session_info["status"] = "closed"

        if "reject" in session_info:
            self.valid_tan = False

        self.session = json.dumps(session_info)

    def is_open(self) -> bool:
        """
        check if the session is already closed

        :return: success - boolean
        """
        if self.session == "":
            self.session = "{}"
        session = json.loads(self.session)
        status = session.get("status", "open")
        ret = status == "open"
        return ret

    def getStatus(self) -> bool:
        """
        check if the session is already closed

        :return: success - boolean
        """
        session = json.loads(self.session) or {}
        status = session.get("status", "open")
        return status

    def getTanCount(self) -> int:
        return self.received_count

    def getTransactionId(self) -> str:
        return self.transid

    def getTokenSerial(self) -> str:
        return self.tokenserial

    def save(self) -> str:
        """
        enforce the saving of a challenge
        - will guarantee the uniqness of the transaction id

        :return: transaction id of the stored challenge
        """
        try:
            db.session.add(self)
            db.session.flush()  # Better safe than sorry.

        except Exception:
            log.error("[save]Error during saving challenge")

        return self.transid

    def get_vars(self, save: bool = False) -> dict:
        """
        return a dictionary of all vars in the challenge class

        :return: dict of vars
        """
        descr: dict = {}
        descr["id"] = self.id
        descr["transid"] = self.transid
        descr["challenge"] = self.getChallenge()
        descr["tokenserial"] = self.tokenserial
        descr["data"] = self.getData()
        if save is True:
            descr["timestamp"] = "%s" % self.timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        else:
            descr["timestamp"] = self.timestamp
        descr["received_tan"] = self.received_tan
        descr["valid_tan"] = self.valid_tan

        # for the vars, session is of interest but without mac

        session_info = {"status": "open"}
        if self.session:
            try:
                session_info = json.loads(self.session)
                if "mac" in session_info:
                    del session_info["mac"]
            except Exception:
                pass

        descr["session"] = session_info

        return descr

    def __str__(self) -> str:
        descr = self.get_vars()
        return "%s" % str(descr)
