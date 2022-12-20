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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de

import binascii
import logging
from datetime import datetime
from typing import Any, Optional, Tuple, Union

from linotp.lib.type_utils import DEFAULT_TIMEFORMAT
from linotp.model import db
from linotp.model.schema import TokenSchema
from linotp.model.tokenRealm import TokenRealm

log = logging.getLogger(__name__)


class Token(TokenSchema):
    def __init__(self, serial: str):
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

        self.LinOtpIdResolver = ""
        self.LinOtpIdResClass = ""
        self.LinOtpUserid = ""

        # when the token is created all time stamps are set to utc now

        self.LinOtpCreationDate = datetime.utcnow().replace(microsecond=0)
        self.LinOtpLastAuthMatch = None
        self.LinOtpLastAuthSuccess = None

    def _fix_spaces(self, data: str) -> str:
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

    def getSerial(self) -> str:
        return self.LinOtpTokenSerialnumber

    def set_encrypted_seed(
        self,
        encrypted_seed: bytes,
        iv: bytes,
        reset_failcount: bool = True,
        reset_counter: bool = True,
    ) -> None:
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

    def get_encrypted_seed(self) -> Tuple[bytes, bytes]:
        key = binascii.unhexlify(self.LinOtpKeyEnc or "")
        iv = binascii.unhexlify(self.LinOtpKeyIV or "")
        return key, iv

    def setUserPin(self, enc_userPin: bytes, iv: bytes) -> None:
        self.LinOtpTokenPinUser = binascii.hexlify(enc_userPin).decode("utf-8")
        self.LinOtpTokenPinUserIV = binascii.hexlify(iv).decode("utf-8")

    def getUserPin(self) -> Tuple[bytes, bytes]:
        pu = self._fix_spaces(self.LinOtpTokenPinUser or "")
        puiv = self._fix_spaces(self.LinOtpTokenPinUserIV or "")
        key = binascii.unhexlify(pu)
        iv = binascii.unhexlify(puiv)
        return key, iv

    def getOtpCounter(self) -> int:
        return self.LinOtpCount or 0

    def set_hashed_pin(self, pin: bytes, iv: bytes) -> None:
        self.LinOtpSeed = binascii.hexlify(iv).decode("utf-8")
        self.LinOtpPinHash = binascii.hexlify(pin).decode("utf-8")

    def get_hashed_pin(self) -> Tuple[bytes, bytes]:
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash)
        return iv, pin

    @staticmethod
    def copy_pin(src: Any, target: Any) -> None:
        target.LinOtpSeed = src.LinOtpSeed
        target.LinOtpPinHash = src.LinOtpPinHash

    def set_encrypted_pin(self, pin: bytes, iv: bytes) -> None:
        self.LinOtpSeed = binascii.hexlify(iv).decode("utf-8")
        self.LinOtpPinHash = binascii.hexlify(pin).decode("utf-8")
        self.LinOtpPinHash = "@@" + self.LinOtpPinHash

    def get_encrypted_pin(self) -> Tuple[bytes, bytes]:
        iv = binascii.unhexlify(self.LinOtpSeed)
        pin = binascii.unhexlify(self.LinOtpPinHash[2:])
        return iv, pin

    def setDescription(self, desc: str) -> str:
        if desc is None:
            desc = ""
        self.LinOtpTokenDesc = str(desc)
        return self.LinOtpTokenDesc

    def setOtpLen(self, otplen: Union[str, int]) -> None:
        self.LinOtpOtpLen = int(otplen)

    def deleteToken(self) -> bool:
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

    def isPinEncrypted(self, pin: Optional[str] = None) -> bool:
        ret = False
        if pin is None:
            pin = self.LinOtpPinHash
        if pin and pin.startswith("@@"):
            ret = True
        return ret

    def setSoPin(self, enc_soPin: bytes, iv: bytes) -> None:
        self.LinOtpTokenPinSO = binascii.hexlify(enc_soPin).decode("utf-8")
        self.LinOtpTokenPinSOIV = binascii.hexlify(iv).decode("utf-8")

    def __str__(self) -> str:
        return self.LinOtpTokenDesc

    def get(
        self,
        key: str = None,
        fallback: Any = None,
        save: bool = False,
    ) -> Any:
        """
        simulate the dict behaviour to make challenge processing
        easier, as this will have to deal as well with
        'dict only challenges'

        :param key: the attribute name - in case key is not provided, a dict
                    of all class attributes is returned
        :param fallback: if the attribute is not found, the fallback
                         is returned
        :param save: in case all attributes are returned and save==True, the
                     timestamp is converted to a string representation
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

    def get_vars(self, save: bool = False) -> dict:

        ret: dict = {}
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

    def __repr__(self) -> str:
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

    def getSyncWindow(self) -> int:
        return self.LinOtpSyncWindow

    def setCountWindow(self, counter: int) -> None:
        self.LinOtpCountWindow = counter

    def getCountWindow(self) -> int:
        return self.LinOtpCountWindow

    def getInfo(self) -> str:
        # Fix for working with MS SQL servers
        # MS SQL servers sometimes return a '<space>' when the column is empty:
        # ''
        return self._fix_spaces(self.LinOtpTokenInfo or "")

    def setInfo(self, info: str) -> None:
        self.LinOtpTokenInfo = info

    def storeToken(self) -> bool:
        if self.LinOtpUserid is None:
            self.LinOtpUserid = ""
        if self.LinOtpIdResClass is None:
            self.LinOtpIdResClass = ""
        if self.LinOtpIdResolver is None:
            self.LinOtpIdResolver = ""

        db.session.add(self)
        db.session.flush()

        return True

    def setType(self, typ: str) -> None:
        self.LinOtpTokenType = typ

    def getType(self) -> str:
        return self.LinOtpTokenType or "hmac"

    def updateType(self, typ: str) -> None:
        # in case the previous type is not the same type
        # we must reset the counters.
        # Remark: comparison must be made case insensitiv
        if self.LinOtpTokenType.lower() != typ.lower():
            self.LinOtpCount = 0
            self.LinOtpFailCount = 0

        self.LinOtpTokenType = typ

    def getRealms(self) -> str:
        return self.realms or ""

    def getRealmNames(self) -> list:
        r_list = []
        for r in self.realms:
            r_list.append(r.name)
        return r_list

    def addRealm(self, realm: str) -> None:
        if realm is not None:
            self.realms.append(realm)
        else:
            log.error("adding empty realm!")

    def setRealms(self, realms: list) -> None:
        if realms is not None:
            self.realms = realms
        else:
            log.error("assigning empty realm!")


def createToken(serial: str) -> Token:
    log.debug("createToken(%s)", serial)
    serial = "" + serial
    token = Token(serial)
    log.debug("token object created")

    return token
