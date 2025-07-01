#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP userid resolvers.
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
"""This module implements the communication interface
   for resolving user info to the /etc/passwd user base

PasswdIdResolver.IdResolver class
    implements the UserIdResolver for local /etc/passwd lookup

Remarks:
    Don't use this as an enterprise solution!

"""

import logging
import os
import re

from passlib.hash import (
    des_crypt,
    md5_crypt,
    sha1_crypt,
    sha256_crypt,
    sha512_crypt,
)

from linotp.lib.cache_utils import cache_in_request
from linotp.lib.config.util import expand_here

from . import resolver_registry
from .UserIdResolver import (
    ResolverLoadConfigError,
    ResParamsType,
    UserIdResolver,
    getResolverClass,
)

log = logging.getLogger(__name__)


def str2unicode(input_str):
    """
    convert as binary string into a unicode string by trying various encodings
    :param input_str: input binary string
    :return: unicode output
    """

    output_str = input_str
    conversions = [
        {},
        {"encoding": "utf-8"},
        {"encoding": "iso-8859-1"},
        {"encoding": "iso-8859-15"},
    ]
    for param in conversions:
        try:
            output_str = str(input_str, **param)
            break
        except UnicodeDecodeError as exx:
            if param == conversions[-1]:
                log.info("no unicode conversion found for %r", input_str)
                raise exx

    return output_str


def tokenise(r):
    def _(s):
        ret = None
        st = s.strip()
        m = re.match("^" + r, st)
        if m:
            ret = (st[: m.end()].strip(), st[m.end() :].strip())
            # ret[0].strip()      ## remove ws
            # ret[1].strip()
        return ret

    return _


@resolver_registry.class_entry("useridresolver.PasswdIdResolver.IdResolver")
@resolver_registry.class_entry("useridresolveree.PasswdIdResolver.IdResolver")
@resolver_registry.class_entry("useridresolver.passwdresolver")
@resolver_registry.class_entry("passwdresolver")
class IdResolver(UserIdResolver):
    db_prefix = "useridresolver.PasswdIdResolver.IdResolver"

    fields = {
        "username": 1,
        "userid": 1,
        "description": 0,
        "phone": 0,
        "mobile": 0,
        "email": 0,
        "givenname": 0,
        "surname": 0,
        "gender": 0,
    }

    searchFields = {
        "username": "text",
        "userid": "numeric",
        "description": "text",
        "email": "text",
    }

    sF = {
        "username": 0,
        "cryptpass": 1,
        "userid": 2,
        "description": 4,
        "email": 4,
    }
    resolver_parameters: ResParamsType = {"fileName": (True, None, str)}
    resolver_parameters.update(UserIdResolver.resolver_parameters)

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        """
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the linotp config
        :type  config: the linotp config dict
        """
        log.debug("Setting up PasswdIdResolver")

    def __init__(self):
        """
        simple constructor
        """
        self.name = "etc-passwd"
        self.fileName = ""

        self.name = "P"
        self.nameDict = {}
        self.descDict = {}
        self.reversDict = {}
        self.passDict = {}
        self.officePhoneDict = {}
        self.homePhoneDict = {}
        self.surnameDict = {}
        self.givennameDict = {}
        self.emailDict = {}

    def close(self):
        """
        request hook - to close down resolver object
        """
        return

    def loadFile(self):
        """
        init loads the /etc/passwd
          user and uid as a dict for /
          user loginname lookup
        """

        if self.fileName == "":
            self.fileName = "/etc/passwd"

        log.info("[loadFile] loading users from file %s", self.fileName)

        ID = self.sF["userid"]
        NAME = self.sF["username"]
        PASS = self.sF["cryptpass"]
        DESCRIPTION = self.sF["description"]

        with open(self.fileName, encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                line = str2unicode(line)
                fields = line.split(":", 7)
                self.nameDict[f"{fields[NAME]}"] = fields[ID]

                # for speed reason - build a revers lookup
                self.reversDict[fields[ID]] = f"{fields[NAME]}"

                # for full info store the line
                self.descDict[fields[ID]] = fields

                # store the crypted password
                self.passDict[fields[ID]] = fields[PASS]

                # store surname, givenname and phones
                descriptions = fields[DESCRIPTION].split(",")
                name = descriptions[0]
                names = name.split(" ", 1)
                self.givennameDict[fields[ID]] = names[0]
                self.surnameDict[fields[ID]] = ""
                self.officePhoneDict[fields[ID]] = ""
                self.homePhoneDict[fields[ID]] = ""
                self.emailDict[fields[ID]] = ""
                if len(names) >= 2:
                    self.surnameDict[fields[ID]] = names[1]
                if len(descriptions) >= 4:
                    self.officePhoneDict[fields[ID]] = descriptions[2]
                    self.homePhoneDict[fields[ID]] = descriptions[3]
                if len(descriptions) >= 5:
                    for field in descriptions[4:]:
                        # very basic e-mail regex
                        email_match = re.search(r".+@.+\..+", field)
                        if email_match:
                            self.emailDict[fields[ID]] = email_match.group(0)

    def checkPass(self, uid, password):
        """
        This function checks the password for a given uid.
        - returns true in case of success
        -         false if password does not match

        We do not support shadow passwords at the moment. so the seconds column
        of the passwd file needs to contain the crypted password
        """

        if isinstance(password, str):
            log.debug(
                "Password is a unicode string. Encoding to UTF-8 for \
                       crypt.crypt() function."
            )
            password = password.encode("utf-8")
        log.info("[checkPass] checking password for user uid %s", uid)
        cryptedpasswd = self.passDict[uid]
        log.debug(
            "[checkPass] We found the crypted pass %s for uid %s",
            cryptedpasswd,
            uid,
        )
        if not cryptedpasswd:
            log.warning(
                "[checkPass] Failed to verify password. "
                "No crypted password found in file"
            )
            return False

        if cryptedpasswd in {"x", "*"}:
            err = "Sorry, currently no support for shadow passwords"
            log.error("[checkPass] %s ", err)
            raise NotImplementedError(err)

        if self._verify_password(password, cryptedpasswd):
            log.info("[checkPass] successfully authenticated user uid %s", uid)
            return True
        else:
            log.warning("[checkPass] user uid %s failed to authenticate", uid)
            return False

    @staticmethod
    def _verify_password(password, hashed_password):
        """
        _verify_password - checks the given password against the stored hash.

        check the Modular Crypt Format (MCF):

        $<id>[$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]

        s. https://en.wikipedia.org/wiki/Crypt_%28C%29

        :param password: the plain text password
        :param hashed_password: the hashed password
        :return :  true in case of success, false if password does not match

        """
        # ------------------------------------------------------------------ --

        crypt_methods = [
            md5_crypt,
            des_crypt,
            sha1_crypt,
            sha256_crypt,
            sha512_crypt,
        ]

        for crypt_method in crypt_methods:
            if hasattr(crypt_method, "identify") and crypt_method.identify(
                hashed_password
            ):
                return crypt_method.verify(password, hashed_password)

        return False  # pragma: no cover

    @cache_in_request
    def getUserInfo(self, userId, no_passwd=False):
        """
        get some info about the user
        as we only have the loginId, we have to traverse the dict for the value

        :param userId: the to be searched user
        :param no_passwd: retrun no password
        :return: dict of user info
        """
        ret = {}

        if userId in self.reversDict:
            fields = self.descDict.get(userId)

            for key in self.sF:
                if no_passwd and key == "cryptpass":
                    continue
                index = self.sF[key]
                ret[key] = fields[index]

            ret["givenname"] = self.givennameDict.get(userId)
            ret["surname"] = self.surnameDict.get(userId)
            ret["phone"] = self.homePhoneDict.get(userId)
            ret["mobile"] = self.officePhoneDict.get(userId)
            ret["email"] = self.emailDict.get(userId)

        return ret

    def getUsername(self, userId):
        """
        ## TODO: why does this return bool

        :param userId: the user to be searched
        :return: true, if a user id exists
        """
        return userId in self.reversDict

    def getUserId(self, LoginName):
        """
        search the user id from the login name
            we need the encoding no more as the input is converted to unicode
            by the str2unicode function

        :param LoginName: the login of the user
        :return: the userId
        """
        return self.nameDict.get(LoginName, "") or ""

    def getSearchFields(self, searchDict=None):
        """
        show, which search fields this userIdResolver supports

        TODO: implementation is not completed

        :param searchDict: fields, which should be queried
        :return: dict of all searchFields
        """
        if searchDict is not None:
            for search in searchDict:
                pattern = searchDict[search]

                log.debug("[getSearchFields] searching for %s:%s", search, pattern)

        return self.searchFields

    def getUserList(self, searchDict: dict):
        """
        get a list of all users matching the search criteria of the searchdict

        :param searchDict: dict of search expressions
        """

        def _userMatchesSearchDict(userDict):
            """
            `searchDict` refers to the one given to `getUserList`
            """
            user_key, user_value = userDict

            searchKeyToCheckFunctionMapping = {
                "username": self.checkUserName,
                "userid": self.checkUserId,
                "description": self.checkDescription,
                "email": self.checkEmail,
            }

            # OR filter
            # is true if no `searchTerm` in given `searchDict` or
            # value of `searchTerm` matches at least one searchable field
            searchTermValue = searchDict.get("searchTerm")
            orFilter = not searchTermValue
            if searchTermValue:
                for checkingFunc in searchKeyToCheckFunctionMapping.values():
                    try:
                        if checkingFunc(user_value, searchTermValue):
                            orFilter = True
                            break
                    except Exception:
                        pass
            # AND filter
            # is true if all `search_keys` match their `search_value`.
            # Note: a `search_keys` is only evaluated if it's a searchable field
            andFilter = True
            filteredSearchDict = {
                search_key: search_value
                for search_key, search_value in searchDict.items()
                if (search_key in self.searchFields)
            }
            for search_key, pattern in filteredSearchDict.items():
                checkingFunc = searchKeyToCheckFunctionMapping[search_key]
                if not checkingFunc(user_value, pattern):
                    andFilter = False
                    break

            return orFilter and andFilter

        matchingUserDicts = dict(filter(_userMatchesSearchDict, self.descDict.items()))

        userInfoList = [
            self.getUserInfo(user_value[self.sF["userid"]], no_passwd=True)
            for user_value in matchingUserDicts.values()
        ]
        return userInfoList

    def checkUserName(self, line, pattern):
        """
        check for user name
        """

        username = line[self.sF["username"]]
        ret = self.stringMatch(username, pattern)
        return ret

    def checkDescription(self, line, pattern):
        description = line[self.sF["description"]]
        ret = self.stringMatch(description, pattern)
        return ret

    def checkEmail(self, line, pattern):
        email = line[self.sF["email"]]
        ret = self.stringMatch(email, pattern)
        return ret

    def stringMatch(self, cString, cPattern):
        ret = False
        e = s = ""

        string = cString.lower()
        pattern = cPattern.lower()

        if pattern.startswith("*"):
            e = "e"
            pattern = pattern[1:]

        if pattern.endswith("*"):
            s = "s"
            pattern = pattern[:-1]

        if e == "e" and s == "s":
            if string.find(pattern) != -1:
                return True
        elif e == "e":
            if string.endswith(pattern):
                return True
        elif s == "s":
            if string.startswith(pattern):
                return True
        elif string == pattern:
            return True

        return ret

    def checkUserId(self, line, pattern):
        """
        check for the userId
        """
        ret = False

        try:
            cUserId = int(line[self.sF["userid"]])
        except BaseException:
            return ret

        (op, val) = tokenise(">=|<=|>|<|=|between")(pattern)

        if op == "between":
            (lVal, hVal) = val.split(",", 2)
            try:
                ilVal = int(lVal.strip())
                ihVal = int(hVal.strip())
                if ihVal < ilVal:
                    v = ihVal
                    ihVal = ilVal
                    ilVal = v
            except BaseException:
                return ret

            if cUserId <= ihVal and cUserId >= ilVal:
                ret = True
        else:
            try:
                ival = int(val)
            except BaseException:
                return ret

            if op == "=":
                if cUserId == ival:
                    ret = True

            elif op == ">":
                if cUserId > ival:
                    ret = True

            elif op == ">=":
                if cUserId >= ival:
                    ret = True

            elif (op in {"<", "<="}) and cUserId < ival:
                ret = True

        return ret

    #############################################################
    # server info methods
    #############################################################
    def getResolverId(self):
        """getResolverId(LoginName)
        - returns the resolver identifier string
        - empty string if not exist
        """
        return self.fileName

    @classmethod
    def getResolverClassType(cls):
        return "passwdresolver"

    def getResolverType(self):
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor["clazz"] = "useridresolver.PasswdIdResolver.IdResolver"
        descriptor["config"] = {"fileName": "string"}
        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def loadConfig(self, config, conf):
        """loadConfig(configDict)
        The UserIdResolver could be configured
        from the pylon app config - here
        this could be the passwd file ,
        whether it is /etc/passwd or /etc/shadow
        """

        l_config, missing = self.filter_config(config, conf)

        if missing:
            log.error("missing config entries: %r", missing)
            msg = f" missing config entries: {missing!r}"
            raise ResolverLoadConfigError(msg)

        fileName = l_config["fileName"]

        fileName = expand_here(fileName)

        fileName = os.path.realpath(fileName)

        if not os.path.isfile(fileName) or not os.access(fileName, os.R_OK):
            msg = f"File {fileName!r} does not exist or is not accessible"
            raise ResolverLoadConfigError(msg)
        self.fileName = fileName
        self.loadFile()

        return self


if __name__ == "__main__":
    print(" PasswdIdResolver - IdResolver class test ")

    y = getResolverClass("PasswdIdResolver", "IdResolver")()

    y.loadConfig({"linotp.passwdresolver.fileName": "/etc/passwd"}, "")
    x = getResolverClass("PasswdIdResolver", "IdResolver")()
    x.loadConfig({"linotp.passwdresolver.fileName": "/etc/meinpass"}, "")

    print("======/etc/meinpass==========")
    print(x.getUserList({"username": "*", "userid": ">= 1000"}))
    print("======/etc/passwd==========")
    print(y.getUserList({"username": "*", "userid": ">= 1000"}))
    print("================")

    user = "koelbel"
    loginId = y.getUserId(user)

    print(f" {user} -  {loginId}")
    print(" reId - " + y.getResolverId())

    ret = y.getUserInfo(loginId)

    print(f"result {ret!r}")

    ret = y.getSearchFields()
    # ret["username"]="^bea*"
    search = {
        "userid": " between 1000, 1005",
        #              "username":"^bea*",
        # "description":"*Audio*",
        #              "descriptio":"*Winkler*",
        #              "userid":" <=1003",
    }

    ret = y.getUserList(search)

    print(ret)
