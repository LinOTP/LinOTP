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
#

"""
ldap resolver tests
"""

import json

import ldap
import pytest
from ldap.controls import SimplePagedResultsControl
from mockldap import LDAPObject, MockLdap
from mockldap.filter import Test as LDAPTest

from linotp.tests import TestController

# pylint: disable=redefined-outer-name, unused-argument


class LDAPExtTest(LDAPTest):
    def matches(self, dn, attrs):
        values = attrs.get(self.attr)

        if values is None:
            return False

        if self.value == "*":
            return len(values) > 0

        # we have to compare bytes and strings in the value array

        matches = False
        for value in values:

            compare_value = value

            if isinstance(self.value, str) and isinstance(value, bytes):
                try:
                    compare_value = value.decode()
                except UnicodeDecodeError:
                    continue

            # strings should be compare case insensitive

            if isinstance(self.value, str) and isinstance(compare_value, str):
                if self.value.casefold() == compare_value.casefold():
                    matches = True
                    break
            else:
                if self.value == compare_value:
                    matches = True
                    break

        return matches


class LDAPExtObject(LDAPObject):
    """
    Extension of MockLdap to implement missing functions

    In LinOTP, we use some of the extended LDAP functions
    which are not implemented in MockLdap. This class provides
    some basic implementations of these.

    Note: We planned to upstream those changes to the mockldap
    library. The library is no longer maintained and we are not
    familiar enough with the topic right now. If we come across
    this topic again, we should consider digging up LINOTP-1336
    again to think about a fork or upstreaming.
    """

    def _guid_object(self, object_guid):
        """
        helper for the search_ext to support special search of '<guid='

        in ldap there is the option to directly search for an
        objectguid. As in the mockldap there is no direct search for this,
        we iterate over all entries and if found, replace the query with
        the query for the found base dn

        :param object_guid: the object guid
        :return: tuple of base and filter or None, None
        """

        for user_info in list(self.directory.values()):
            entries = list(user_info.keys())
            for entry in entries:
                if entry.casefold() == "objectguid".casefold():
                    user_guid = user_info[entry][0].hex()
                    if object_guid == user_guid:
                        base = user_info["distinguishedName"][0].decode()
                        filterstr = "(objectClass=*)"
                        return (base, filterstr)

        return None, None

    def search_ext(
        self,
        base,
        scope,
        filterstr,
        attrlist=None,  # pylint: disable=dangerous-default-value
        serverctrls=[],
        timeout=0,
        sizelimit=500,
    ):

        if not filterstr:
            filterstr = "(objectClass=*)"

        # for special ad syntax to searhc for objecguid objects,
        # we have to rewrite the search

        if base.startswith("<guid="):

            (n_base, n_filterstr) = self._guid_object(base[6:-1])

            if n_base and n_filterstr:
                base = n_base
                filterstr = n_filterstr

        return self.search(
            base, scope, filterstr=filterstr, attrlist=attrlist, attrsonly=0
        )

    def search_s(
        self,
        base,
        scope,
        filterstr="(objectClass=*)",
        attrlist=None,
        attrsonly=0,
    ):

        return self.search(
            base, scope, filterstr=filterstr, attrlist=attrlist, attrsonly=0
        )

    def result2(
        self, msgid, all=1, timeout=None
    ):  # pylint: disable=redefined-builtin
        return ldap.RES_SEARCH_RESULT, self._pop_async_result(msgid), None

    def result3(
        self, msgid, all=1, timeout=None
    ):  # pylint: disable=redefined-builtin
        """
        Last result plus server controls
        """

        class FakeServerControl:
            controlType = SimplePagedResultsControl.controlType
            cookie = None

        return (
            ldap.RES_SEARCH_RESULT,
            self._pop_async_result(msgid),
            None,
            [FakeServerControl],
        )


@pytest.fixture(autouse=True)
def extendMockldap(monkeypatch):
    """
    Extend MockLdap with our additional functions
    """
    monkeypatch.setattr("mockldap.ldapobject.LDAPObject", LDAPExtObject)
    monkeypatch.setattr("mockldap.filter.Test.matches", LDAPExtTest.matches)


@pytest.fixture(autouse=True)
def ad_entries():
    _ad_entries = {
        "DC=net": {"DC": ["net"]},
        "DC=example,DC=net": {"DC": ["example"]},
        "DC=hotad,DC=example,DC=net": {"DC": ["hotad"]},
        "OU=corp,DC=hotad,DC=example,DC=net": {"OU": ["corp"]},
        "CN=Users,DC=hotad,DC=example,DC=net": {"CN": ["Users"]},
        "OU=Domain Controllers,DC=hotad,DC=example,DC=net": {
            "OU": ["Domain Controllers"]
        },
        "OU=grouptests,DC=hotad,DC=example,DC=net": {"OU": ["grouptests"]},
        "OU=people,DC=hotad,DC=example,DC=net": {"OU": ["people"]},
        "CN=Administrator,CN=Users,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Administrator"],
            "description": [
                b"Built-in account for administering the computer/domain"
            ],
            "distinguishedName": [
                b"CN=Administrator,CN=Users,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140129145235.0Z"],
            "whenChanged": [b"20190516114546.0Z"],
            "uSNCreated": [b"8196"],
            "memberOf": [
                b"CN=Group Policy Creator Owners,CN=Users,DC=hotad,DC=example,DC=net",
                b"CN=Domain Admins,CN=Users,DC=hotad,DC=example,DC=net",
                b"CN=Enterprise Admins,CN=Users,DC=hotad,DC=example,DC=net",
                b"CN=Schema Admins,CN=Users,DC=hotad,DC=example,DC=net",
                b"CN=Administrators,CN=Builtin,DC=hotad,DC=example,DC=net",
            ],
            "uSNChanged": [b"718271"],
            "name": [b"Administrator"],
            "objectGUID": [b"p\x88\xb6\xd4\xa1\xfc\x89K\x95?\xe9\xd1\xe0[\ne"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"131976523302492000"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"132024807461208000"],
            "logonHours": [
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ],
            "pwdLastSet": [b"131979940043984000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1e\xf4\x01\x00\x00"
            ],
            "adminCount": [b"1"],
            "accountExpires": [b"0"],
            "logonCount": [b"61"],
            "sAMAccountName": [b"Administrator"],
            "sAMAccountType": [b"805306368"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "isCriticalSystemObject": [b"TRUE"],
            "dSCorePropagationData": [
                b"20140129150836.0Z",
                b"20140129150836.0Z",
                b"20140129150307.0Z",
                b"16010101181216.0Z",
            ],
            "lastLogonTimestamp": [b"132024807461208000"],
            "msDS-SupportedEncryptionTypes": [b"0"],
        },
        "CN=Guest,CN=Users,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Guest"],
            "description": [
                b"Built-in account for guest access to the computer/domain"
            ],
            "distinguishedName": [
                b"CN=Guest,CN=Users,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140129145235.0Z"],
            "whenChanged": [b"20140129145235.0Z"],
            "uSNCreated": [b"8197"],
            "memberOf": [b"CN=Guests,CN=Builtin,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"8197"],
            "name": [b"Guest"],
            "objectGUID": [b";U0\xbd33U@\x8c\xc4q\xdb\x01\xf9e\xb8"],
            "userAccountControl": [b"66082"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"0"],
            "primaryGroupID": [b"514"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1e\xf5\x01\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"Guest"],
            "sAMAccountType": [b"805306368"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "isCriticalSystemObject": [b"TRUE"],
            "dSCorePropagationData": [
                b"20140129150307.0Z",
                b"16010101000001.0Z",
            ],
        },
        "CN=HOTTYBOTTY,OU=Domain Controllers,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
                b"computer",
            ],
            "cn": [b"HOTTYBOTTY"],
            "userCertificate": [
                b"0\x82\x06)0\x82\x05\x11\xa0\x03\x02\x01\x02\x02\n\x15\xe8\xbax\x00\x00\x00\x00\x00\x0e0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000c1\x130\x11\x06\n\t\x92&\x89\x93\xf2,d\x01\x19\x16\x03net1\x170\x15\x06\n\t\x92&\x89\x93\xf2,d\x01\x19\x16\x07example1\x150\x13\x06\n\t\x92&\x89\x93\xf2,d\x01\x19\x16\x05hotad1\x1c0\x1a\x06\x03U\x04\x03\x13\x13hotad-HOTTYBOTTY-CA0\x1e\x17\r191105005736Z\x17\r201104005736Z0'1%0#\x06\x03U\x04\x03\x13\x1cHOTTYBOTTY.hotad.example.net0\x82\x01\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xa8\x82\xc5\x80cV\x16\xa2\xffG'\xfa\xc3\xb7\x152 \xc1\xde_\x06\xc7\xcc\xf5eY\x1c\x1b\xbb\xc8\x87\x16\xf83\xca8\xf4\xa1\xe4\xcc\xca\x8d\x13M\xda_,\xf5\x05S\xad\xba\xc8d\x92\xfc~\xc2Be\xa6o\xcb\xa2\xd3\x97\x89\xaa\xdc\xdc\xeb&\xf6%9$\xa5\x05\x8b`@\"{\xdaB\xd0W\x94\xef\x92\xa8\xbb\t\xe1x\xe8H\x84\xf7!\x02\xa8\xed\x8cm&\xde\xda\x04\x8er\x17\xf3\xaf\xce\x05\xad\xc0\x8c\xad\xc6T*\xb7S\xdc\xf5\xb3gl~\xc6\xac5\x8e1(\xd3.\x92\xb4\xdflR\nO+\xd5\x92\xa5c\xf8*\x0b8\x0cG-\x83Ce\xf4H\x9a},\x94\x04\x07\x91,\x07W\x0e]!.\xc7'\x0e\xa3\xbc\x9a\tcySdEs\xc7\xfah\x88\x81\x88@W\xf3C%\n\xdcaI\x87\xa8w\xb8KM\xc1T\xb1\xd1S\x02\xe9\xe5p\xef\x92\xef\xe3.\x8f\xd4\xeb!\xa1x\xb7\x93\xfd\xc4\xbd\xd1)(\x93\x13J\x7f\xecn\x10h\n7\xddb\x01\"\xe0RW\x02\x03\x01\x00\x01\xa3\x82\x03\x190\x82\x03\x150/\x06\t+\x06\x01\x04\x01\x827\x14\x02\x04\"\x1e \x00D\x00o\x00m\x00a\x00i\x00n\x00C\x00o\x00n\x00t\x00r\x00o\x00l\x00l\x00e\x00r0\x1d\x06\x03U\x1d%\x04\x160\x14\x06\x08+\x06\x01\x05\x05\x07\x03\x02\x06\x08+\x06\x01\x05\x05\x07\x03\x010\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa00x\x06\t*\x86H\x86\xf7\r\x01\t\x0f\x04k0i0\x0e\x06\x08*\x86H\x86\xf7\r\x03\x02\x02\x02\x00\x800\x0e\x06\x08*\x86H\x86\xf7\r\x03\x04\x02\x02\x00\x800\x0b\x06\t`\x86H\x01e\x03\x04\x01*0\x0b\x06\t`\x86H\x01e\x03\x04\x01-0\x0b\x06\t`\x86H\x01e\x03\x04\x01\x020\x0b\x06\t`\x86H\x01e\x03\x04\x01\x050\x07\x06\x05+\x0e\x03\x02\x070\n\x06\x08*\x86H\x86\xf7\r\x03\x070H\x06\x03U\x1d\x11\x04A0?\xa0\x1f\x06\t+\x06\x01\x04\x01\x827\x19\x01\xa0\x12\x04\x10\x06%\xf2\x9d\x0frQH\xb6h\xb3`\xd7\x85\xda\xe0\x82\x1cHOTTYBOTTY.hotad.example.net0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\x85\xa6\xe1\xc3\xd6}{\x94$h\x9d\xf9P\xd4V+{\xde\xaaV0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xbe\x16\x04\x1amD\x07c@9_\x8a\xf4\xe7\x86%\x18\xf6?\x940\x81\xdd\x06\x03U\x1d\x1f\x04\x81\xd50\x81\xd20\x81\xcf\xa0\x81\xcc\xa0\x81\xc9\x86\x81\xc6ldap:///CN=hotad-HOTTYBOTTY-CA,CN=HOTTYBOTTY,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=hotad,DC=example,DC=net?certificateRevocationList?base?objectClass=cRLDistributionPoint0\x81\xce\x06\x08+\x06\x01\x05\x05\x07\x01\x01\x04\x81\xc10\x81\xbe0\x81\xbb\x06\x08+\x06\x01\x05\x05\x070\x02\x86\x81\xaeldap:///CN=hotad-HOTTYBOTTY-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=hotad,DC=example,DC=net?cACertificate?base?objectClass=certificationAuthority0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x87^<q\x01s\x97\xc9\xa0'\x9d\xd74=0\x8b\xa5\x8d\x1d\x96\xc5X\xa5\xa1@\x06T\xb9.'\xaf3l\x9e&\xe0\xbc\x95\xc2H_\xc8:q\x12\xab{ZC\x02\xaa\xd4\xc5\xf6,n\x8c\xf1\x08m\x88\xe3m\x10\xd2\x01\xc1\x0e\x9c\xfc/`\xa1j9\x0bu\x99S0\xe4\xfa\xa3\xba\x1d\xa2o\xf6^\r\\\x1b\xf3\xd06\xe1?\xd6\x9c\x11\xc7\xbb\xbfk\xe2\xc6\xe1\xb8\x127+\x89\xa5\xef\x9a&\x19>g\x8cD\xb0\xe5E\xfc?}Pq\x8d\x83@\xd9aXl\xfa\xd3\ts\x7ffzQ\x7f4\x16\x0c\x19QK\rp\xeb\x93\xddJE\xab\xda\xb1\x95\xaf\xac\xf1\x94\x997\x07uL(\xe0E\xb1C\xc8\x17\x18\xafg\xcb\xc7\xb3lj\xe3\xcf \xe4\xe8\x991\xcc}\xd1\x82\xe0N\xebG\x19\xb9\x8d\x88^\xf5\xc6]\xeb\xc9\xed\xbd\xe2T\x1e\x0b.\x11\xe7`b\xc3\x87G\xd5\xcf\x00\xb9\x0c\xfa\xc5\xcf@;\xe3\xde\x9e\xc7VbeS\x0e\xc4\x05u`\xda\xc7\xa7\x8d^\xee\x18\x1c",
                b'0\x82\x06)0\x82\x05\x11\xa0\x03\x02\x01\x02\x02\n\x18\n\x89\xb6\x00\x00\x00\x00\x00\r0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000c1\x130\x11\x06\n\t\x92&\x89\x93\xf2,d\x01\x19\x16\x03net1\x170\x15\x06\n\t\x92&\x89\x93\xf2,d\x01\x19\x16\x07example1\x150\x13\x06\n\t\x92&\x89\x93\xf2,d\x01\x19\x16\x05hotad1\x1c0\x1a\x06\x03U\x04\x03\x13\x13hotad-HOTTYBOTTY-CA0\x1e\x17\r181216175823Z\x17\r191216175823Z0\'1%0#\x06\x03U\x04\x03\x13\x1cHOTTYBOTTY.hotad.example.net0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xe5\x88[\x08\x93i\xcf\x93\x1dy\xfcBWf\xca7\x19\x0c\xd3\x16"H_W`\xee\xbd\xb93o\xce\xb2"\x19\x8d\x96\x1a\xb0,\xc2M\r\xb6\x86\x01\x80\xc9#.\x9aS8\x86\xbd6\x8d\xab\xdd\x03\x96\xb7\xf1pYl\x82\x19\xde\x139\xfc\xc3\xbe\xeb\xad\x10\x83\x1dW\x01x\xd7\xf3B\x17\xf2VT`\xe5Z\xbe\x86l\x16\xb4~\xff\xbe\xcc2\xe5\xda\x08y\x1d\xbe\xec\xb6\x9e\x9f7m$\xb1\x00O\x1c\xd8\x97\x1a*\xec \x15z\xf8\xd6\x7f\x97L\x84\xf7I\xbdipwN\xa9\xed\x16v!\x1aAo\xb8\x1c\x8d~\xcf\xf4\x81\xe0l\xd8\xf3\xf8\xb6\x10\xd0\xec\x8e/Cy\x87\xd1\xf2\xc0\x90\xd6\x07)\xe5\xfdT\xcb\xa90\xb7\xd8m\xc4\xb8\xe2\'J\x98\xa6\xad\xff\x9c\xc0U\x88\x9aY\xe8\x9d:\x8d\xcb\xfe g\xaf\x88^SN\x12Urw\xd9kO\xf4\xfbyR\x8d\\!\x81\xbd\xccg$<w\x98\xd5\xdbS1\xdc\x1c7[\xdd\x88<\xcb\xf4Ie\xc0\xa3\xbe\xae\x8d\x8d\x7f\x02\x03\x01\x00\x01\xa3\x82\x03\x190\x82\x03\x150/\x06\t+\x06\x01\x04\x01\x827\x14\x02\x04"\x1e \x00D\x00o\x00m\x00a\x00i\x00n\x00C\x00o\x00n\x00t\x00r\x00o\x00l\x00l\x00e\x00r0\x1d\x06\x03U\x1d%\x04\x160\x14\x06\x08+\x06\x01\x05\x05\x07\x03\x02\x06\x08+\x06\x01\x05\x05\x07\x03\x010\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa00x\x06\t*\x86H\x86\xf7\r\x01\t\x0f\x04k0i0\x0e\x06\x08*\x86H\x86\xf7\r\x03\x02\x02\x02\x00\x800\x0e\x06\x08*\x86H\x86\xf7\r\x03\x04\x02\x02\x00\x800\x0b\x06\t`\x86H\x01e\x03\x04\x01*0\x0b\x06\t`\x86H\x01e\x03\x04\x01-0\x0b\x06\t`\x86H\x01e\x03\x04\x01\x020\x0b\x06\t`\x86H\x01e\x03\x04\x01\x050\x07\x06\x05+\x0e\x03\x02\x070\n\x06\x08*\x86H\x86\xf7\r\x03\x070H\x06\x03U\x1d\x11\x04A0?\xa0\x1f\x06\t+\x06\x01\x04\x01\x827\x19\x01\xa0\x12\x04\x10\x06%\xf2\x9d\x0frQH\xb6h\xb3`\xd7\x85\xda\xe0\x82\x1cHOTTYBOTTY.hotad.example.net0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\x9eQ\x96\xd4m*x\xffs^tf\x11n\x1bc\xad^\x7f\x880\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xbe\x16\x04\x1amD\x07c@9_\x8a\xf4\xe7\x86%\x18\xf6?\x940\x81\xdd\x06\x03U\x1d\x1f\x04\x81\xd50\x81\xd20\x81\xcf\xa0\x81\xcc\xa0\x81\xc9\x86\x81\xc6ldap:///CN=hotad-HOTTYBOTTY-CA,CN=HOTTYBOTTY,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=hotad,DC=example,DC=net?certificateRevocationList?base?objectClass=cRLDistributionPoint0\x81\xce\x06\x08+\x06\x01\x05\x05\x07\x01\x01\x04\x81\xc10\x81\xbe0\x81\xbb\x06\x08+\x06\x01\x05\x05\x070\x02\x86\x81\xaeldap:///CN=hotad-HOTTYBOTTY-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=hotad,DC=example,DC=net?cACertificate?base?objectClass=certificationAuthority0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x7f\xcbTy\x8e\xc7C\x19\xdeF;\x1eg\xfeFSE\xa0\xf7\xd3\x8e\x00"r\x825\xaa\xd6\t\x9e\x04\xad\x0eo\x9c\xcf\x9b\x9b\x91\xd2\x0f\xac\xe4\x10\x99\xb7)\xcd\xd8\x90\xb1X\x87\x8a\x8f\x84u\xefp\xc5A\x10\xc5\xa9\xf0\x07\x04\xe6N\x13\x17%17}\x9d1\xba\xaf=\xc5\x15\x9d\xad\xf4\x81\xe4\xf5\x94\x04\x9c\xb8=j\x9e\xe2\x10\xf9\xae/\xbe\xcd\xa8\xac\xac\xb4\x88\xa6\x1f\xe6\x1b\xbe*\x1a\xeeJ\xc2\xac\x9b\xc4\xee\x83\xd6\xdc\x1c\xa8\'\x80[\x08\xf5\xaf\xb6\xf8\x08X\x8a=)e\x87\x1c\xd1\xe5\xaf\xd2\x81Tf8\xe9n\xc1\x9a\xad\xde\xff\xbb\x88\x80\xf3J\xce\xf9\xb124\xb9\xe8\xb9\xc7rGd\x80i.\xcb\x1e*&;%\x1b]\xd6t\xb1H\x11\xa6\xc6]\x1d\x91O|\xc4\r[\x8a~\xb6\x84\xfdG?\n\xe0\xf2\x95Dt=\xedw\x1fr\xce\xf2\xaf.\xc8R_w\xa8\x92\xc0\xd8\xfd\xb3\x1c\xa5\xce\xf2\x02\xc15)\x1ej*\xbej\xf4\xf5\x0f\x9a@\xd4\\\x0b\xfa\xd9\x99',
            ],
            "distinguishedName": [
                b"CN=HOTTYBOTTY,OU=Domain Controllers,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140129145326.0Z"],
            "whenChanged": [b"20191210100804.0Z"],
            "uSNCreated": [b"12293"],
            "memberOf": [
                b"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=hotad,DC=example,DC=net",
                b"CN=Cert Publishers,CN=Users,DC=hotad,DC=example,DC=net",
            ],
            "uSNChanged": [b"783466"],
            "name": [b"HOTTYBOTTY"],
            "objectGUID": [b"\x06%\xf2\x9d\x0frQH\xb6h\xb3`\xd7\x85\xda\xe0"],
            "userAccountControl": [b"532480"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"132209643996760000"],
            "localPolicyFlags": [b"0"],
            "pwdLastSet": [b"132200779271400000"],
            "primaryGroupID": [b"516"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1e\xe8\x03\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"34193"],
            "sAMAccountName": [b"HOTTYBOTTY$"],
            "sAMAccountType": [b"805306369"],
            "operatingSystem": [b"Windows Server 2008 R2 Enterprise"],
            "operatingSystemVersion": [b"6.1 (7601)"],
            "operatingSystemServicePack": [b"Service Pack 1"],
            "serverReferenceBL": [
                b"CN=HOTTYBOTTY,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dNSHostName": [b"HOTTYBOTTY.hotad.example.net"],
            "rIDSetReferences": [
                b"CN=RID Set,CN=HOTTYBOTTY,OU=Domain Controllers,DC=hotad,DC=example,DC=net"
            ],
            "servicePrincipalName": [
                b"TERMSRV/HOTTYBOTTY",
                b"TERMSRV/HOTTYBOTTY.hotad.example.net",
                b"ldap/HOTTYBOTTY.hotad.example.net/ForestDnsZones.hotad.example.net",
                b"ldap/HOTTYBOTTY.hotad.example.net/DomainDnsZones.hotad.example.net",
                b"Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/HOTTYBOTTY.hotad.example.net",
                b"DNS/HOTTYBOTTY.hotad.example.net",
                b"GC/HOTTYBOTTY.hotad.example.net/hotad.example.net",
                b"RestrictedKrbHost/HOTTYBOTTY.hotad.example.net",
                b"RestrictedKrbHost/HOTTYBOTTY",
                b"HOST/HOTTYBOTTY/HOTAD",
                b"HOST/HOTTYBOTTY.hotad.example.net/HOTAD",
                b"HOST/HOTTYBOTTY",
                b"HOST/HOTTYBOTTY.hotad.example.net",
                b"HOST/HOTTYBOTTY.hotad.example.net/hotad.example.net",
                b"E3514235-4B06-11D1-AB04-00C04FC2DCD2/3795f607-4f4c-455b-b352-a820a8830083/hotad.example.net",
                b"ldap/HOTTYBOTTY/HOTAD",
                b"ldap/3795f607-4f4c-455b-b352-a820a8830083._msdcs.hotad.example.net",
                b"ldap/HOTTYBOTTY.hotad.example.net/HOTAD",
                b"ldap/HOTTYBOTTY",
                b"ldap/HOTTYBOTTY.hotad.example.net",
                b"ldap/HOTTYBOTTY.hotad.example.net/hotad.example.net",
            ],
            "objectCategory": [
                b"CN=Computer,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "isCriticalSystemObject": [b"TRUE"],
            "dSCorePropagationData": [
                b"20140129150307.0Z",
                b"16010101000001.0Z",
            ],
            "lastLogonTimestamp": [b"132204460842384000"],
            "msDS-SupportedEncryptionTypes": [b"31"],
            "msDFSR-ComputerReferenceBL": [
                b"CN=HOTTYBOTTY,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=hotad,DC=example,DC=net"
            ],
        },
        "CN=krbtgt,CN=Users,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"krbtgt"],
            "description": [b"Key Distribution Center Service Account"],
            "distinguishedName": [
                b"CN=krbtgt,CN=Users,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140129145327.0Z"],
            "whenChanged": [b"20140129150836.0Z"],
            "uSNCreated": [b"12324"],
            "memberOf": [
                b"CN=Denied RODC Password Replication Group,CN=Users,DC=hotad,DC=example,DC=net"
            ],
            "uSNChanged": [b"12745"],
            "showInAdvancedViewOnly": [b"TRUE"],
            "name": [b"krbtgt"],
            "objectGUID": [b"]fmG\xcb\xab\xd7B\xbc*J\xf4(jmn"],
            "userAccountControl": [b"514"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"130354808077880000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1e\xf6\x01\x00\x00"
            ],
            "adminCount": [b"1"],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"krbtgt"],
            "sAMAccountType": [b"805306368"],
            "servicePrincipalName": [b"kadmin/changepw"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "isCriticalSystemObject": [b"TRUE"],
            "dSCorePropagationData": [
                b"20140129150836.0Z",
                b"20140129150307.0Z",
                b"16010101000416.0Z",
            ],
        },
        "CN=Clark Maxwell,OU=corp,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Clark Maxwell"],
            "sn": [b"Maxwell"],
            "givenName": [b"Clark"],
            "distinguishedName": [
                b"CN=Clark Maxwell,OU=corp,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140129150349.0Z"],
            "whenChanged": [b"20191211162200.0Z"],
            "displayName": [b"Clark Maxwell"],
            "uSNCreated": [b"12721"],
            "uSNChanged": [b"783709"],
            "name": [b"Clark Maxwell"],
            "objectGUID": [b"\x9a\x13Y\xb6uF\xd4N\xba\x0f \xc9\xfd\xd9{\x00"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"132185447043840000"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"132185447175816000"],
            "pwdLastSet": [b"130354814297600000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eO\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"maxwell"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"maxwell@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20140129150349.0Z",
                b"16010101000000.0Z",
            ],
            "lastLogonTimestamp": [b"132205549202436000"],
            "msDS-SupportedEncryptionTypes": [b"0"],
        },
        "CN=郎朗,OU=corp,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"\xe9\x83\x8e\xe6\x9c\x97"],
            "givenName": [b"\xe9\x83\x8e\xe6\x9c\x97"],
            "distinguishedName": [
                b"CN=\xe9\x83\x8e\xe6\x9c\x97,OU=corp,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140130160618.0Z"],
            "whenChanged": [b"20140130160618.0Z"],
            "displayName": [b"\xe9\x83\x8e\xe6\x9c\x97"],
            "uSNCreated": [b"16539"],
            "uSNChanged": [b"16545"],
            "name": [b"\xe9\x83\x8e\xe6\x9c\x97"],
            "objectGUID": [b"\x03\x18\x05\x1c=;\xc2H\xa9\x81W\x7fxl\xff\xe8"],
            "userAccountControl": [b"512"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"130355715783401000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eP\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"\xe9\x83\x8e\xe6\x9c\x97"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [
                b"\xe9\x83\x8e\xe6\x9c\x97@hotad.example.net"
            ],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20140130160618.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=أبو يوسف يعقوب بن إسحاق الصبّاح الكندي\u200e,OU=corp,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [
                b"\xd8\xa3\xd8\xa8\xd9\x88 \xd9\x8a\xd9\x88\xd8\xb3\xd9\x81 \xd9\x8a\xd8\xb9\xd9\x82\xd9\x88\xd8\xa8 \xd8\xa8\xd9\x86 \xd8\xa5\xd8\xb3\xd8\xad\xd8\xa7\xd9\x82 \xd8\xa7\xd9\x84\xd8\xb5\xd8\xa8\xd9\x91\xd8\xa7\xd8\xad \xd8\xa7\xd9\x84\xd9\x83\xd9\x86\xd8\xaf\xd9\x8a\xe2\x80\x8e"
            ],
            "distinguishedName": [
                b"CN=\xd8\xa3\xd8\xa8\xd9\x88 \xd9\x8a\xd9\x88\xd8\xb3\xd9\x81 \xd9\x8a\xd8\xb9\xd9\x82\xd9\x88\xd8\xa8 \xd8\xa8\xd9\x86 \xd8\xa5\xd8\xb3\xd8\xad\xd8\xa7\xd9\x82 \xd8\xa7\xd9\x84\xd8\xb5\xd8\xa8\xd9\x91\xd8\xa7\xd8\xad \xd8\xa7\xd9\x84\xd9\x83\xd9\x86\xd8\xaf\xd9\x8a\xe2\x80\x8e,OU=corp,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140130160817.0Z"],
            "whenChanged": [b"20140130160817.0Z"],
            "displayName": [
                b"\xd8\xa3\xd8\xa8\xd9\x88 \xd9\x8a\xd9\x88\xd8\xb3\xd9\x81 \xd9\x8a\xd8\xb9\xd9\x82\xd9\x88\xd8\xa8 \xd8\xa8\xd9\x86 \xd8\xa5\xd8\xb3\xd8\xad\xd8\xa7\xd9\x82 \xd8\xa7\xd9\x84\xd8\xb5\xd8\xa8\xd9\x91\xd8\xa7\xd8\xad \xd8\xa7\xd9\x84\xd9\x83\xd9\x86\xd8\xaf\xd9\x8a\xe2\x80\x8e"
            ],
            "uSNCreated": [b"16548"],
            "uSNChanged": [b"16554"],
            "name": [
                b"\xd8\xa3\xd8\xa8\xd9\x88 \xd9\x8a\xd9\x88\xd8\xb3\xd9\x81 \xd9\x8a\xd8\xb9\xd9\x82\xd9\x88\xd8\xa8 \xd8\xa8\xd9\x86 \xd8\xa5\xd8\xb3\xd8\xad\xd8\xa7\xd9\x82 \xd8\xa7\xd9\x84\xd8\xb5\xd8\xa8\xd9\x91\xd8\xa7\xd8\xad \xd8\xa7\xd9\x84\xd9\x83\xd9\x86\xd8\xaf\xd9\x8a\xe2\x80\x8e"
            ],
            "objectGUID": [b"\x8a\x0b\xb7\xa8=\xe4\x0fD\x88\xe5\xdfl`\x9b\rx"],
            "userAccountControl": [b"512"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"130355716973669000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eQ\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [
                b"\xd8\xa7\xd9\x84\xd8\xb5\xd8\xa8\xd9\x91\xd8\xa7\xd8\xad"
            ],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [
                b"\xd8\xa7\xd9\x84\xd8\xb5\xd8\xa8\xd9\x91\xd8\xa7\xd8\xad@hotad.example.net"
            ],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20140130160817.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Test User,OU=grouptests,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Test User"],
            "sn": [b"User"],
            "givenName": [b"Test"],
            "distinguishedName": [
                b"CN=Test User,OU=grouptests,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140520133730.0Z"],
            "whenChanged": [b"20151112163916.0Z"],
            "displayName": [b"Test User"],
            "uSNCreated": [b"83296"],
            "memberOf": [
                b"CN=group1,OU=grouptests,DC=hotad,DC=example,DC=net"
            ],
            "uSNChanged": [b"274872"],
            "name": [b"Test User"],
            "objectGUID": [b"\xe5\xc8V\x8f6+\x0bL\xbcs\xf5-c\x91\xa6J"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"130892190138372000"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"130892190330408000"],
            "pwdLastSet": [b"130450666501788000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eU\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"testuser1"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"testuser1@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20140520133730.0Z",
                b"16010101000000.0Z",
            ],
            "lastLogonTimestamp": [b"130918199564188000"],
        },
        "CN=Test 2. User,OU=grouptests,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Test 2. User"],
            "sn": [b"User"],
            "givenName": [b"Test"],
            "initials": [b"2"],
            "distinguishedName": [
                b"CN=Test 2. User,OU=grouptests,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20140520134302.0Z"],
            "whenChanged": [b"20140520134302.0Z"],
            "displayName": [b"Test 2. User"],
            "uSNCreated": [b"83305"],
            "memberOf": [
                b"CN=group1,OU=grouptests,DC=hotad,DC=example,DC=net"
            ],
            "uSNChanged": [b"83311"],
            "name": [b"Test 2. User"],
            "objectGUID": [b"\xfd\x16\x81\xe54\xea\xc0C\x8fat\xe9\\P\xcal"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"130450669821468000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eV\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"testuser2"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"testuser2@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20140520134302.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Olaf Hürß,OU=utf8,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Olaf H\xc3\xbcr\xc3\x9f"],
            "sn": [b"H\xc3\xbcr\xc3\x9f"],
            "givenName": [b"Olaf"],
            "distinguishedName": [
                b"CN=Olaf H\xc3\xbcr\xc3\x9f,OU=utf8,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20150304153621.0Z"],
            "whenChanged": [b"20150305085648.0Z"],
            "displayName": [b"Olaf H\xc3\xbcr\xc3\x9f"],
            "uSNCreated": [b"190229"],
            "uSNChanged": [b"190410"],
            "name": [b"Olaf H\xc3\xbcr\xc3\x9f"],
            "objectGUID": [
                b"\xffm\xac\xef\xc1\x16\xa1A\xbb+\x8f\x85Uc\xee\xc9"
            ],
            "userAccountControl": [b"512"],
            "badPwdCount": [b"3"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"130717647869472000"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"0"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eY\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"olafh\xc3\xbcr\xc3\x9f"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"olafh\xc3\xbcr\xc3\x9f@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20150304153621.0Z",
                b"16010101000000.0Z",
            ],
            "mail": [b"olafhuerss@example.net"],
        },
        "CN=Erika Mustermann,OU=profserv,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Erika Mustermann"],
            "sn": [b"Mustermann"],
            "givenName": [b"Erika"],
            "distinguishedName": [
                b"CN=Erika Mustermann,OU=profserv,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20160118074551.0Z"],
            "whenChanged": [b"20170711151048.0Z"],
            "displayName": [b"Erika Mustermann"],
            "uSNCreated": [b"303989"],
            "memberOf": [b"CN=OTP,OU=profserv,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"484457"],
            "name": [b"Erika Mustermann"],
            "objectGUID": [b"M5f\xf1,\x9e\x8cF\x87?\x06\xc7s\x1c\xd7\xef"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"131396794001356000"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"131396795016916000"],
            "pwdLastSet": [b"130975767515236000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eZ\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"erika.mustermann"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"erika.mustermann@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [b"16010101000000.0Z"],
            "lastLogonTimestamp": [b"131442594482312000"],
        },
        "CN=Kurt Vorlage,OU=profserv,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Kurt Vorlage"],
            "sn": [b"Vorlage"],
            "givenName": [b"Kurt"],
            "distinguishedName": [
                b"CN=Kurt Vorlage,OU=profserv,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20160118074633.0Z"],
            "whenChanged": [b"20160118074633.0Z"],
            "displayName": [b"Kurt Vorlage"],
            "uSNCreated": [b"303996"],
            "memberOf": [b"CN=OTP,OU=profserv,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"304001"],
            "name": [b"Kurt Vorlage"],
            "objectGUID": [b"Ozf@\x94\xb3\xffJ\x8bC\x1c\x1b\xc5l\x05\xb2"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"130975767932692000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1e[\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"kurt.vorlage"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"kurt.vorlage@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [b"16010101000000.0Z"],
        },
        "CN=Mirko Ahnert,OU=corp,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Mirko Ahnert"],
            "sn": [b"Ahnert"],
            "givenName": [b"Mirko"],
            "distinguishedName": [
                b"CN=Mirko Ahnert,OU=corp,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170718124702.0Z"],
            "whenChanged": [b"20170719115121.0Z"],
            "displayName": [b"Mirko Ahnert"],
            "uSNCreated": [b"488587"],
            "memberOf": [
                b"CN=Domain Admins,CN=Users,DC=hotad,DC=example,DC=net"
            ],
            "uSNChanged": [b"488786"],
            "name": [b"Mirko Ahnert"],
            "objectGUID": [
                b"\x05\xbc\xa7\xa0Rf\x1bF\x87\xc3f\xea\xb5\xd9\xdc@"
            ],
            "userAccountControl": [b"512"],
            "badPwdCount": [b"7"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"131847801776484000"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"131449384249708000"],
            "pwdLastSet": [b"131449386817780000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1e]\x04\x00\x00"
            ],
            "adminCount": [b"1"],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"1"],
            "sAMAccountName": [b"mirko.ahnert"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"mirko.ahnert@hotad.example.net"],
            "lockoutTime": [b"0"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170718132354.0Z",
                b"16010101000000.0Z",
            ],
            "lastLogonTimestamp": [b"131449343199400000"],
        },
        "CN=Albrecht Altdorfer,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Albrecht Altdorfer"],
            "sn": [b"Altdorfer"],
            "telephoneNumber": [b"+49123456789"],
            "givenName": [b"Albrecht"],
            "distinguishedName": [
                b"CN=Albrecht Altdorfer,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719122350.0Z"],
            "whenChanged": [b"20170719122936.0Z"],
            "displayName": [b"Albrecht Altdorfer"],
            "uSNCreated": [b"488794"],
            "memberOf": [b"CN=anames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"488863"],
            "name": [b"Albrecht Altdorfer"],
            "objectGUID": [b'jr\x9baS\xd9\xf0E\xa3\x04\xcb\xd0i`"\xb4'],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449406308576000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1e^\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"albrecht.aldtorfer"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"albrecht.aldtorfer@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719122401.0Z",
                b"20170719122350.0Z",
                b"16010101000000.0Z",
            ],
            "mail": [b"albrecht.altdorfer@hotad.example.net"],
        },
        "CN=Maurice Adams,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Maurice Adams"],
            "sn": [b"Adams"],
            "givenName": [b"Maurice"],
            "distinguishedName": [
                b"CN=Maurice Adams,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719133916.0Z"],
            "whenChanged": [b"20170719133917.0Z"],
            "displayName": [b"Maurice Adams"],
            "uSNCreated": [b"488976"],
            "memberOf": [b"CN=anames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"488983"],
            "name": [b"Maurice Adams"],
            "objectGUID": [b"\xc3\xd2\xd4cz\x07gB\xaf\xbbG\xe8\xcb\xa8.\x98"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449451565580000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eo\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"maurice.adams"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"maurice.adams@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719133916.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Tschingis Aitmatow,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Tschingis Aitmatow"],
            "sn": [b"Aitmatow"],
            "givenName": [b"Tschingis"],
            "distinguishedName": [
                b"CN=Tschingis Aitmatow,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134007.0Z"],
            "whenChanged": [b"20170719134007.0Z"],
            "displayName": [b"Tschingis Aitmatow"],
            "uSNCreated": [b"488985"],
            "memberOf": [
                b"CN=mixednames,OU=groups,DC=hotad,DC=example,DC=net",
                b"CN=anames,OU=groups,DC=hotad,DC=example,DC=net",
            ],
            "uSNChanged": [b"488991"],
            "name": [b"Tschingis Aitmatow"],
            "objectGUID": [b"e\xbb\xfe\xb6RTVF\xa3\xc3\x84\xf3\xce\x10;\xc7"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449452075388000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1ep\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"tschingis.aitmatov"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"tschingis.aitmatov@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134007.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Karla Anderson,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Karla Anderson"],
            "sn": [b"Anderson"],
            "givenName": [b"Karla"],
            "distinguishedName": [
                b"CN=Karla Anderson,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134100.0Z"],
            "whenChanged": [b"20191206215635.0Z"],
            "displayName": [b"Karla Anderson"],
            "uSNCreated": [b"488993"],
            "memberOf": [b"CN=anames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"782791"],
            "name": [b"Karla Anderson"],
            "objectGUID": [b"&\x03\x94\xc5\x8d\r8D\xac\x15\xd8{0\xc6\x84/"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449452605164000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eq\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"karla.anderson"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"karla.anderson@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134100.0Z",
                b"16010101000000.0Z",
            ],
            "lastLogonTimestamp": [b"132201429950364000"],
        },
        "CN=Ilse Aichinger,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Ilse Aichinger"],
            "sn": [b"Aichinger"],
            "givenName": [b"Ilse"],
            "distinguishedName": [
                b"CN=Ilse Aichinger,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134201.0Z"],
            "whenChanged": [b"20170719134201.0Z"],
            "displayName": [b"Ilse Aichinger"],
            "uSNCreated": [b"489001"],
            "memberOf": [b"CN=anames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"489007"],
            "name": [b"Ilse Aichinger"],
            "objectGUID": [b"F\xc3'\xd6\xe7\x93QB\xb1w3R\xbdgH\x07"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449453212160000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1er\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"ilse.aichinger"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"ilse.aichinger@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134201.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Marlon Brando,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Marlon Brando"],
            "sn": [b"Brando"],
            "givenName": [b"Marlon"],
            "distinguishedName": [
                b"CN=Marlon Brando,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134227.0Z"],
            "whenChanged": [b"20170719134227.0Z"],
            "displayName": [b"Marlon Brando"],
            "uSNCreated": [b"489009"],
            "memberOf": [b"CN=bnames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"489015"],
            "name": [b"Marlon Brando"],
            "objectGUID": [b"w\x98)\xaf\xaaG+C\xa5\xebt\xd1h\x93y\xc8"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449453474084000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1es\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"marlon.brando"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"marlon.brando@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134227.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Hieronymus Bosch,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Hieronymus Bosch"],
            "sn": [b"Bosch"],
            "givenName": [b"Hieronymus"],
            "distinguishedName": [
                b"CN=Hieronymus Bosch,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134309.0Z"],
            "whenChanged": [b"20170719134310.0Z"],
            "displayName": [b"Hieronymus Bosch"],
            "uSNCreated": [b"489018"],
            "memberOf": [b"CN=bnames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"489025"],
            "name": [b"Hieronymus Bosch"],
            "objectGUID": [
                b"L\xd1\xc4\xc5\xa9\xc1\xf5O\x8a \xfb\x1c\xf0S\x84\xec"
            ],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449453891852000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1et\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"hieronymus.bosch"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"hieronymus.bosch@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134309.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Hildegard Bingen,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Hildegard Bingen"],
            "sn": [b"Bingen"],
            "givenName": [b"Hildegard"],
            "distinguishedName": [
                b"CN=Hildegard Bingen,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134508.0Z"],
            "whenChanged": [b"20170719134508.0Z"],
            "displayName": [b"Hildegard Bingen"],
            "uSNCreated": [b"489027"],
            "memberOf": [
                b"CN=mixednames,OU=groups,DC=hotad,DC=example,DC=net",
                b"CN=bnames,OU=groups,DC=hotad,DC=example,DC=net",
            ],
            "uSNChanged": [b"489033"],
            "name": [b"Hildegard Bingen"],
            "objectGUID": [
                b"\x18\xe7\x8c\xb3\xc8\x8c\xfbA\x836P\x963\xfb2\x19"
            ],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449455085408000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1eu\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"hildegard.bingen"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"hildegard.bingen@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134508.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Georg Büchner,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Georg B\xc3\xbcchner"],
            "sn": [b"B\xc3\xbcchner"],
            "givenName": [b"Georg"],
            "distinguishedName": [
                b"CN=Georg B\xc3\xbcchner,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134600.0Z"],
            "whenChanged": [b"20170719134601.0Z"],
            "displayName": [b"Georg B\xc3\xbcchner"],
            "uSNCreated": [b"489036"],
            "memberOf": [b"CN=bnames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"489043"],
            "name": [b"Georg B\xc3\xbcchner"],
            "objectGUID": [b"\x10q)\xab=\x8f$D\x96\x15$R\x81\x14Rw"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449455601144000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1ev\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"georg.buechner"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"georg.buechner@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134600.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Thomas Bernhard,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Thomas Bernhard"],
            "sn": [b"Bernhard"],
            "givenName": [b"Thomas"],
            "distinguishedName": [
                b"CN=Thomas Bernhard,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134644.0Z"],
            "whenChanged": [b"20170719134644.0Z"],
            "displayName": [b"Thomas Bernhard"],
            "uSNCreated": [b"489045"],
            "memberOf": [b"CN=bnames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"489051"],
            "name": [b"Thomas Bernhard"],
            "objectGUID": [b"\xd7D\t\x86\xb1|\xe5L\x98a\x9f\xb9\x84E\x8c\xa0"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449456045744000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1ew\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"thomas.bernhard"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"thomas.bernhard@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134644.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Tracy Chapman,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Tracy Chapman"],
            "sn": [b"Chapman"],
            "givenName": [b"Tracy"],
            "distinguishedName": [
                b"CN=Tracy Chapman,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134724.0Z"],
            "whenChanged": [b"20170719134724.0Z"],
            "displayName": [b"Tracy Chapman"],
            "uSNCreated": [b"489053"],
            "memberOf": [b"CN=cnames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"489059"],
            "name": [b"Tracy Chapman"],
            "objectGUID": [b"\x1a\xf8P\x83\xac\x8c\x8fD\x94Id/V\xb8`\xdd"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449456447756000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1ex\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"tracy.chapman"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"tracy.chapman@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134724.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Leonard Cohen,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Leonard Cohen"],
            "sn": [b"Cohen"],
            "givenName": [b"Leonard"],
            "distinguishedName": [
                b"CN=Leonard Cohen,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719134922.0Z"],
            "whenChanged": [b"20170719134922.0Z"],
            "displayName": [b"Leonard Cohen"],
            "uSNCreated": [b"489061"],
            "memberOf": [b"CN=cnames,OU=groups,DC=hotad,DC=example,DC=net"],
            "uSNChanged": [b"489067"],
            "name": [b"Leonard Cohen"],
            "objectGUID": [b"\x8c\x90D\x9aX\xae_@\xbei\x82\xe2-\x84\xdb\xe7"],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449457620096000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1ey\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"leonard.cohen"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"leonard.cohen@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719134922.0Z",
                b"16010101000000.0Z",
            ],
        },
        "CN=Charlie Chaplin,OU=people,DC=hotad,DC=example,DC=net": {
            "objectClass": [
                b"top",
                b"person",
                b"organizationalPerson",
                b"user",
            ],
            "cn": [b"Charlie Chaplin"],
            "sn": [b"Chaplin"],
            "givenName": [b"Charlie"],
            "distinguishedName": [
                b"CN=Charlie Chaplin,OU=people,DC=hotad,DC=example,DC=net"
            ],
            "instanceType": [b"4"],
            "whenCreated": [b"20170719135025.0Z"],
            "whenChanged": [b"20170719135025.0Z"],
            "displayName": [b"Charlie Chaplin"],
            "uSNCreated": [b"489069"],
            "memberOf": [
                b"CN=mixednames,OU=groups,DC=hotad,DC=example,DC=net",
                b"CN=cnames,OU=groups,DC=hotad,DC=example,DC=net",
            ],
            "uSNChanged": [b"489075"],
            "name": [b"Charlie Chaplin"],
            "objectGUID": [
                b"\xa4\xeb\xf8\xf6\x1c\x94\xb3@\x96\xe0H\x97A.\xa0\xf2"
            ],
            "userAccountControl": [b"66048"],
            "badPwdCount": [b"0"],
            "codePage": [b"0"],
            "countryCode": [b"0"],
            "badPasswordTime": [b"0"],
            "lastLogoff": [b"0"],
            "lastLogon": [b"0"],
            "pwdLastSet": [b"131449458258136000"],
            "primaryGroupID": [b"513"],
            "objectSid": [
                b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00Tw)\xc9xdQ\xfeA\xde\xb1ez\x04\x00\x00"
            ],
            "accountExpires": [b"9223372036854775807"],
            "logonCount": [b"0"],
            "sAMAccountName": [b"charlie.chaplin"],
            "sAMAccountType": [b"805306368"],
            "userPrincipalName": [b"charlie.chaplin@hotad.example.net"],
            "objectCategory": [
                b"CN=Person,CN=Schema,CN=Configuration,DC=hotad,DC=example,DC=net"
            ],
            "dSCorePropagationData": [
                b"20170719135025.0Z",
                b"16010101000000.0Z",
            ],
        },
    }
    # add a userPassword and create tuples from the dict,
    # which are required for the mockldap config
    return _ad_entries


@pytest.fixture(autouse=True)
def ad_user(ad_entries):
    _ad_user = []
    for dn, info in ad_entries.items():
        if "objectClass" in info and b"user" in info["objectClass"]:
            info["userPassword"] = ["Test123!"]
        _ad_user.append((dn, info))
    return _ad_user


@pytest.fixture
@pytest.mark.usefixtures("extendMockLdap")
def mock_ldap(ad_user):
    """
    Provide a mock ldap instance configured with our test data
    """

    ad_test_config = dict([*ad_user])

    with MockLdap(ad_test_config) as mockldap:
        yield mockldap


@pytest.mark.usefixtures("app")
class TestLDAPResolver(TestController):
    def define_ldap_resolver(
        self,
        name,
        base_dn="OU=people,DC=hotad,DC=example,DC=net",
        manager_dn="CN=Clark Maxwell,OU=corp,DC=hotad,DC=example,DC=net",
        ldap_uri="ldap://localhost/",
        params=None,
        ad_entries=None,
    ):
        """"""

        u_map = {
            "username": "sAMAccountName",
            "phone": "telephoneNumber",
            "mobile": "mobile",
            "email": "mail",
            "surname": "sn",
            "givenname": "givenName",
        }

        iparams = {
            "name": name,
            "BINDDN": manager_dn,
            "BINDPW": ad_entries[manager_dn]["userPassword"],
            "LDAPBASE": base_dn,
            "LDAPURI": ldap_uri,
            "CACERTIFICATE": "",
            "LOGINNAMEATTRIBUTE": "sAMAccountName",
            # 'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
            "LDAPSEARCHFILTER": "(sAMAccountName=*)",
            # 'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
            "LDAPFILTER": "(sAMAccountName=%s)",
            "UIDTYPE": "dn",
            "USERINFO": json.dumps(u_map),
            "TIMEOUT": "5",
            "SIZELIMIT": "500",
            "NOREFERRALS": "True",
            "type": "ldapresolver",
            "EnforceTLS": "True",
        }

        if params:
            iparams.update(params)

        response = self.make_system_request("setResolver", params=iparams)
        assert response.json["result"]["value"]

        return response, iparams

    @pytest.fixture
    def ldap_realm_test(self, mock_ldap, ad_entries):
        """
        Fixture to provide a test LDAP resolver in realm 'test'
        """
        # define the resolver 'test'

        resolver_name = "test"
        realm_name = "test"

        # define the realm 'test'
        resolver_base = "useridresolver.LDAPIdResolver.IdResolver."
        resolver_list = [resolver_base + resolver_name]

        (response, _params) = self.define_ldap_resolver(
            resolver_name, ad_entries=ad_entries
        )
        assert '"value": true' in response

        response = self.create_realm(realm_name, resolver_list)
        assert '"value": true' in response

    @pytest.fixture
    def ldap_realm_corp(self, mock_ldap, ad_entries):
        """
        Fixture to provide a test LDAP resolver in realm 'corp'
        with the uidType: objectGUID
        """
        # define the resolver 'test'

        resolver_name = "corp"
        realm_name = "corp"

        manager_dn = "CN=Clark Maxwell,OU=corp,DC=hotad,DC=example,DC=net"
        base_dn = "OU=corp,DC=hotad,DC=example,DC=net"

        (response, _params) = self.define_ldap_resolver(
            resolver_name,
            manager_dn=manager_dn,
            base_dn=base_dn,
            params={"UIDTYPE": "objectGUID"},
            ad_entries=ad_entries,
        )
        assert '"value": true' in response

        # define the realm 'test'
        resolver_base = "useridresolver.LDAPIdResolver.IdResolver."
        resolver_list = [resolver_base + resolver_name]

        response = self.create_realm(realm_name, resolver_list)
        assert '"value": true' in response

    @pytest.mark.usefixtures("ldap_realm_test")
    def test_ldap_dn(self):
        """search in ldapresolver pointing to ad with uid type: dn"""

        realm = "test"
        user = "charlie.chaplin"

        params = {"realm": realm}
        response = self.make_admin_request("userlist", params=params)

        usernames = [u["username"] for u in response.json["result"]["value"]]

        assert user in usernames
        assert len(usernames) == 13

        params = {
            "user": user,
            "type": "pw",
            "otpkey": "geheim1",
            "realm": realm,
        }

        response = self.make_admin_request("init", params=params)
        assert "detail" in response

        params = {
            "name": "pin_policy",
            "scope": "authentication",
            "active": True,
            "client": "*",
            "realm": "*",
            "user": "*",
            "action": "otppin=password",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response

        params = {"user": user, "realm": realm, "pass": "Test123!geheim1"}
        response = self.make_validate_request("check", params=params)
        assert "false" not in response

        return

    @pytest.mark.usefixtures("ldap_realm_corp")
    def test_ldap_objectGUID(self):
        """search in ldapresolver pointing to ad with uid type: objectGUID"""

        realm = "corp"
        user = "maxwell"

        params = {"realm": realm}
        response = self.make_admin_request("userlist", params=params)

        usernames = [u["username"] for u in response.json["result"]["value"]]

        assert user in usernames
        assert len(usernames) == 4

        params = {
            "user": user,
            "type": "pw",
            "otpkey": "geheim1",
            "realm": realm,
        }
        response = self.make_admin_request("init", params=params)
        assert "detail" in response

        params = {
            "name": "pin_policy",
            "scope": "authentication",
            "active": True,
            "client": "*",
            "realm": "*",
            "user": "*",
            "action": "otppin=password",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response

        params = {"user": user, "realm": realm, "pass": "Test123!geheim1"}
        response = self.make_validate_request("check", params=params)
        assert "false" not in response

        return
