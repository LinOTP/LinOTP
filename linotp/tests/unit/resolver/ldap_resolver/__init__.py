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


class Bindresult(object):
    def __init__(self, uid_type):
        self.uid_type = uid_type
        self._filter_str = None

    def search_ext(
        self,
        base,
        scope_subtree,
        filterstr=None,
        sizelimit=None,
        attrlist=None,
        timeout=None,
    ):

        if attrlist:
            for attr in attrlist:

                # invalid utf-8 will raise an exception
                attr.encode("utf-8")

        # invalid utf-8 will raise an exception
        filterstr.encode("utf-8")

        self._filter_str = filterstr
        return True

    def result(self, l_id, all=1):
        return [
            [],
            [
                (
                    "cn=Wolfgang Amadeus Mözart,ou=people,dc=blackdog,"
                    "dc=corp,dc=lsexperts,dc=de",
                    {
                        self.uid_type: [
                            "f4450c88-1df9-1033-90e8-Wolfgang Amadeus Mözart"
                        ]
                    },
                )
            ],
        ]
