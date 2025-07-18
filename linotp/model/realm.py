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

from linotp.model import db
from linotp.model.schema import RealmSchema


class Realm(RealmSchema):
    def __init__(self, realm: str):
        super().__init__()
        self.name = realm
        if realm is not None:
            self.name = realm.lower()
        # self.id     = 0

    def storeRealm(self) -> bool:
        if self.name is None:
            self.name = ""
        self.name = self.name.lower()

        db.session.add(self)
        db.session.flush()

        return True
