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


from datetime import datetime

from linotp.model.schema import ReportingSchema


class Reporting(ReportingSchema):
    def __init__(
        self,
        event: str,
        realm: str,
        parameter: str = "",
        value: str = "",
        count: int = 0,
        detail: str = "",
        session: str = "",
        description: str = "",
        timestamp: str | None = None,
    ):
        super().__init__(
            event=str(event),
            realm=str(realm),
            parameter=str(parameter),
            value=str(value),
            count=count,
            detail=str(detail),
            session=str(session),
            description=str(description),
            timestamp=datetime.now() if timestamp is None else timestamp,
        )

    def get_vars(self) -> dict:
        ret: dict = {}

        ret["timestamp"] = str(self.timestamp)
        ret["event"] = self.event
        ret["realm"] = self.realm
        ret["parameter"] = self.parameter
        ret["value"] = self.value
        ret["count"] = self.count
        ret["detail"] = self.detail
        ret["session"] = self.session
        ret["description"] = self.description

        return ret
