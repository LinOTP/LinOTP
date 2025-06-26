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
sql user db helper
"""

import json
import logging

import sqlalchemy
from sqlalchemy.engine import create_engine

log = logging.getLogger(__name__)


class SqlUserDB:
    def __init__(self, connect="sqlite://", table_name="User2"):
        self.tableName = table_name
        self.usercol = '"user"'
        self.userTable = f'"{self.tableName}"'

        self.connection = None
        try:
            self.engine = create_engine(connect)
            self.sqlurl = self.engine.url
            if self.sqlurl.drivername.startswith("mysql"):
                self.userTable = f"{self.sqlurl.database}.{self.tableName}"
                self.usercol = "user"

        except Exception as e:
            print(f"{e!r}")
            raise e

        umap = {
            "userid": "id",
            "username": "user",
            "phone": "telephonenumber",
            "mobile": "mobile",
            "email": "mail",
            "surname": "sn",
            "givenname": "givenname",
            "password": "password",
        }

        self.resolverDef = {
            "Table": self.tableName,
            "Map": json.dumps(umap),
        }

        self.sql_params = {
            self.usercol: "text",
            "telephonenumber": "text",
            "mobile": "text",
            "sn": "text",
            "givenname": "text",
            "password": "text",
            "id": "text",
            "mail": "text",
        }

        # extend the dict with userid resolver attributes from the connect
        conn_dict = self._parse_connection(connect)
        self.resolverDef.update(conn_dict)

        return

    def _parse_connection(self, connect):
        """
        analyse the sql connection string and transform this to a dict
        that can be used as an input for an sqluserid resolver

         connect = postgresql://otpd:linotp2d@localhost/otpdb # gitleaks:allow

        """

        dbdrive_port, _sep, rest = connect.partition("//")
        dbdrive, _sep, port = dbdrive_port.partition(":")
        user_pass, _sep, host_db = rest.partition("@")
        user, _sep, passw = user_pass.partition(":")
        host, _sep, db = host_db.partition("/")

        conn = {
            "Database": db,
            "Driver": dbdrive,
            "Server": host,
            "User": user,
            "Password": passw,
            "type": "sqlresolver",
        }
        if port:
            conn["Port"] = port
        return conn

    def getResolverDefinition(self):
        return self.resolverDef

    def createTable(self, params=None):
        if isinstance(params, dict):
            self.sql_params.update(params)

        create_key_value = []

        for key, value in list(self.sql_params.items()):
            create_key_value.append(f"{key} {value}")

        createStr = "CREATE TABLE {} ( {} )".format(
            self.userTable,
            ", ".join(create_key_value),
        )

        t = sqlalchemy.sql.expression.text(createStr)
        with self.engine.begin() as conn:
            conn.execute(t)

        return

    def dropTable(self):
        dropStr = f"DROP TABLE {self.userTable}"
        t = sqlalchemy.sql.expression.text(dropStr)
        with self.engine.begin() as conn:
            conn.execute(t)

    def addUser(
        self, user, telephonenumber, mobile, sn, givenname, password, uid, mail
    ):
        intoStr = f"""
            INSERT INTO {self.userTable}( {self.usercol}, telephonenumber, mobile,
            sn, givenname, password, id, mail)
            VALUES (:user, :telephonenumber, :mobile, :sn, :givenname,
                    :password, :id, :mail)
            """
        t = sqlalchemy.sql.expression.text(intoStr)

        with self.engine.begin() as conn:
            conn.execute(
                t,
                {
                    "user": user,
                    "telephonenumber": telephonenumber,
                    "mobile": mobile,
                    "sn": sn,
                    "givenname": givenname,
                    "password": password,
                    "id": uid,
                    "mail": mail,
                },
            )

        # execute(sqlalchemy.sql.expression.text("""SELECT COUNT(*)
        # FROM Config WHERE Config.Key = :key"""), key=REPLICATION_CONFIG_KEY)

    def query(self):
        selectStr = f"select * from {self.userTable}"
        with self.engine.begin() as conn:
            result = conn.execute(selectStr)

        res = list(result)
        return res

    def delUsers(self, uid=None, username=None):
        if username is not None:
            delStr = f"DELETE FROM {self.userTable}  WHERE user=:user"
            t = sqlalchemy.sql.expression.text(delStr)
            with self.engine.begin() as conn:
                conn.execute(t, {"user": username})

        elif type(uid) in (str, ""):
            delStr = f"DELETE FROM {self.userTable}  WHERE id=:id"
            t = sqlalchemy.sql.expression.text(delStr)
            with self.engine.begin() as conn:
                conn.execute(t, {"id": uid})

        elif uid is None:
            delStr = f"DELETE FROM {self.userTable}"
            t = sqlalchemy.sql.expression.text(delStr)
            with self.engine.begin() as conn:
                conn.execute(t)
