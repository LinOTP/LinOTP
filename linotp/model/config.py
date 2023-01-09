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


from typing import Any

from linotp.model import db
from linotp.model.schema import ConfigSchema


class Config(ConfigSchema):
    def __init__(
        self,
        Key: str,
        Value: str,
        *args: Any,
        **kwargs: Any,
    ):
        if not Key.startswith("linotp.") and not Key.startswith("enclinotp."):
            Key = "linotp." + Key
        super().__init__(Key=Key, Value=Value, **kwargs)

    def __str__(self) -> str:
        return self.Description


# The following used to be in `linotp/defaults.py`, but we want to avoid
# issues with circular `import` dependencies.


def set_config(
    key: str,
    value: str,
    typ: str,
    description: str = None,
    update: bool = False,
) -> None:
    """
    create an intial config entry, if it does not exist

    :param key: the key
    :param value: the value
    :param description: the description of the key

    :return: nothing
    """
    count = Config.query.filter_by(Key="linotp." + key).count()
    if count == 0:
        config_entry = Config(key, value, Type=typ, Description=description)
        db.session.add(config_entry)

    elif update:
        config_entry = Config.query.filter_by(Key="linotp." + key).first()

        if not key.startswith("linotp."):
            key = "linotp." + key

        config_entry.Key = key
        config_entry.Value = value
        config_entry.Type = typ

        if description:
            config_entry.Description = description

        db.session.add(config_entry)
