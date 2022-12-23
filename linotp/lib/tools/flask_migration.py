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

"""
This module helps decouple LinOTP functions from specific versions
of flask_jwt_extended (v3 / v4)
It basically loads different modules/functions based on the installed 
version.

Note for developers: The way it works is as follows:
The using code assumes flask_jwt_extended v.4 code.

from flask_migration import TestResponse

Later when we move to completely drop flask-jwt-extended v3 usage,
one can replace all the code above with
from flask import TestResponse

"""

from importlib import import_module

from flask import __version__ as FLASK_VERSION

if FLASK_VERSION.startswith("1."):
    flaskmodule = import_module("flask")
    TestResponse = getattr(flaskmodule, "Response")
elif FLASK_VERSION.startswith("2."):
    werkzeugmodule = import_module("werkzeug.test")
    TestResponse = getattr(werkzeugmodule, "TestResponse")
else:
    raise ImportError(
        "flask_migration is based on either flask 1 or 2"
        "If you see this error, you need to reconsider the migration"
        "or install the correct library"
    )
