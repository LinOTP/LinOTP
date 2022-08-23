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


from flask_jwt_extended import *
from flask_jwt_extended import __version__

if __version__.startswith("4."):
    # We're good
    pass
elif __version__.startswith("3."):
    from importlib import import_module

    module = import_module("flask_jwt_extended")

    def verify_jwt_in_request(optional=False, *args, **kwargs):
        if optional:
            return getattr(module, "verify_jwt_in_request_optional")(
                *args, **kwargs
            )
        else:
            return getattr(module, "verify_jwt_in_request")(*args, **kwargs)

    JWTManager.token_in_blocklist_loader = JWTManager.token_in_blacklist_loader
    get_jwt = get_raw_jwt
else:
    raise ImportError("Your flask_jwt_extended is too old (or too new)")
