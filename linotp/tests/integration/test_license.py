#
# -*- coding: utf-8 -*-
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


EXPIRED_LICENSE = """-----BEGIN LICENSE-----
comment=License for LSE LinOTP 2
contact-email=hs@unknown/unbekannt
licensee=Testkunde
expire=2018-11-19
contact-phone=unknown/unbekannt
address=unknown/unbekannt
date=2018-11-19
user-num=4
subscription=2018-11-19
contact-name=unknown/unbekannt
version=2
issuer=LSE Leading Security Experts GmbH
-----END LICENSE-----
-----BEGIN LICENSE SIGNATURE-----
lgNY1u/Y96WG7DVfuid/rdCDBPX99RgcWml+YU1JJdDudSYKheKitoWcoFVp+4YV5FqdfkfESzcJwYoF2588q+RUfky2g/FmE0XM+YBhRsc/SW9Xp199yHMnIBbvx3zBGomZxizKb5/nCwKvQaOGIAdzvmg+MHWqk+rE0HuZU0xXZQRhxPlDcGeeMvBI+X207WlUKQk4fI4yO5lb4FBr4pixjYlSq/1k88NKI48FHADwkoeq7xC6Pw8LLTjO9wYEYeh+JhI0R0xPPPfLCiqgPtZA9lYbICgJXhLwQClB6qYe3C5i9+ePuKqNOC1NDDulOhiv4RfpfxkXXjhky2DIGA==
-----END LICENSE SIGNATURE-----
"""

import pytest
from linotp_selenium_helper.license_import import (
    FileUploadException,
    LicenseImport,
    LicenseTempFile,
)


def test_expired_license(testcase):
    """Verify that an expired license will pop up an alert box.

    we are using an expired licence as string value which is loaded
    into a tempfile
    """

    with LicenseTempFile(EXPIRED_LICENSE, suffix=".pem") as temp_file:
        license_import = LicenseImport(testcase.manage_ui)

        with pytest.raises(FileUploadException) as lic_exx:
            license_import.import_file(temp_file.name)

        error_message = lic_exx.value.args[0]
        msg = "The upload of your support and subscription license failed"
        assert msg in error_message
        assert "2018-11-19" in error_message
