#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010-2019 KeyIdentity GmbH
#
#   This file is part of LinOTP userid resolvers.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU Affero General Public
#   License, version 3, as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the
#              GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#   E-mail: info@linotp.de
#   Contact: www.linotp.org
#   Support: www.linotp.de

"""
SQL Resolver unit test - test passwords formats
"""

import pytest
from passlib.context import CryptContext
from passlib.exc import MissingBackendError
from passlib.hash import atlassian_pbkdf2_sha1

from linotp.useridresolver.SQLIdResolver import check_password


class TestSQLResolver_Password:
    def test_pbkdf2_password(self):
        brahms_hashed_pw = (
            "{PKCS5S2}TGF1K1olIoY5a4HHy89R+LcT8E/V5P+"
            "u92L0ClePbhzqWikJUGmS0lyHSibsj4th=="
        )

        brahms_pw = "brahms123"

        res = atlassian_pbkdf2_sha1.verify(brahms_pw, brahms_hashed_pw)
        assert res

        res = check_password(brahms_pw, brahms_hashed_pw)
        assert res

        wrong_brahms_hashed_pw = brahms_hashed_pw.replace("PKCS5S2", "OKCS5S2")
        res = check_password(brahms_pw, wrong_brahms_hashed_pw)
        assert not res

        wrong_brahms_hashed_pw = brahms_hashed_pw.replace("+", "-")
        res = check_password(brahms_pw, wrong_brahms_hashed_pw)
        assert not res

        wrong_brahms_hashed_pw = brahms_hashed_pw.replace("G", "Q")
        res = check_password(brahms_pw, wrong_brahms_hashed_pw)
        assert not res

    def test_bcrypt_password(self):
        """check the bcrypt password verification method"""

        password = "password"
        password_hash = "$2a$12$NT0I31Sa7ihGEWpka9ASYeEFkhuTNeBQ2xfZskIiiJeyFXhRgS.Sy"
        res = check_password(password, password_hash)
        assert res

        wrong_password_hash = password_hash.replace("h", "t")

        res = check_password(password, wrong_password_hash)
        assert not res

        wrong_password = password + "!"

        res = check_password(wrong_password, password_hash)
        assert not res

    def test_bcrypt_password_no_bcrypt(self, monkeypatch):
        """Deal with a missing bcrypt backend."""

        def mock_verify(pwd, crypted_pwd):
            msg = (
                "bcrypt: no backends available -- recommend you install one "
                "(e.g., 'pip install bcrypt')"
            )
            raise MissingBackendError(msg)

        context = CryptContext(schemes=["bcrypt"])
        monkeypatch.setattr(context, "verify", mock_verify)
        with pytest.raises(MissingBackendError) as excinfo:
            context.verify("foo", "bar")
        assert "bcrypt: no backends available" in str(excinfo.value)

    def test_php_passwords(self):
        """check the php password verification method"""

        password = "password"
        password_hash = "$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1"

        res = check_password(password, password_hash)
        assert res

        wrong_password_hash = password_hash.replace("U", "Z")

        res = check_password(password, wrong_password_hash)
        assert not res

        wrong_password = password + "!"

        res = check_password(wrong_password, password_hash)
        assert not res

    @pytest.mark.parametrize(
        "hash_type,expected,pwd,crypted_pwd",
        [
            (
                "ldap_sha1",
                True,
                "password",
                "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=",
            ),
            (
                "ldap_salted_sha1",
                True,
                "password",
                "{SSHA}0CvY/gQbyB0UM/zwwup0XYz+JTTVujcm",
            ),
            (
                "ldap_sha1_crypt",
                True,
                "password",
                "{CRYPT}$sha1$480000$WpQDC2ME$cYbwgZIuo8KzOk/cpEGX5rgzmT9o",
            ),
            (
                "ldap_sha256_crypt",
                True,
                "password",
                "{CRYPT}$5$rounds=535000$3x7dgjrjlxwPQ0UQ$KZQwDCX/t5vp0R71Vsy"
                "4l0ZzbLssORlAJlxvbNin9v9",
            ),
            (
                "ldap_sha512_crypt",
                True,
                "password",
                "{CRYPT}$6$rounds=656000$HN0Ia6arOe9FupFq$eqYig8QZiVa9wvGzDvnpmcJe"
                "7aTiWc05OQ0B5gYswoD7xOY8z9ypdAW4LsNMxNb5cjOIECaUWD/KFa/Ri69ee/",
            ),
            (
                "ldap_bcrypt",
                True,
                "password",
                "{CRYPT}$2b$12$x2RXheO87fHLqPz4XH8Pg.x3vniptX1APpRuM5tDqFUcBdTGCx.bu",
            ),
            ("ldap_des_crypt", True, "password", "{CRYPT}k18nM0E6BizDk"),
            (
                "ldap_bsdi_crypt",
                True,
                "password",
                "{CRYPT}_7C/.EzMY7IITy53/69c",
            ),
            (
                "ldap_md5_crypt",
                True,
                "password",
                "{CRYPT}$1$15ynznR7$Vzam.Gnb8uCZeXaFgP7a31",
            ),
            ("ldap_md5", True, "password", "{MD5}X03MO1qnZdYdgyfeuILPmQ=="),
            (
                "ldap_salted_md5",
                True,
                "password",
                "{SMD5}AA6H4iinM9uj0MfCh8Rf0XfOOQc=",
            ),
            (
                "atlassian_pbkdf2_sha1",
                True,
                "password",
                "{PKCS5S2}1BqDsHYuRQih1Nq7dy7lvAVd5kCkYipNw1yRBSHKqTIM8zrn"
                "vwlPvTntxnQ4cTll",
            ),
            (
                "fshp",
                True,
                "password",
                "{FSHP1|16|480000}A8CYszamVOp9T6nV2vu/VyeO5MoWP3zEKIeF8YnE7"
                "eVPPQi4Zdd1DcUL/dS35q9z",
            ),
            (
                "md5_crypt",
                True,
                "password",
                "$1$4wC5ifi5$mCsGdDRXA9GftMo8zK7Ao0",
            ),
            (
                "bcrypt",
                True,
                "password",
                "$2b$12$F3Lzt92wW0xwgSCX31kiv.Yhfv808nertv33dZJ0vCQCoHSlKpT1S",
            ),
            (
                "bsd_nthash",
                True,
                "password",
                "$3$$8846f7eaee8fb117ad06bdd830b7586c",
            ),
            (
                "sha512_crypt",
                True,
                "password",
                "$6$rounds=656000$jiP2BX3wbH1d7GA5$9ANxldzE7PnVoQvNaFBPOZfkUf"
                "v1rmS7ljWrJG/1YBM2IGy6f2LfiKp/oGeaxZMemcfJYYIPi3xnxDmz7FjJX0",
            ),
            (
                "sha256_crypt",
                True,
                "password",
                "$5$rounds=535000$4FyrTfhAB1QhxSs1$GxEb8g889FFBbI.lhdQEBRSOp1"
                "AXHAoDFqebk3poIr5",
            ),
            (
                "sha1_crypt",
                True,
                "password",
                "$sha1$480000$wP/cZJse$y8mc3U7SMCKiyAMxFFwCZ0psX4BC",
            ),
            (
                "sun_md5_crypt",
                True,
                "password",
                "$md5,rounds=34000$l6o46MsZ$$zq2aAM1Wn4bRIQEL6xNwz0",
            ),
            (
                "bcrypt_sha256",
                True,
                "password",
                "$bcrypt-sha256$2b,12$FPVB0Puo23LR1aZdcIOLze$Ai34tXDFEx/y0pUqS"
                "r4zy/tTYFnTTiS",
            ),
            ("phpass", True, "password", "$P$HeGb4QI3zNxoRDpPyvcLD0wck/en9t0"),
            (
                "mssql2000",
                True,
                "password",
                "0x0100A114E25C6B1D75175D2EC07EEE264855F8574D5CD69BDACFD80BF51E"
                "E1BA4234771DB10F17D577D070FC6CDE",
            ),
            (
                "mssql2005",
                True,
                "password",
                "0x0100BAB7B6D62CAF7D399E11AD25FCE53D513AD6514AE302FCC3",
            ),
            ("mysql323", True, "password", "5d2e19393cc5ef67"),
            (
                "mysql41",
                True,
                "password",
                "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
            ),
            (
                "oracle11",
                True,
                "password",
                "S:9E9B8C72DD594EAF6AEF698BCCB2DE02E45028BBBDC16DDCFD5DDC3E1F43",
            ),
            ("des_crypt", True, "password", "l6m8HD0UETxVo"),
            ("bsdi_crypt", True, "password", "_7C/.Nohv0hv.CWzNzq."),
            ("bigcrypt", True, "password", "p6cUugZyGjvRM"),
        ],
    )
    def test_supported_passwords(self, hash_type, expected, pwd, crypted_pwd):
        assert expected == check_password(pwd, crypted_pwd)
