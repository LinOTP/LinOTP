# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP smsprovider.
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

import os
from unittest import TestCase

from mock import patch

from linotp.provider.emailprovider import EMAIL_PROVIDER_TEMPLATE_KEY
from linotp.provider.emailprovider import SMTPEmailProvider as EMailProvider

TEMPLATE_MESSAGE = """Content-Type: multipart/alternative;
 boundary="===============3294676191386143061=="
MIME-Version: 1.0
Subject: ${Subject}
From: ${From}
To: ${To}

This is a multi-part alternative message in MIME format.
--===============3294676191386143061==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

Your requested OTP is ${otp}.
--===============3294676191386143061==
Content-Type: multipart/related;
 boundary="===============3984710301122897564=="
MIME-Version: 1.0

--===============3984710301122897564==
Content-Type: text/html; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

<html>

<body>
    <div align='center' height='100%'>
        <table width='40%' cellpadding='20px' bgcolor="#f1f2f5">
            <thead>
                <tr>
                    <th align='center'><img src="cid:image1"></th>
                </tr>
                <tr>
                    <th align='center'>Your requested OTP is</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td align='center'>${otp}</td>
                </tr>
                <tr>
                    <td align='right'><i>Happy authenticating</i></td>
                </tr>
            </tbody>
        </table>
    </div>
</body>

</html>

--===============3984710301122897564==
Content-Type: image/png
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-ID: <image1>

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
Oqava1sNK9ktL/Yp7PY2RG5dvLs4cTkmvz8ZZsmjhYKorq1KWj5fsqxjwIsGfg7sKFrWSSPiLa+O
iOoay7LG9zdPxQ3DU3CzG1ayitxQx8YulddhYNXlUcibP5lL9/rhZwZS9rUqEp/i4UXu0tq26F1U
v78kk/vTgu1caVw1nZKDDaY/lRfllcscM/Uab9g1R8/3BX43Pa38nnx2eKK8SfzGPCKq94vqm9OG
h6rbRfWOJfn87xZsP1cDqYEp863nJ3RqnRw3YZoR7t8rPgUM1lSyEdGAMS9bql+eMZBX3QvgM+Yh
YKuAKoxZj58rofqNeUbgr64Ax1A9VBVivepTvd0t/KuWI4rJmgRARyJf3JeydxbhZb9ql4G7VOQW
haBbU34ZkVcUzkarPj/VydxiPtUn3OflgJpG26/axzke/ApHGjEVblXzceB7OEmn71L3Q/9P5513
blfvYg5vaaOePax4+3qeud64mTz54Az9FxJp1LuuXo3c++HDSTqrnKTTWznoYxbNdHQ4SecmJ+m8
6CSdwJWMk//vyPX8C+ubwBpgfeWznp9yjXYWFwnXwQWBe4D7gb8BjyXiiZOVfnGSzknK9VffLGUX
DMt11kPAK5S/Dn2QiCeKXgf4X0iH4OfyrFVlAAAAAElFTkSuQmCC
--===============3984710301122897564==--

--===============3294676191386143061==--
"""


mocked_context = {"Config": {EMAIL_PROVIDER_TEMPLATE_KEY: os.path.dirname(__file__)}}


class TestEMailTemplate(TestCase):
    """
    test the processing of email templates

    the main subject are the following static methods:

        render_simple_message
        render_template_message

    """

    def test_legacy_email_messages(self):
        """
        verify that the former email substitutions <otp> <serial> still works
        """

        email_from = "me@home.org"
        email_to = "you@home.org"

        subject = "<otp> subject"
        message = "Hello <otp>"

        otp = "123 456"

        replacements = {"otp": otp, "serial": "LEMT_12345"}

        response = EMailProvider.render_simple_message(
            email_to, email_from, subject, message, replacements
        )

        # verify that the otp is appended to the message without <otp>

        assert response

        # depending of the input of the rendering the response could be
        # of type bytes or python str - thus we convert to assure to
        # recieve a python str
        if not isinstance(response, str):
            response = response.decode("utf-8")

        assert otp in response
        assert otp + " subject" in response
        assert "Hello " + otp in response

        message = "no otp in message"

        response = EMailProvider.render_simple_message(
            email_to, email_from, subject, message, replacements
        )

        assert message + otp in response

        # verify that multiple <otp> are replaced

        message = "<otp> double <otp>"

        response = EMailProvider.render_simple_message(
            email_to, email_from, subject, message, replacements
        )

        assert otp + " double " + otp in response

    def test_email_templates(self):
        """
        verify that vars in an email template will be substituted
        """

        email_from = "me@home.org"
        email_to = "you@home.org"

        subject = "${otp} subject"
        template_message = TEMPLATE_MESSAGE

        otp = "123 456"

        replacements = {"otp": otp, "serial": "LEMT_12345"}

        response = EMailProvider.render_template_message(
            email_to, email_from, subject, template_message, replacements
        )

        assert response

        # depending of the input of the rendering the response could be
        # of type bytes or python str - thus we convert to assure to
        # recieve a python str
        if not isinstance(response, str):
            response = response.decode("utf-8")

        assert "Your requested OTP is " + otp in response
        assert "<td align='center'>" + otp in response
        assert "Subject: " + otp + " subject" in response

    def test_email_templates_unknown(self):
        """
        verify that unknown vars in an email template wont break
        """

        email_from = "me@home.org"
        email_to = "you@home.org"

        subject = "${otp} subject"
        template_message = TEMPLATE_MESSAGE.replace("${otp}", "${otp} ${var}")

        otp = "123 456"

        replacements = {"otp": otp, "serial": "LEMT_12345"}

        response = EMailProvider.render_template_message(
            email_to, email_from, subject, template_message, replacements
        )

        assert response

        # depending of the input of the rendering the response could be
        # of type bytes or python str - thus we convert to assure to
        # recieve a python str
        if not isinstance(response, str):
            response = response.decode("utf-8")

        assert "Your requested OTP is " + otp + " ${var}" in response
        assert "<td align='center'>" + otp + " ${var}" in response
        assert "Subject: " + otp + " subject" in response

    @patch("linotp.provider.emailprovider.request_context", new=mocked_context)
    def test_load_file_template(self):
        """test secure template file loding - not allowed below the templ root"""

        email_from = "me@home.org"
        email_to = "you@home.org"

        subject = "${otp} subject"

        otp = "123 456"

        replacements = {"otp": otp, "serial": "LEMT_12345"}

        # ------------------------------------------------------------------ --

        # now get the fixture directory which contains our email.eml template

        fixture_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "..",
                "functional",
                "fixtures",
            )
        )

        global mocked_context
        mocked_context["Config"][EMAIL_PROVIDER_TEMPLATE_KEY] = fixture_path

        # ------------------------------------------------------------------ --

        # lets render the template, which is found in the fixture directory

        template_message = "file://email.eml"

        response = EMailProvider.render_template_message(
            email_to, email_from, subject, template_message, replacements
        )

        assert response

        # depending of the input of the rendering the response could be
        # of type bytes or python str - thus we convert to assure to
        # recieve a python str
        if not isinstance(response, str):
            response = response.decode("utf-8")

        assert "Subject: " + otp + " subject" in response

        # ------------------------------------------------------------------ --

        # try to access a file below the defined template root directory

        template_message = "file://../__init__.py"

        with self.assertRaises(Exception) as exx:
            response = EMailProvider.render_template_message(
                email_to, email_from, subject, template_message, replacements
            )

        ex_msg = "%r" % exx.exception
        assert "not in email provider template root" in ex_msg


# eof
