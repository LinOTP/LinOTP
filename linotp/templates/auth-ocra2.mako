# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010-2019 KeyIdentity GmbH
 *   Copyright (C) 2019-     netgo software GmbH
 *
 *   This file is part of LinOTP server.
 *
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Affero General Public
 *   License, version 3, as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the
 *              GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *    E-mail: info@linotp.de
 *    Contact: www.linotp.org
 *    Support: www.linotp.de
 *
</%doc>

<%block name="title">
<title>LinOTP OCRA2 Auth testing</title>
</%block>

<%inherit file="auth-base.mako"/>

<div id="sidebar">
<p>
${_("Here you may try to authenticate using your OCRA OTP token.")}
</p>
<p>
${_("Enter your username, the OTP PIN and the input for the challenge.")}
${_("By submitting this you will generate a QR image, that can be scaned with your OCRA2 Token reader.")}
${_("To verify your result enter the OTP value into the form below.")}
</p>
</div> <!-- sidebar -->


<div id="main">
<h1>${_("OCRA2 Login")}</h1>
<div id="auth">
    <table>
        <tr><td>
        <form class="cmxform" id="form_challenge_ocra2" method="post" action="">
            <section name="login">
                <table><tr>
                    <td><h2>${_("Submit a challenge:")}</h2></td>
                </tr><tr>
                <td>${_("username")}</td>
                <td><input type="text" id="user" name="user" class="required"></td>
                </tr>
                %if c.realmbox:
                <tr>
                    <td>${_("realm")}</td>
                    <td>
                        <select name="realm" id="realm">
                            %for realm in c.realmArray:
                            <option value="${realm}"
                                %if c.defaultRealm == realm:
                                selected
                                %endif
                                >
                            ${realm}
                            </option>
                            %endfor
                        </select>
                    </td>
                </tr>
                %endif
                <tr>
                    <td>${_("OTP PIN")}</td>
                    <td><input type="text" id="pin" name="pass" class="required"></td>
                </tr><tr>
                    <td>${_("message / data")}</td>
                    <td><textarea cols="40" rows="6" id="challenge" name="data" class="required"></textarea></td>
                </tr><tr>
                <td></td>
                        <td>
                        <input type="submit" value="${_('get challenge')}">
                </tr></table>
            </section>
        </form>
        </td><td rowspan="3">
        <div id="display"></div>
        </td>
        </tr><tr>
            <td>
                <h2>${_("Scan your challenge and get your OTP:")}</h2>
            </td>
        </tr><tr>
        <td>
        <form class="cmxform" id="form_login_ocra2" method="post" action="">
            <section name="login">
                <table><tr>
                    <td><h2>${_("Login:")}</h2></td>
                </tr><tr>
                    <td>${_("username")}</td>
                    <td><input type="text" id="user2" name="user" class="required"></td>
                </tr><tr>
                    <td>${_("OTP PIN and OTP value")}</td>
                    <td><input type="password" autocomplete="off" name="pass" id="pass" class="required"></td>
                </tr></table>
                </section>
                <input type="submit" value="${_('login')}">
                </form>
        </td></tr>
    </table>
</div>
<div id="errorDiv"></div>
<div id="successDiv"></div>


</div>  <!-- end of main-->

