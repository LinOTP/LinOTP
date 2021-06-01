# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
 *    E-mail: linotp@keyidentity.com
 *    Contact: www.linotp.org
 *    Support: www.keyidentity.com
 *
</%doc>

<%block name="title">
        <title>LinOTP Auth testing</title>
</%block>

<%inherit file="auth-base.mako"/>

<div id="sidebar">
<p>
${_("Here you may try to authenticate using your OTP token.")}
</p>
<p>
${_("Enter your username, the OTP PIN (Password) and the OTP value.")}
</p>
</div> <!-- sidebar -->


<div id="main">
<h1>${_("Login")}</h1>
<div id='register'>
        <form class="cmxform"  id="form_login3" method="post" action="">
            <frameset name=login>
                <table>
                <tr>
                    <td>${_("username")}</td>
                    <td><input type='text' id='user3' name="user"  class="required"></td>
                </tr>
                <tr>
                    <td>${_("OTP PIN")}</td>
                    <td><input type="password" autocomplete="off" name="pass" id="pass3"></td>
                </tr>
                <tr>
                    <td>${_("OTP value")}</td>
                    <td><input type="text" autocomplete="off" name="otp" id="otp3"></td>
                </tr>
                </table>
            </frameset>
            <input type="submit" value="${_('login')}">
        </form>
</div>
<div id='errorDiv'></div>
<div id='successDiv'></div>


</div>  <!-- end of main-->

