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
<title>LinOTP Push Token Auth testing</title>
</%block>

<%inherit file="auth-base.mako"/>

<div id="sidebar">
    <p>${_("Here you may try to authenticate using your LinOTP Push Token.")}</p>
    <p>${_("Enter your username, the OTP PIN and the data you want to display to verify the authentication.")}</p>
</div> <!-- sidebar -->

<div id="main">
<h1>${_("LinOTP Push Token Login")}</h1>
<div id="auth" class="pushtoken">
    <table>
        <tr>
            <td>
                <form class="cmxform" id="form_challenge_trigger" method="post" action="">
                    <section name="login">
                        <table>
                            <tr>
                                <td><h2>${_("Create challenge:")}</h2></td>
                            </tr>
                            <tr>
                                <td>${_("username")}</td>
                                <td><input type="text" id="user" name="user" class="required"></td>
                            </tr>
                            <tr>
                                <td>${_("OTP PIN")}</td>
                                <td><input type="password" id="pin" name="pin" class="required"></td>
                            </tr>
                            <tr>
                                <td>${_("message / data")}</td>
                                <td><textarea cols="40" rows="6" id="challenge" name="data" class="required"></textarea></td>
                            </tr>
                            <tr>
                                <td></td>
                                <td><input type="submit" value="${_('get challenge')}"></td>
                            </tr>
                        </table>
                    </section>
                </form>
            </td>
        </tr>
        <tr>
            <td>
                <table>
                    <tr>
                        <td>${_("Transaction-ID")}</td>
                        <td><input type="text" id="transactionid" name="transactionid" class="required"></td>
                    </tr>
                    <tr>
                        <td><h2>${_("Check the status of your challenge:")}</h2></td>
                        <td><button id="check_status">${_("check status")}</button></td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</div>
<div id="errorDiv"></div>
<div id="successDiv"></div>
</div>  <!-- end of main-->
