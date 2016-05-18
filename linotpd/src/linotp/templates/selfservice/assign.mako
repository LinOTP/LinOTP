# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
</%doc>

<h1>${_("Assign OTP Token")}</h1>
<div id='assignform'>
    <form class="cmxform" name='myForm'>
    <fieldset>
        %if 'getserial' in c.actions:
        ${_("You may either assign the token by entering the serial number or you can enter an OTP value of the token and the system will try to identify the token for you.")}
        %endif
        <table>
        %if 'getserial' in c.actions:
        <tr>
        <td><label for=otp_serial>${_("The OTP value of the Token to assign")}</label></td>
        <td><input type='text' id='otp_serial' class='text ui-widget-content ui-corner-all' value='' size="20" />
            <button class='action-button' id='button_otp_serial' onclick="getserial(); return false">
                ${_("Determine Serial Number")}
            </button>
        </td>
        </tr>

        %endif
        <tr>
        <td><label for=serial>${_("Serialnumber of new Token")}</label></td>
        <td><input type='text' id='assign_serial' class="text ui-widget-content ui-corner-all" value='' /></td>
        </tr>
        </table>
        <button class='action-button' id='button_assign' onclick="assign(); return false">${_("Assign Token")}</button>
    </fieldset>
    </form>
</div>

