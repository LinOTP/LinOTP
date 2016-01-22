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
<h1>${_("Reset OTP PIN")}</h1>

<div id='passwordform'>
    <form class="cmxform" name='myForm'>
        <fieldset>

        <table>
        <tr>
        <td>${_("selected Token")}</td>
        <td><input type='text' class='selectedToken' class="text ui-widget-content ui-corner-all" disabled value='' /></td>
        </tr>
        <tr>
        <td><label for=pin1>PIN</label></td>
        <td><input autocomplete="off" type='password' onkeyup="checkpins('pin1', 'pin2');" id='pin1' class="text ui-widget-content ui-corner-all" value='' /></td>
        </tr>
        <tr>
        <td><label for=pin2>${_("repeat PIN")}</label></td>
        <td><input autocomplete="off" type='password' onkeyup="checkpins('pin1', 'pin2');" id='pin2' class="text ui-widget-content ui-corner-all" value=''/></td>
        </tr>
        </table>
        <button class='action-button' id='button_setpin' onclick="setpin(); return false;">${_("set PIN")}</button>
    <input type='hidden' value='${_("The passwords do not match!")}'        id='setpin_fail'/>
        <input type='hidden' value='${_("Error setting PIN: ")}'            id='setpin_error'/>
        <input type='hidden' value='${_("PIN set successfully")}'           id='setpin_ok'/>
        </fieldset>
    </form>
</div>
