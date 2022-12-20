# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2019 KeyIdentity GmbH
 *   Copyright (C) 2019 -      netgo software GmbH
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
<h1>${_("Delete OTP Token")}</h1>

<div id='deleteform'>
    <form class="cmxform" name='myForm' action="">
        <fieldset>
        <table>
        <tr>
        <td>${_("selected Token")}</td>
        <td><input type='text' class='selectedToken'  class="text ui-widget-content ui-corner-all" disabled value=''></td>
        </tr>
        </table>
        <button class='action-button' id='button_delete' onclick="token_delete(); return false;">${_("delete Token")}</button>
        </fieldset>
    </form>
</div>
