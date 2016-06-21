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

<h1>${_("Activate your OCRA Token")}</h1>


<div id='oathtokenform'>
    <form class="cmxform" name='myForm'>

        <fieldset>
        <table>
        <p id=oath_info>
        <tr><td>${_("Your OCRA Token :")}      </td>
            <td> <input type='text' class='selectedToken' class="text ui-widget-content ui-corner-all" disabled
                value='' id='serial' onchange="resetOcraForm()"/></td></tr>
        <tr><td><label for=activationcode>${_("1. Enter the activation code :")}</label> </td>
            <td><input type='text' class="text ui-widget-content ui-corner-all" value='' id='activationcode'/></td>
                <input type='hidden' value='${_("Failed to enroll token!")}' id='ocra_activate_fail'/>
            <td><div id='qr_activate'>
                <button class='action-button' id='button_provisionOcra' onclick="provisionOcra(); return false;">
                ${_("activate your OCRA Token")}
                </button>
                </div>
            </td>
            </tr>
        <tr><td><div id='ocra_qr_code'></div></td></tr>
        </table>
    </form>
    <form class="cmxform" name='myForm2'>
        <table>
        <tr><td><div id='qr_confirm1'><label for=ocra_check>${_("2. Enter your confirmation code:")}
                </label></div> </td>
            <td><div id='qr_confirm2'>
                <input type='hidden' class="text ui-widget-content ui-corner-all" id='transactionid' value='' />
                <input type='hidden' value='${_("OCRA rollout for token %s completed!")}' 			id='ocra_finish_ok'  />
                <input type='hidden' value='${_("OCRA token rollout failed! Please retry")}' 		id='ocra_finish_fail'/>
                <input type='text' class="text ui-widget-content ui-corner-all"              		id='ocra_check' value='' />
                </div>
            </td>
            <td>
                <div id=qr_finish >
                <button class='action-button' id='button_finishOcra' onclick="finishOcra(); return false;">
                ${_("finish your OCRA Token")}
                </button>
                </div>
            </td>
            </tr>
        </div>
        <tr><td><div id='qr_completed'></div></td></tr>
        </p>
        </table>
        </fieldset>
    </form>
</div>


<script>
    $('#qr_finish').hide();
    $('#qr_completed').hide();
    $('#qr_confirm1').hide();
    $('#qr_confirm2').hide();
    $('#ocra_check').removeAttr("disabled");
    $('#activationcode').removeAttr("disabled");
</script>
