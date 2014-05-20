# -*- coding: utf-8 -*-
<!--
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
-->
<script>
	jQuery.validator.addMethod("motp_key", function(value, element, param){
        return value.match(/^[a-fA-F0-9]+$/i);
    }, "Please enter a valid init secret. It may only contain numbers and the letters A-F.");
	
	$('#form_registermotp').validate({
        rules: {
            secret: {
                required: true,
                minlength: 16,
                maxlength: 32,
                number: false,
                motp_key: true
            }
        }
	});
</script>

<h1>${_("Register your mOTP Token")}</h1>
<div id='registermotpform'>
	<form class="cmxform" id='form_registermotp'>
	<fieldset>
		<table>
		<tr>
		<td><label for=secret>${_("Init Secret of motp-Token")}</label></td>
		<td><input id='secret' 
					name='secret' 
					class="required ui-widget-content ui-corner-all" 
					minlenght=16 
					maxlength=32/>
		</td>		
		</tr>
        <tr>
        <td><label for=otppin1>${_("mOTP PIN")}</label></td>
        <td><input autocomplete="off" type="password" onkeyup="checkpins('otppin1', 'otppin2');" id="otppin1" class="required text ui-widget-content ui-corner-all" /></td>
        </tr>
        <tr>
        <td><label for=otppin2>${_("mOTP PIN (again)")}</label></td>
        <td><input autocomplete="off" type="password" onkeyup="checkpins('otppin1', 'otppin2');" id="otppin2" class="required text ui-widget-content ui-corner-all" /></td>
        </tr>
        </table>
        <button class='action-button' id='button_register_motp' onclick="register_motp(); return false;">${_("register mOTP Token")}</button>
    </fieldset>    
    </form>
</div>

