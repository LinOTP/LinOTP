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
<script>
    jQuery.validator.addMethod("phone", function(value, element, param){
        return value.match(/^[+0-9\/\ ]+$/i);
    }, "Please enter a valid phone number. It may only contain numbers and + or /.");

    $('#form_registersms').validate({
        rules: {
            mobilephone: {
                required: true,
                minlength: 6,
                number: false,
                phone: true
            }
        }
    });

</script>

<h1>${_("Register your SMS OTP Token / mobileTAN")}</h1>
<div id='registersmsform'>
    <form class="cmxform" id='form_registersms'>
    <fieldset>
        <table>
        <tr>
        <td><label for=mobilephone>${_("Your mobile phone number")}</label></td>
        <td><input id='mobilephone'
                    name='mobilephone'
                    class="required ui-widget-content ui-corner-all"
                    value='${c.phonenumber}'/>
        </td>
        </tr>
        <tr>
        </table>
        <button class='action-button' id='button_register_sms' onclick="register_sms(); return false;">${_("register SMS Token")}</button>
    </fieldset>
    </form>
</div>

