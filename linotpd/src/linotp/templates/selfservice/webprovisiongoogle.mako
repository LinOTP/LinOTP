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
<h2>${_("Provision your OATH soft token")}</h2>

<div id='googletokenform' >
    <form class="cmxform" name='myForm'>
        <ol>
            <li>${_("You need an OATH compatible soft token app installed on your mobile device.")}
               <br>${_("(FreeOTP, Google Authenticator or another OATH compatible soft token)")}
            </li>
            <li>${_("Provision your soft token in LinOTP")}:
                % if 'webprovisionGOOGLE' in c.actions and 'webprovisionGOOGLEtime' in c.actions:
                <br><label for="google_type">${_("Choose your token profile ")}</label>
                    <select id="google_type">
                    <option value=hotp>${_("event based")}</option>
                    <option value=totp>${_("time based")}</option>
                    </select>
                    ${_("and")} <button class='action-button' id='button_provisionGoogle' onclick="provisionGoogle(); return false;">
                    ${_("enroll your token")}.
                    </button>
                % elif 'webprovisionGOOGLE' in c.actions:
                    <input type="hidden" id="google_type" value="hotp"/>
                    <br>
                    <button class='action-button' id='button_provisionGoogle_hotp' onclick="provisionGoogle(); return false;">
                    ${_("enroll your event based token")}.
                    </button>
                % elif 'webprovisionGOOGLEtime' in c.actions:
                    <input type="hidden" id="google_type" value="totp"/>
                    <br>
                    <button class='action-button' id='button_provisionGoogle_totp' onclick="provisionGoogle(); return false;">
                    ${_("enroll your time based token")}.
                    </button>
                %endif
            </li>
            <div id="provisionGoogleResultDiv">
            <li>${_("Install your soft token profile")}:
                <p>${_("To install the token on your mobile device, scan the QR code below with your soft token app or follow the link")}:</p>
                <br><a id="google_link"><span id="google_qr_code"> </span></a>
           </li>
            </div>
        </ol>
    </form>
</div>

<script>
    $('#provisionGoogleResultDiv').hide();
</script>
