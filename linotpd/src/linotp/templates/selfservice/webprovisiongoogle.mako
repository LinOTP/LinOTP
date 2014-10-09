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
<h2>${_("Provision your Google Authenticator")}</h2>

<div id='googletokenform'>
    <form class="cmxform" name='myForm'>
      <fieldset>
         <div title='${_("The Google Authenticator is an OTP token for smartphones ")}
            ${_("which is available in the appropriate app stores.")}'>
            <b>${_("Provision your ")}
                <a href='https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2' target='extern'>
                    ${_(" Google Authenticator")}</a> 
                ${_(" in LinOTP:")}</b>
            <p class='indent'>
                <label for="google_type">${_("Choose your token profile ")}</label>
                <select id="google_type">
                % if 'webprovisionGOOGLE' in c.actions:
                    <option value=hotp>${_("event based")}</option>
                %endif
                % if 'webprovisionGOOGLEtime' in c.actions:
                    <option value=totp>${_("time based")}</option>
                %endif
               </select>
            ${_("and")} <button class='action-button' id='button_provisionGoogle' onclick="provisionGoogle(); return false;">
            ${_("enroll it!")}
            </button>
            </p>
        </div>
        <div id="provisionGoogleResultDiv">
            <p class='indent'><i>${_("Google Authenticator token successfully created!")}</i></p>
            <p><b>${_("Load your Google Authenticator profile:")}</b></p>
            <div class='indent'>
                ${_("To install the profile on your mobil, click on the QR code image")}
                ${_(" or scan the QR code below with your Google Authenticator mobile app.")}
                <br/><a id="google_link"><span id="google_qr_code"> </span></a>
            </div>
        </div>
        </fieldset>
    </form>
</div>

<script>
    $('#provisionGoogleResultDiv').hide();
</script>
