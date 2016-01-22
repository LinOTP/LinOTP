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
<h2>${_("Provision your OATH Token")}</h2>

<div id='oathtokenform'>
    <form class="cmxform" name='myForm'>
        <fieldset>
        <p id=oath_info>
        ${_("1. You first need to install the oathtoken to your iPhone.")}
        <ul>
        <li><a href='http://itunes.apple.com/us/app/oath-token/id364017137?mt=8' target='extern'>${_("link for iPhone")}</a><br>
            ${_("Using the QR Code you can directly go to install the oath token on your iPhone.")}
             <span id=qr_code_iphone_download_oath></span>
            </li>
        </ul>
        <p>${_("2. Then you may create a profile.")}<br>
        <button class='action-button' id='button_provisionOath' onclick="provisionOath(); return false;">
            ${_("enroll OATH Token")}
        </button>
        </p>
        <div id="provisionresultDiv">
            <p>${_("3.")} <b>oathtoken</b> ${_("successfully created!")}</p>
            <p>${_("Click on this link to install the oathtoken profile to your iPhone:")}
                <a id=oath_link>${_("install profile")}</a>
            </p>
            <p>${_("Or you can scan the QR code below your iPhone to import the secret.")}</p>
            <p><span id=oath_qr_code></span></p>
        </div>
        </fieldset>
    </form>
</div>

<script>
        $('#provisionresultDiv').hide();
        $('#qr_code_iphone_download_oath').show();
        $('#qr_code_iphone_download_oath').html(generate_qrcode(10,"http://itunes.apple.com/us/app/oath-token/id364017137?mt=8"));
</script>
