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
<%
    ttype = c.tokeninfo.get("LinOtp.TokenType","").lower()
%>

<table class=tokeninfoOuterTable>
    % for value in c.tokeninfo:
    <tr>
        <!-- left column -->
    <td class=tokeninfoOuterTable>${value}</td>
        <!-- middle column -->
    <td class=tokeninfoOuterTable>
    %if "LinOtp.TokenInfo" == value:
        <table class=tokeninfoInnerTable>
        %for k in c.tokeninfo[value]:
        <tr>
        <td class=tokeninfoInnerTable>${k}</td>
        <td class=tokeninfoInnerTable>${c.tokeninfo[value][k]}</td>
        </tr>
        %endfor
        </table>
        <div id="toolbar" class="ui-widget-header ui-corner-all">
            <button id="ti_button_hashlib">${_("hashlib")}</button>
            <button id="ti_button_count_auth_max">${_("count auth")}</button>
            <button id="ti_button_count_auth_max_success">${_("count auth max")}</button>
            <button id="ti_button_valid_start">${_("count auth max")}</button>
            <button id="ti_button_valid_end">${_("count auth max")}</button>
            %if ttype in [ "totp", "ocra" ]:
            <button id="ti_button_time_window">${_("time window")}</button>
            <button id="ti_button_time_step">${_("time step")}</button>
            <button id="ti_button_time_shift">${_("time shift")}</button>
            %endif
            %if ttype in [ "sms" ]:
            <button id="ti_button_mobile_phone">${_("mobile phone number")}</button>
            %endif


        </div>
    %elif "LinOtp.RealmNames" == value:
        <table class=tokeninfoInnerTable>
        % for r in c.tokeninfo[value]:
        <tr>
            <td class=tokeninfoInnerTable>${r}</td>
        </tr>
        % endfor
        </table>
    %else:
        ${c.tokeninfo[value]}
    %endif
    </td>
            <!-- right column -->
    <td>
        %if value == "LinOtp.TokenDesc":
            <button id="ti_button_desc"></button>
        %elif value == "LinOtp.OtpLen":
            <button id="ti_button_otplen"></button>
        %elif value == "LinOtp.SyncWindow":
            <button id="ti_button_sync"></button>
        %elif value == "LinOtp.CountWindow":
            <button id="ti_button_countwindow"></button>
        %elif value == "LinOtp.MaxFail":
            <button id="ti_button_maxfail"></button>
        %elif value == "LinOtp.FailCount":
            <button id="ti_button_failcount"></button>
        %endif

    </td>
    </tr>
    % endfor
</table>
