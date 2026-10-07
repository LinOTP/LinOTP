# -*- coding: utf-8 -*-
<%doc>
 *
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010-2019 KeyIdentity GmbH
 *   Copyright (C) 2019-     netgo software GmbH
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
<%
    ttype = c.tokeninfo.get("LinOtp.TokenType","").lower()
%>
<%def name="token_info_value(value)">\
## Render a token info value. Objects and lists are broken down into nested
## tables at any depth, so that no value ends up as a python representation.
% if isinstance(value, dict):
<table class=tokeninfoInnerTable>
% for key, item in value.items():
<tr>
<td class=tokeninfoInnerTable>${key}</td>
<td class=tokeninfoInnerTable>${token_info_value(item)}</td>
</tr>
% endfor
</table>\
% elif isinstance(value, list):
<table class=tokeninfoInnerTable>
% for item in value:
<tr>
<td class=tokeninfoInnerTable>${token_info_value(item)}</td>
</tr>
% endfor
</table>\
% elif isinstance(value, str) and len(value) > 64:
<span title="${value}">${value[:48]}&hellip;</span>\
% else:
${value}\
% endif
</%def>

<table class=tokeninfoOuterTable>
    % for value in c.tokeninfo:
    <tr>
        <!-- left column -->
    <td class=tokeninfoOuterTable>${value}</td>
        <!-- middle column -->
    <td class=tokeninfoOuterTable>
    %if "LinOtp.TokenInfo" == value:
        <div class="tokeninfo-hint">
            Timestamps are in UTC
        </div>
        <table class=tokeninfoInnerTable>
        %for k in c.tokeninfo[value]:
        <tr>
        <td class=tokeninfoInnerTable>${k}</td>
        <td class=tokeninfoInnerTable id="tokeninfo_${k}">${token_info_value(c.tokeninfo[value][k])}</td>
        </tr>
        %endfor
        </table>
        <div id="toolbar" class="ui-widget-header ui-corner-all">
            <button id="ti_button_hashlib">${_("hashlib")}</button>
            <button id="ti_button_expiration">${_("Set Expiration")}</button>
            %if ttype in [ "totp", "ocra2" ]:
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
