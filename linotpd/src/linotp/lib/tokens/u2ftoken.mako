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
 *   contains the U2F token web interface
</%doc>

%if c.scope == 'selfservice.title.enroll':
${_("Enroll FIDO U2F Token")}
%endif

%if c.scope == 'selfservice.enroll':

<%!
    from linotp.lib.user import getUserRealms
%>
<%
    realm = ''
    realms = getUserRealms(c.authUser)
    if len(realms) > 0:
        realm = realms[0]
        realm += '/'
%>

<script>
    function self_u2f_get_param()
    {
        var urlparam = {};
        urlparam['type'] = 'u2f';
        urlparam['phase'] = 'registration1';
        urlparam['description'] = $('#enroll_u2f_desc').val();

        return urlparam;
    }

    function self_u2f_device_response(deviceResponseJSON, serial) {
        var deviceResponse = JSON.stringify(deviceResponseJSON);
        var params =  self_u2f_get_param();
        params['phase'] = 'registration2';
        params['otpkey'] = deviceResponse;
        params['serial'] = serial;
        enroll_token(params);
    }

    function self_u2f_submit(){
        var params =  self_u2f_get_param();
        var returnObj = enroll_token(params);
        var chal = returnObj.registerrequest;

        var self_u2f_device_response_callback = function(deviceResponseJSON) {
            var serial = returnObj.serial;
            self_u2f_device_response(deviceResponseJSON, serial);
        }
        u2f.register([chal], [], self_u2f_device_response_callback);
        return true;
    }
</script>

<table>
<tr>
    <td><label for="enroll_u2f_desc" id='enroll_u2f_desc_label'>${_("Description")}</label></td>
    <td><input type="text" name="enroll_u2f_desc" id="enroll_u2f_desc" value="self enrolled" class="ui-widget-content ui-corner-all" /></td>
</tr>
<tr>
    <td><button type="button" role="button" id="enroll_u2f_data_button" class='action-button' onclick='self_u2f_submit();'>${_("Enroll token")}</button></td>
</tr>
</table>
%endif
