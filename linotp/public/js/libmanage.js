/*!
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
 */

function processLDAPTestResponse (xhdr, textStatus) {

    function displayResult(status, message) {
        var msg =  "<p>" + (status ? i18n.gettext("Connection test successful.") : i18n.gettext("Connection test failed.")) + "</p>"
            + "<p>" + message + "</p>";

        alert_box({
            'title': "LDAP Connection Test",
            'text': msg,
             'is_escaped': true
        });
    }

    $('#progress_test_ldap').hide();

    if(textStatus !== "success") {
        displayResult(false, i18n.gettext("Connection to LinOTP failed"));
        return;
    }

    var resp = xhdr.responseText;
    var obj = $.parseJSON(resp);

    if (obj.result.status == false) {
        displayResult(false, escape(obj.result.error.message));
        return;
    }
    if (obj.result.value && obj.result.value.result && obj.result.value.result.lastIndexOf("success", 0) === 0) {
        var limit = "";
        if (obj.result.value.result === "success SIZELIMIT_EXCEEDED") {
            limit = "<br><br><span class='hint'>" +
                    i18n.gettext("LDAP Server, especially Active Directory, implement a default serverside maximum size limit of 1000 objects.") +
                    i18n.gettext(" This is independed of the local sizelimit and does not hinder the functionality of LinOTP.") +
                    "</span>";
        }
        // show number of found users
        var userarray = obj.result.value.desc;
        if (userarray instanceof Array) {
            var usr_msg = sprintf(i18n.gettext("Number of users found: %d"),userarray.length);
            displayResult(true, escape(usr_msg) + limit)
            return;
        }
    }

    if(obj.result.value && obj.result.value.desc) {
        displayResult(false, escape(obj.result.value.desc));
    }
    else {
        displayResult(false, "");
    }
    return;
}
