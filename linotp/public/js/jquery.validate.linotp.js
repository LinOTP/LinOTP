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
 *    E-mail: linotp@keyidentity.com
 *    Contact: www.linotp.org
 *    Support: www.keyidentity.com
 *
 */

jQuery.validator.addMethod(
    "password-strength",
    function(value, element, param) {
        var required_char_types = param;
        required_char_types -= !!value.match(/[a-z]/);
        required_char_types -= !!value.match(/[A-Z]/);
        required_char_types -= !!value.match(/[0-9]/);
        required_char_types -= !!value.match(/[^a-zA-Z0-9]/);
        required_char_types -= value.length > 12;
        return required_char_types <= 0;
    },
    jQuery.validator.format(i18n.gettext(
        "The password must contain {0} of the following: lowercase, uppercase, special characters, numbers, length of 12"
    ))
);

jQuery.validator.addMethod(
    "valid_json",
    function(value, element, param) {
        try {
            $.parseJSON(value);
            return true;
        } catch (err) {
            return false;
        }
    },
    i18n.gettext('Not a valid json string!')
);

jQuery.validator.addMethod(
    "realmname",
    function(value, element, param) {
        return value.match(/^[a-zA-Z0-9_\-\.]+$/i);
    },
    i18n.gettext("Please enter a valid realm name. It may contain characters, numbers and '_-.'.")
);

jQuery.validator.addMethod(
    "unique_resolver_name",
    function(value, element, param) {
        if (g.current_resolver_name !== value) {
            var resolvers = get_resolvers();
            return $.inArray(value, resolvers) === -1;
        }
        return true;
    },
    i18n.gettext("Resolver name is already in use")
);

jQuery.validator.addMethod(
    "unique_realm_name",
    function(value, element, param) {
        var realms = get_realms();
        return $.inArray(value, realms) === -1;
    },
    i18n.gettext("Realm name is already in use")
);

jQuery.validator.addMethod(
    "resolvername",
    function(value, element, param) {
        return value.match(/^[a-zA-Z0-9_\-]+$/i);
    },
    i18n.gettext("Please enter a valid resolver name. It may contain characters, numbers and '_-'.")
);

jQuery.validator.addMethod(
    "providername",
    function(value, element, param) {
        return value.match(/^[a-zA-Z0-9_\-]+$/i);
    },
    i18n.gettext("Please enter a valid provider name. It may contain characters, numbers and '_-'.")
);

jQuery.validator.addMethod(
    "ldap_uri",
    function(value, element, param) {
        return value.match(param);
    },
    i18n.gettext("Please enter a valid ldap uri. It needs to start with ldap:// or ldaps://")
);

jQuery.validator.addMethod(
    "http_uri",
    function(value, element, param) {
        return value.match(param);
    },
    i18n.gettext("Please enter a valid http uri. It needs to start with http:// or https://")
);

jQuery.validator.addMethod(
    "ldap_timeout",
    function(value, element, param) {
        return value.match(
            /(^[+]?[0-9]+(\.[0-9]+){0,1}$)|((^[+]?[0-9]+(\.[0-9]+){0,1})\s*;\s*([+]?[0-9]+(\.[0-9]+){0,1}$))/
        );
    },
    i18n.gettext("Please enter a timeout like: 5.0; 5.0 ")
);

jQuery.validator.addMethod(
    "ldap_searchfilter",
    function(value, element, param) {
        return value.match(/(\(\S+=(\S+).*\))+/);
    },
    i18n.gettext("Please enter a valid searchfilter like this: (sAMAccountName=*)(objectClass=user)")
);

jQuery.validator.addMethod(
    "ldap_userfilter",
    function(value, element, param) {
        return value.match(/\(\&(\(\S+=(\S+).*\))+\)/);
    },
    i18n.gettext("Please enter a valid user searchfilter like this: (&(sAMAccountName=%s)(objectClass=user))")
);

jQuery.validator.addMethod(
    "ldap_mapping",
    function(value, element, param) {
        return value.match(/{.+}/);
    },
    sprintf(i18n.gettext('Please enter a valid searchfilter like this: %s'),
        '{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile"'
        + ' : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }')
);

jQuery.validator.addMethod(
    "ldap_uidtype",
    function(value, element, param) {
        return value.match(/.*/);
    },
    i18n.gettext('Please enter the UID of your LDAP server like DN, entryUUID, objectGUID or GUID')
);

jQuery.validator.addMethod(
    "sql_driver",
    function(value, element, param) {
        return value.match(/(mysql)|(postgres)|(mssql)|(oracle)|(ibm_db_sa\+pyodbc)|(ibm_db_sa)/);
    },
    i18n.gettext("Please enter a valid driver specification like: mysql, "
        + "postgres, mssql, oracle, ibm_db_sa or ibm_db_sa+pyodbc")
);

jQuery.validator.addMethod(
    "sql_mapping",
    function(value, element, param) {
        return value.match(/{.+}/);
    },
    sprintf(i18n.gettext('Please enter a valid searchfilter like this: %s'),
        '{ "userid" : "id", "username": "user", "phone" : "telephoneNumber", "mobile" : "mobile", '
            + '"email" : "mail", "surname" : "sn", "givenname" : "givenName" ,"password" : "password" }')
);
