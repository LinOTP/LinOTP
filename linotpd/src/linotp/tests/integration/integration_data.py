# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2015 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""
This file contains sample data for the integration tests
"""

# This is the "O = LinOTP-DE, CN = LinOTP-DE Root CA" certificate
# used by the new blackdog-ldap container.

ldap_ca_cert = """-----BEGIN CERTIFICATE-----
MIIBojCCAUmgAwIBAgIQPlwfzlZDQsPhD1rWE9Ux3TAKBggqhkjOPQQDAjAwMRIw
EAYDVQQKEwlMaW5PVFAtREUxGjAYBgNVBAMTEUxpbk9UUC1ERSBSb290IENBMB4X
DTIyMDIwNjEyMTUzN1oXDTMyMDIwNDEyMTUzN1owMDESMBAGA1UEChMJTGluT1RQ
LURFMRowGAYDVQQDExFMaW5PVFAtREUgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABGZPiX58lcLz+oX/CNZFdJI3bWE9KdxRlmypYWwbZUqkhLn1ARWc
lblmltOU/L6/XlbYuLWdTE3Hk1VF7UA+zdejRTBDMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBRY28kvC11GjduDBsUaQvIr87ke
MDAKBggqhkjOPQQDAgNHADBEAiB9pumbZbFk5ChludETNKxFzSVRCx7Cbzm1zNCw
TGfofQIgFClkyscaKq+ALGjKzDAf+oF4A1BgOzqdFxafFePRH54=
-----END CERTIFICATE-----"""

musicians_ldap_resolver = {
    'name': "SE_musicians",
    'title': "Musicians LDAP (Blackdog)",
    'type': 'ldapresolver',
    'uri': "ldaps://blackdog-ldap",
    'certificate': ldap_ca_cert,
    'basedn': "ou=people,dc=blackdog,dc=corp,dc=lsexperts,dc=de",
    # You may also use cn="Wolfgang Amadeus Mozart"
    'binddn': u'cn="عبد الحليم حافظ",ou=people,dc=blackdog,dc=corp,dc=lsexperts,dc=de',
    'password': "Test123!",
    'preset_ldap': True,
    'expected_users': 10,
    'users': ['bach', 'beethoven', 'berlioz', 'brahms', 'debussy', u'dvořák',
              'haydn', 'mozart', u'حافظ', u'郎']
}

physics_ldap_resolver = {
    'name': "SE_physics",
    'title': "Physics LDAP (Blackdog)",
    'type': 'ldapresolver',
    'uri': "ldaps://ad-dev-team.dmz.linotp.de",
    'certificate': ldap_ca_cert,
    'basedn': 'dc=dmz,dc=linotp,dc=de',
    'binddn': u'cn="Clark Maxwell",ou=corp,dc=dmz,dc=linotp,dc=de',
    'password': "Test123!",
    'preset_ldap': False,
    'expected_users': 26,
}

sql_resolver = {
    'name': "SE_mySql",
    'type': 'sqlresolver',
    'server': 'blackdog-mysql',
    'database': 'userdb',
    'user': 'resolver_user',
    'password': 'Test123!',
    'table': 'user',
    'limit': 500,
    'encoding': 'latin1',
    'expected_users': 5,
    'users': ['corny', 'kay', 'eric', u'knöt', 'bianca']
}

# Expected content of /etc/se_mypasswd is:
#
# hans:x:42:0:Hans Müller,Room 22,+49(0)1234-22,+49(0)5678-22,hans@example.com:x:x
# susi:x:1336:0:Susanne Bauer,Room 23,+49(0)1234-24,+49(0)5678-23,susanne@example.com:x:x
# rollo:x:21:0:Rollobert Fischer,Room 24,+49(0)1234-24,+49(0)5678-24,rollo@example.com:x:x
sepasswd_resolver = {
    'name': 'SE_myPasswd',
    'type': 'passwdresolver',
    'filename': '/etc/se_mypasswd',
    'expected_users': 3,
}
