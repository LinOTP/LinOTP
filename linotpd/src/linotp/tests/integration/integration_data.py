# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2015 - 2017 KeyIdentity GmbH
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

# LDAP resolvers
ldap_ca_cert = \
"""-----BEGIN CERTIFICATE-----
MIIFgzCCA2ugAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJERTEq
MCgGA1UECgwhTFNFIExlYWRpbmcgU2VjdXJpdHkgRXhwZXJ0cyBHbWJIMRQwEgYD
VQQDDAtMU0UgQ0EgMjAxNTAiGA8yMDE1MDQwMTAwMDAwMFoYDzIwMjcwNDAxMDAw
MDAwWjBPMQswCQYDVQQGEwJERTEqMCgGA1UECgwhTFNFIExlYWRpbmcgU2VjdXJp
dHkgRXhwZXJ0cyBHbWJIMRQwEgYDVQQDDAtMU0UgQ0EgMjAxNTCCAiIwDQYJKoZI
hvcNAQEBBQADggIPADCCAgoCggIBAOXqHuDVcqkSOsb+mwXZloq6WdGNinvZA0L2
0JgpY/kBfRrMowu/NUCB0vgNEfJPkeLX115QeIHTK17+HZ16+G/CCgDNiVr8NcOJ
tSHQyw+OYrV3dHoBWMfKkYDEUXdqv+Q7905IKBWnM1DgQLkrNt/BTF9ePmgRpUFl
Gza/5fvFZErK/0koLq3esyysBCJRlnCzkWJK9JmkUcpvW3O21/+qrtMC3w3fmuL6
dT2xpRBdlzNPBSVci+VGxBEK7F6H+ZVXCxe/fSl32cXcbJQy/Pz4E3AqIV4mphku
u+3ZxS1AVhLDCfOnHBkT5Mx/09jRbQnOugCbhiuglqk/v0zfv164m6+2aZKm6CRo
+7f5ipkBuowUyv1X1+GLIT0hSLTZdoIX1mfBZ5bvO20P32UfhgwNdsmi0er4HViv
92fH8JX/0eh2PfLUfILQtPS0M86TtPVmFrCd+DHdqP4C73xqGF+qNUoUoXDIQ/rB
o50xsk9a1mGe7y1T+hnMPfPxjj1Pm4v+0InuUzE5WEA9cjWrvzkuxE9uaP5eYnB4
2kMne3clRZSwWcrOjWqA6tWV8/emynwhe3CGndIvOejrBrd2GR9w/0iLjwqw3JZ7
sBalglf21k+zos0njcsbGITW9SpMCKe2AuauFqtwGGqn3CzLfF+/u5OAFVErP8W7
r3yiqcCXAgMBAAGjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFOSY
lUpVl3nYrcQ3wBPY6yswIvX2MB8GA1UdIwQYMBaAFOSYlUpVl3nYrcQ3wBPY6ysw
IvX2MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQ0FAAOCAgEAif0FsJfgGq1d
xMy3hYT6xC5cB5hTAlmO5UT0TSOSi/Fe0IeKQFSI2bxBkaYLMv02SzHKdD3GxYfz
F9QA2dvHxAJIF4/BQckb3lO5f8F1UBRwfXBaG/2FEnwAl0fiyl3YvoFa4duLN9PO
YTT/esrmkEpZETonftaGB7rJq55AJun9SMAQ5dnDSvnTU5pia/wVQj0PNkU8hO/z
P3qg4ZaiOzYkMbD8Dw0odppG26EhxfXelfonCF1mAaiHU7RavCL1hqtXtESmGqmV
B++u2PHBKvaxyW1UkoH7zy6teYO89YmmOf7aYoXnZ+hY7GLkiQfgxlam5PLT++ra
bHIjLGFTJgGEj948MQ8hl8oG+nMAP6DcNkjhvuOq5O+aEPNMsidTNfUj3FtC60Pa
U67TZfaCUP4DyASNKH6K0LHY3C5qwy17pKnWA1Y6Udf9QufkeZJcIhnnmW/PiVeK
tLOm03i8iOAitjiMU9kO2yCn28e/4BUFixoG7eE9cHIZWPJh+ncNih64xepJlzvX
a9DD2ujwHAbgpbE4id0bHYbpPVNVNMADwA8g0vI1fcd+VzeEcU/8wK77zl3MjXM4
iDCfI7WTMiUSMthBqBysBkLTVODcoK3C0QmJMbGAczHglK65tVInkK504+SdRREz
D73172agRToOg0Sid2C4iipj//OA3q4=
-----END CERTIFICATE-----"""

# CA for test AD server certificate
ad_ca_cert= \
"""-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIQEf6o60+xo6NJkdPwYpVFoTANBgkqhkiG9w0BAQsFADBj
MRMwEQYKCZImiZPyLGQBGRYDbmV0MRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEV
MBMGCgmSJomT8ixkARkWBWhvdGFkMRwwGgYDVQQDExNob3RhZC1IT1RUWUJPVFRZ
LUNBMB4XDTE2MDMwOTE2MDc0NFoXDTIxMDMwOTE2MTc0NFowYzETMBEGCgmSJomT
8ixkARkWA25ldDEXMBUGCgmSJomT8ixkARkWB2V4YW1wbGUxFTATBgoJkiaJk/Is
ZAEZFgVob3RhZDEcMBoGA1UEAxMTaG90YWQtSE9UVFlCT1RUWS1DQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALxHY5XG5pTwKmrDKsHGdO2IPEhhuAW+
cXYE27xocBq+fbgp+rD7KwR8TCv/LhjMzT+lAqHc9PMnr6VtAVHu+S2waNpWPm2y
RTYtWOXXZQK/1gVi+q68+nKHQmCT3sOsrsaOpPH2v8NxrMRkKi5xwQRMqjojfmHr
QMS72Pa63U73fS2cqSYhTIAfJlmu1UWQ0aHmI15PyrFWJGo4KVw3GfKu5oHGfuk6
pt93Ab7TvCbJ3Syk+VVbSfaprdHYVHCTQjz8235r5Etl+hgvt9NRfAYskcC3DAKq
cLoOb+G1wmfcA2isQVPhrho/glyjlkaZYEtafFybRl4Bxq4JU0lc6AcCAwEAAaNR
ME8wCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFL4WBBpt
RAdjQDlfivTnhiUY9j+UMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUA
A4IBAQCEe5MX+Yb6HjfNDmimBLr06dqc5hYSlOZ6lgWl2rIhI8/Bdc6OHlZTVdUV
1RztceB1h6gsIBoUkVemLaToUewnZR7Zw38qNjHwD88qi1Io8r0jxQceLODuKhGp
R0XCjjPozONBIf6kkXsZLp/6a6vkb9uycoDgGWzQw/+8ytEz+WXvb3x3/cpUQ2XY
mpu3hbwIGWzjCoXa1zLrNhC6B2j1JZ3NmeUp2DsURWkUWUCCPtMPDAPjh4DGT8gx
wksjsMcgvCrISnUOLAIH3IXD2x9C8NvVursf22x4T+JhIT6Ipkm3yzmhdjTOuOOB
mOOzQ8LklhTOAHJva7wNJrcfEG0B
-----END CERTIFICATE-----"""

musicians_ldap_resolver = {
                'name' : "SE_musicians",
                'title' : "Musicians LDAP (Blackdog)",
                'type': 'ldapresolver',
                'uri' : "ldaps://blackdog",
                'certificate' : ldap_ca_cert,
                'basedn' : "ou=people,dc=blackdog,dc=corp,dc=lsexperts,dc=de",
                # You may also use cn="Wolfgang Amadeus Mozart"
                'binddn' : u'cn="عبد الحليم حافظ",ou=people,dc=blackdog,dc=corp,dc=lsexperts,dc=de',
                'password' : "Test123!",
                'preset_ldap' : True,
                'expected_users' : 10,
                'users': ['bach', 'beethoven', 'berlioz', 'brahms', 'debussy', u'dvořák',
                                'haydn', 'mozart', u'حافظ', u'郎']
}

physics_ldap_resolver = {
                'name' : "SE_physics",
                'title' : "Physics LDAP (Blackdog)",
                'type': 'ldapresolver',
                'uri' : "ldaps://hottybotty",
                'certificate' : ad_ca_cert,
                'basedn' : 'dc=hotad,dc=example,dc=net',
                'binddn' : u'cn="Clark Maxwell",ou=corp,dc=hotad,dc=example,dc=net',
                'password' : "Test123!",
                'preset_ldap' : False,
                'expected_users' : 12,
}

sql_resolver = {
                'name' : "SE_mySql",
                'type' : 'sqlresolver',
                'server' : 'blackdog',
                'database' : 'userdb',
                'user' : 'resolver_user',
                'password' : 'Test123!',
                'table' : 'user',
                'limit' : 500,
                'encoding' : 'latin1',
                'expected_users' : 5,
                'users': ['corny', 'kay', 'eric', u'knöt', 'bianca']
}

# Expected content of /etc/se_mypasswd is:
#
# hans:x:42:0:Hans Müller,Room 22,+49(0)1234-22,+49(0)5678-22,hans@example.com:x:x
# susi:x:1336:0:Susanne Bauer,Room 23,+49(0)1234-24,+49(0)5678-23,susanne@example.com:x:x
# rollo:x:21:0:Rollobert Fischer,Room 24,+49(0)1234-24,+49(0)5678-24,rollo@example.com:x:x
sepasswd_resolver = {
                'name' : 'SE_myPasswd',
                'type' : 'passwdresolver',
                'filename' : '/etc/se_mypasswd',
                'expected_users' : 3,
}
