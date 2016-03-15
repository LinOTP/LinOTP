# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
This file contains sample data for the integration tests
"""

# LDAP resolvers
ad_cert = \
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

old_ad_cert = \
"""-----BEGIN CERTIFICATE-----
MIIDcjCCAtugAwIBAgIQVSU6NwMTmKNI6t3WcjY6uTANBgkqhkiG9w0BAQUFADBC
MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFglsc2V4cGVy
dHMxDjAMBgNVBAMTBUNBMDAxMB4XDTA1MDQxMTE2NDgzOVoXDTQwMDQxMTE2NTY1
MFowQjEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRkwFwYKCZImiZPyLGQBGRYJbHNl
eHBlcnRzMQ4wDAYDVQQDEwVDQTAwMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAqlWLfYK+dExjG+Qa/jpYjSo3EQnweQ7azacosa+xsrTMfDV5wLgMBSclCTX2
i/35VRg282Bh7hKCZifOBnAxjCBIHMpHQmW9c0T/GpeWSOQ1x0KeKrZ4PRj5oHEv
/uDJ7q2HlWXgRQo6NR75yDGLpsAWk64TyQ/I4f2vlC+AtjMCAyPS46OCAWcwggFj
MBMGCSsGAQQBgjcUAgQGHgQAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBTCY8rVNcU/NGvgZxaPmO+Kz8bG4TCB/AYDVR0fBIH0MIHx
MIHuoIHroIHohoGwbGRhcDovLy9DTj1DQTAwMSxDTj1sc2V4czAxLENOPUNEUCxD
Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
cmF0aW9uLERDPWxzZXhwZXJ0cyxEQz1sb2NhbD9jZXJ0aWZpY2F0ZVJldm9jYXRp
b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGM2h0
dHA6Ly9sc2V4czAxLmxzZXhwZXJ0cy5sb2NhbC9DZXJ0RW5yb2xsL0NBMDAxLmNy
bDAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQUFAAOBgQBa+RGoezCgJS5W
PFCPy9BWqZr7iRimfRGBDqHpYDCPDtgec2fKCZ+u4jfwuTisZ7UOoiM1iEvkw0hH
Z7R1pz4Yd6E074kS/fe6u7U+9L3dmSUjFvO3gkLKtHKbhQi0NA+EHMRrPsQQemLm
gYzNiYwtvAu74Q+eTC6R5Uf0hOlFig==
-----END CERTIFICATE-----"""

musicians_ldap_resolver = {
                'name' : "SE_musicians",
                'title' : "Musicians LDAP (Blackdog)",
                'type': 'ldapresolver',
                'uri' : "ldaps://blackdog",
                'certificate' : ad_cert,
                'basedn' : "ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de",
                # You may also use cn="Wolfgang Amadeus Mozart"
                'binddn' : u'cn="عبد الحليم حافظ",ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de',
                'password' : "Test123!",
                'preset_ldap' : True,
                'expected_users' : 10,
}

physics_ldap_resolver = {
                'name' : "SE_physics",
                'title' : "Physics LDAP (Blackdog)",
                'type': 'ldapresolver',
                'uri' : "ldaps://hottybotty",
                'certificate' : ad_cert,
                'basedn' : 'dc=hotad,dc=example,dc=net',
                'binddn' : u'cn="Clark Maxwell",ou=corp,dc=hotad,dc=example,dc=net',
                'password' : "Test123!",
                'preset_ldap' : False,
                'expected_users' : 10,
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
                'expected_users' : 4,
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
