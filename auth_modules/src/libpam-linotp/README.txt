#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
# 
#    This file is part of LinOTP authentication modules.
# 
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
# 
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
#     E-mail: linotp@lsexperts.de
#     Contact: www.linotp.org
#     Support: www.lsexperts.de
# 
#


This is the LinOTP pam module, which will send the username and
password - including otp - to the LinOTP-server to verify.

Thus you can login via OTP to every service that supports pam.

copy your /etc/pam.d/common_auth to something like /etc/pam.d/linotp_auth and replace the line
   auth ...... pam_unix.so

with 
   auth ...... pam_linotp.so

Now you can use the 
  @include linotp_auth
in every service you want to authenticate with OTP.

Config options to be set in the pam configuration:
        url=http://localhost:5001/validate/simplecheck
        nosslhostnameverify
        nosslcertverify
        realm=<yourRealm>
        resConf=<specialResolverConfig>


Have fun.
