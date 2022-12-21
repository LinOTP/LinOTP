LinOTP
======

LinOTP - the Open Source solution for two factor authentication
  Copyright (C) 2010 - 2019 KeyIdentity GmbH
  Copyright (C) 2019 -      netgo software GmbH


This repository contains all parts to build your own solution
for a strong, two factor authentication, which are:

 * linotpd        - the LinOTP server
 * useridresolver - integrate your user information through LDAP or SQL 
 * smsprovider    - module to support the submission of SMS through different channels

 * auth\_modules   - authentication modules for Radius and PAM
 * adminclient    - utilities to administrate the LinOTP server and to enroll tokens


LinOTP server is truly open in two ways. The modules and components 
are licensed under the AGPLv3, so you are able to have a complete 
working open source solution for strong, two factor authentication.

But LinOTP server is also open as far as its modular architecture is 
concerned. LinOTP aims not to bind you to any decision of the authentication 
protocol or where your user information should be stored. This is achieved by 
its modular architecture.

LinOTP server also provides a modular architecture to calculate OTP values. 
Thus many different OTP algorithms like the OATH standards: HMAC (RFC 4226)
and time based HMAC are supported by LinOTP. But LinOTP's design makes it 
easy to create your own tokens with different algorithms or even challenge 
response tokens.

The other components like the LinOTP authentication modules or the LinOTP 
administration clients will make it easy to integrate strong, two factor
authentication in your environment.

