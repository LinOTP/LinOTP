# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
"""

import logging
from linotp.tests import TestController, url
import linotp.lib.ImportOTP
import linotp.lib.ImportOTP

log = logging.getLogger(__name__)


XML_PSKC = '''<?xml version="1.0" encoding="UTF-8"?>

<KeyContainer Version="1.0" xmlns ="urn:ietf:params:xml:ns:keyprov:pskc">
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>Feitian Technology Co.,Ltd</Manufacturer>
      <SerialNo>1000133508267</SerialNo>
    </DeviceInfo>
    <Key Id="1000133508267" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
      <AlgorithmParameters>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
      </AlgorithmParameters>
      <Data>
        <Secret>
          <PlainValue>PuMnCivln/14Ii3DNhR4/1zGN5A=</PlainValue>
        </Secret>
        <Counter>
          <PlainValue>0</PlainValue>
        </Counter>
      </Data>
      <Policy>
        <StartDate>2012-08-01T00:00:00Z</StartDate>
        <ExpiryDate>2037-12-31T00:00:00Z</ExpiryDate>
      </Policy>
    </Key>
  </KeyPackage>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>Feitian Technology Co.,Ltd</Manufacturer>
      <SerialNo>1000133508255</SerialNo>
    </DeviceInfo>
    <Key Id="1000133508255" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
      <AlgorithmParameters>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
      </AlgorithmParameters>
      <Data>
        <Secret>
          <PlainValue>wRjcslncyKj//L1oaDVQbAvCNnI=</PlainValue>
        </Secret>
        <Counter>
          <PlainValue>0</PlainValue>
        </Counter>
      </Data>
      <Policy>
        <StartDate>2012-08-01T00:00:00Z</StartDate>
        <ExpiryDate>2037-12-31T00:00:00Z</ExpiryDate>
      </Policy>
    </Key>
  </KeyPackage>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>Feitian Technology Co.,Ltd</Manufacturer>
      <SerialNo>2600124809778</SerialNo>
    </DeviceInfo>
    <Key Id="2600124809778" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp">
      <AlgorithmParameters>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
      </AlgorithmParameters>
      <Data>
        <Secret>
          <PlainValue>MRffGnGNJKmo8uSW313HCvGNIYM=</PlainValue>
        </Secret>
        <Time>
          <PlainValue>0</PlainValue>
        </Time>
        <TimeInterval>
          <PlainValue>60</PlainValue>
        </TimeInterval>
      </Data>
      <Policy>
        <StartDate>2012-08-01T00:00:00Z</StartDate>
        <ExpiryDate>2037-12-31T00:00:00Z</ExpiryDate>
      </Policy>
    </Key>
  </KeyPackage>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>Feitian Technology Co.,Ltd</Manufacturer>
      <SerialNo>2600124809787</SerialNo>
    </DeviceInfo>
    <Key Id="2600124809787" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp">
      <AlgorithmParameters>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
      </AlgorithmParameters>
      <Data>
        <Secret>
          <PlainValue>9O9PX9g20x74kIcaLLrGiwMUReM=</PlainValue>
        </Secret>
        <Time>
          <PlainValue>0</PlainValue>
        </Time>
        <TimeInterval>
          <PlainValue>60</PlainValue>
        </TimeInterval>
      </Data>
      <Policy>
        <StartDate>2012-08-01T00:00:00Z</StartDate>
        <ExpiryDate>2037-12-31T00:00:00Z</ExpiryDate>
      </Policy>
    </Key>
  </KeyPackage>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>Feitian Technology Co.,Ltd</Manufacturer>
      <SerialNo>2600135004012</SerialNo>
    </DeviceInfo>
    <Key Id="2600135004012" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp">
      <AlgorithmParameters>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
      </AlgorithmParameters>
      <Data>
        <Secret>
          <PlainValue>A0DxFX1zRVTsxJlMKFsDXuNQYcI=</PlainValue>
        </Secret>
        <Time>
          <PlainValue>0</PlainValue>
        </Time>
        <TimeInterval>
          <PlainValue>60</PlainValue>
        </TimeInterval>
      </Data>
      <Policy>
        <StartDate>2012-08-01T00:00:00Z</StartDate>
        <ExpiryDate>2037-12-31T00:00:00Z</ExpiryDate>
      </Policy>
    </Key>
  </KeyPackage>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>Feitian Technology Co.,Ltd</Manufacturer>
      <SerialNo>2600135004013</SerialNo>
    </DeviceInfo>
    <Key Id="2600135004013" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp">
      <AlgorithmParameters>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
      </AlgorithmParameters>
      <Data>
        <Secret>
          <PlainValue>NSLuCF/qeQPsqY7Sod4anJMjIBg=</PlainValue>
        </Secret>
        <Time>
          <PlainValue>0</PlainValue>
        </Time>
        <TimeInterval>
          <PlainValue>60</PlainValue>
        </TimeInterval>
      </Data>
      <Policy>
        <StartDate>2012-08-01T00:00:00Z</StartDate>
        <ExpiryDate>2037-12-31T00:00:00Z</ExpiryDate>
      </Policy>
    </Key>
  </KeyPackage>
</KeyContainer>
'''

class TestImportOTP(TestController):

    def setUp(self):
        TestController.setUp(self)
        self.set_config_selftest()

    def test_parse_DAT(self):
        '''
        Test to parse of eToken dat file format - import
        '''
        data = '''
# ===== SafeWord Authenticator Records $Version: 100$ =====
dn: sccAuthenticatorId=RAINER01
objectclass: sccCompatibleToken
sccAuthenticatorId: RAINER01
sccTokenType: eToken-PASS-ES
sccTokenData: sccKey=E26BF3661C254BBAB7370296A6DE60D7AC8E0141;sccMode=E;sccPwLen=6;sccVer=6.20;
sccSignature:MC0CFGxPAjrb0zg7MwFzrPibnC70klMnAhUAwZzVdGBaKGjA0djXrGuv6ejTtII=

dn: sccAuthenticatorId=RAINER02
objectclass: sccCompatibleToken
sccAuthenticatorId: RAINER02
sccTokenType: eToken-PASS-TS
sccTokenData: sccKey=535CC2CB9DEA0B55B0A2D585EAB648EBCE73AC8B;sccMode=T;sccPwLen=6;sccVer=6.20;sccTick=30;sccPrTime=2013/03/12 00:00:00
sccSignature: MC4CFQDju23MCRqmkWC7Z9sVDB0y0TeEOwIVAOIibmqMFxhPiY7mLlkt5qmRT/xn        '''

        #from linotp.lib.ImportOTP.eTokenDat import parse_dat_data
        import linotp.lib.ImportOTP.eTokenDat
        TOKENS = linotp.lib.ImportOTP.eTokenDat.parse_dat_data(data, '1.1.2000')
        log.error(TOKENS)
        assert(len(TOKENS) == 2)
        assert(TOKENS.get("RAINER02") != None)
        assert(TOKENS.get("RAINER01") != None)
        return

    def test_import_DAT(self):
        '''
        Test to import of eToken dat file format
        '''
        data = '''
# ===== SafeWord Authenticator Records $Version: 100$ =====
dn: sccAuthenticatorId=RAINER01
objectclass: sccCompatibleToken
sccAuthenticatorId: RAINER01
sccTokenType: eToken-PASS-ES
sccTokenData: sccKey=E26BF3661C254BBAB7370296A6DE60D7AC8E0141;sccMode=E;sccPwLen=6;sccVer=6.20;
sccSignature:MC0CFGxPAjrb0zg7MwFzrPibnC70klMnAhUAwZzVdGBaKGjA0djXrGuv6ejTtII=

dn: sccAuthenticatorId=RAINER02
objectclass: sccCompatibleToken
sccAuthenticatorId: RAINER02
sccTokenType: eToken-PASS-TS
sccTokenData: sccKey=535CC2CB9DEA0B55B0A2D585EAB648EBCE73AC8B;sccMode=T;sccPwLen=6;sccVer=6.20;sccTick=30;sccPrTime=2013/03/12 00:00:00
sccSignature: MC4CFQDju23MCRqmkWC7Z9sVDB0y0TeEOwIVAOIibmqMFxhPiY7mLlkt5qmRT/xn        '''

        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':data,
                                         'type':'dat',
                                         'startdate':'1.1.2000', })
        print response
        assert '"imported": 2' in response

        data = ""
        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':data,
                                         'type':'dat',
                                         'startdate':'1.1.2000', })
        print response
        assert 'Error loading tokens. File or Type empty' in response

        data = """
####
"""
        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file': data,
                                         'type': 'dat',
                                         'startdate': '1.1.2000', })
        print response
        assert '"imported": 0' in response

        ## test: no startdate
        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':data,
                                         'type':'dat',
                                         })
        print response
        assert '"imported": 0' in response

        ## test: wrong startdate
        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':data,
                                         'type':'dat',
                                         'startdate': '2000-12-12', })
        print response
        assert '"imported": 0' in response

    def test_parse_PSKC_OCRA(self):
        '''
        Test import OCRA via PSCK
        '''
        xml = '''<?xml version="1.0" encoding="UTF-8"?>
<KeyContainer Version="1.0"
              Id="KC20130122"
              xmlns="urn:ietf:params:xml:ns:keyprov:pskc"
              xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
              xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
     <EncryptionKey>
         <ds:KeyName>Pre-shared-key</ds:KeyName>
     </EncryptionKey>
     <MACMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
         <MACKey>
             <xenc:EncryptionMethod
             Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
             <xenc:CipherData>
                 <xenc:CipherValue>OdudVkgsZywiwE1HqPGOJtHmBl+6HzJkylgDrZU9gcflyCddzO+cxEwzYIlOiwrE</xenc:CipherValue>
             </xenc:CipherData>
         </MACKey>
     </MACMethod>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>NagraID Security</Manufacturer>
      <SerialNo>306EUO4-00960</SerialNo>
      <Model>306E</Model>
      <IssueNo>880479B6A2CA2080</IssueNo>
    </DeviceInfo>
    <Key Id="880479B6A2CA2080"
         Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:ocra">
    <AlgorithmParameters>
        <Suite>OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1</Suite>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
    </AlgorithmParameters>
      <Data>
        <Secret>
          <EncryptedValue>
            <xenc:EncryptionMethod
                  Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
            <xenc:CipherData>
              <xenc:CipherValue>VHdEP8TXnMmE3yiAnB5Fx+SQ85UXCNAxH7IyOixJpUZHMk9GTdFYWNsxZp8jVpfp</xenc:CipherValue>
            </xenc:CipherData>
          </EncryptedValue>
          <ValueMAC>uQ1Bef+XVXHQoW4ZzyQ/cv/9zYA=</ValueMAC>
        </Secret>
        <Counter>
          <PlainValue>0</PlainValue>
        </Counter>
      </Data>
    </Key>
  </KeyPackage>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>NagraID Security</Manufacturer>
      <SerialNo>306EUO4-00954</SerialNo>
      <Model>306E</Model>
      <IssueNo>880489CFA2CA2080</IssueNo>
    </DeviceInfo>
    <Key Id="880489CFA2CA2080"
         Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:ocra">
    <AlgorithmParameters>
       <Suite>OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1</Suite>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
    </AlgorithmParameters>
      <Data>
        <Secret>
          <EncryptedValue>
            <xenc:EncryptionMethod
                  Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
            <xenc:CipherData>
              <xenc:CipherValue>YTvA1cSntb4cPJHPFkJwuSZkAsLPo+o1EJPA22DeijZRaKhJAwArQKbwDwSmNrR1</xenc:CipherValue>
            </xenc:CipherData>
          </EncryptedValue>
          <ValueMAC>N8QGRQ7yKd8suyUgaEVme7f0HrA=</ValueMAC>
        </Secret>
        <Counter>
          <PlainValue>0</PlainValue>
        </Counter>
      </Data>
    </Key>
  </KeyPackage>
  <KeyPackage>
    <DeviceInfo>
      <Manufacturer>NagraID Security</Manufacturer>
      <SerialNo>306EUO4-00958</SerialNo>
      <Model>306E</Model>
      <IssueNo>880497B3A2CA2080</IssueNo>
    </DeviceInfo>
    <Key Id="880497B3A2CA2080"
         Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:ocra">
    <AlgorithmParameters>
        <Suite>OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1</Suite>
        <ResponseFormat Length="6" Encoding="DECIMAL"/>
    </AlgorithmParameters>
      <Data>
        <Secret>
          <EncryptedValue>
            <xenc:EncryptionMethod
                  Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
            <xenc:CipherData>
              <xenc:CipherValue>BdxW7Pb46LafGV8k2zDQ48ujoyYX7M+JumfS3Wx5dP1E9y5By/97QTMiGkzJrcWj</xenc:CipherValue>
            </xenc:CipherData>
          </EncryptedValue>
          <ValueMAC>WGhmLhbGn4Dksa7lHKfKOqbsJhU=</ValueMAC>
        </Secret>
        <Counter>
          <PlainValue>0</PlainValue>
        </Counter>
      </Data>
    </Key>
  </KeyPackage>
</KeyContainer>
        '''
        from linotp.lib.ImportOTP.PSKC import parsePSKCdata
        TOKENS = parsePSKCdata(xml,
                 preshared_key_hex="4A057F6AB6FCB57AB5408E46A9835E68",
                 do_checkserial=False)
        log.error(TOKENS)
        assert(len(TOKENS) == 3)
        assert(TOKENS.get("306EUO4-00954") != None)
        assert(TOKENS.get("306EUO4-00958") != None)
        assert(TOKENS.get("306EUO4-00960") != None)


    def test_parse_HOTP_PSKC(self):
        '''
        Test import HOTP via PSKC
        '''

        TOKENS = linotp.lib.ImportOTP.PSKC.parsePSKCdata(XML_PSKC,
                                                           do_checkserial=False)
        log.error(TOKENS)
        assert(len(TOKENS) == 6)


    def test_parse_Yubikey_CSV(self):
        '''
        Test the parsing of Yubikey CSV file
        '''
        csv = '''
        Static Password: Scan Code,17.04.12 12:25,1,051212172c092728,,,,,0,0,0,0,0,0,0,0,0,0
        Static Password: Scan Code,17.04.12 12:27,1,282828051212172c092728,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,17.04.12 12:29
        Static Password: Scan Code,17.04.12 12:29,1,2828282828051212172c092728,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 16:43
        Yubico OTP,11.12.13 16:43,1,cccccccirblh,b321173a2fb8,6faa3ce885fcd5eda7efa5195e5a5d44,,,0,0,0,0,0,0,0,0,0,1
        Yubico OTP,11.12.13 16:43,1,ccccccbgbhkl,9b19889fc5c1,11261596dbbeae6538b26ce0cfd4f9c9,,,0,0,0,0,0,0,0,0,0,1
        LOGGING START,11.12.13 18:55
        OATH-HOTP,11.12.13 18:55,1,cccccccccccc,,916821d3a138bf855e70069605559a206ba854cd,,,0,0,0,6,0,0,0,0,0,0
        LOGGING START,11.12.13 18:58
        Yubico OTP,11.12.13 18:58,1,,,a54c68c7c3d5a1fec8a0c85b8d60765b,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 19:00
        OATH-HOTP,11.12.13 19:00,1,cccccccccccc,,1390612c06ec6dd0fa077ce99bf9c86d2c058f42,,,0,0,0,6,0,0,0,0,0,0
        LOGGING START,11.12.13 19:01
        OATH-HOTP,11.12.13 19:01,1,,,d41845578effd750887edc70f04df754603e2b63,,,0,0,0,6,0,0,0,0,0,0
        LOGGING START,11.12.13 19:05
        Static Password: Scan Code,11.12.13 19:05,1,040716040416070416041607041607,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 19:06
        Static Password: Scan Code,11.12.13 19:06,1,1e1f201a1407048796,,,,,0,0,0,0,0,0,0,0,0,0
        Static Password: Scan Code,11.12.13 19:06,1,1e1f201a1407048796,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 19:07
        Static Password,11.12.13 19:07,1,,ba23877e747c,fe8abdf8c0c9b6ad6a1daabefa4d50b3,,,0,0,0,0,0,0,0,0,0,0
        Static Password,11.12.13 19:08,1,,d5a3d50327dc,0e8e37b0e38b314a56748c030f58d21d,,,0,0,0,0,0,0,0,0,0,0
        '''
        TOKENS = linotp.lib.ImportOTP.parseYubicoCSV(csv)
        print TOKENS
        print len(TOKENS)
        assert len(TOKENS) == 5

    def test_parse_XML(self):
        '''
        Test an SafeNet XML import
        '''
        xml = '''
        <Tokens>
        <Token serial="00040008CFA5">
        <CaseModel>5</CaseModel>
        <Model>101</Model>
        <ProductionDate>02/19/2009</ProductionDate>
        <ProductName>Safeword Alpine</ProductName>
        <Applications>
        <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
        <Seed>123412354</Seed>
        <MovingFactor>1</MovingFactor>
        </Application>
        </Applications>
        </Token>

        <Token serial="00040008CFA52">
        <CaseModel>5</CaseModel>
        <Model>101</Model>
        <ProductionDate>02/19/2009</ProductionDate>
        <ProductName>Safeword Alpine</ProductName>
        <Applications>
        <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
        <Seed>123456</Seed>
        <MovingFactor>1</MovingFactor>
        </Application>
        </Applications>
        </Token>

        </Tokens>

        '''
        TOKENS = linotp.lib.ImportOTP.parseSafeNetXML(xml)

        assert len(TOKENS) == 2



    def test_parse_OATH(self):
        '''
        Test an OATH csv import
        '''
        csv = '''
        tok1, 1212
        tok2, 1212, totp, 6
        tok3, 1212, hotp, 8
        tok4, 1212, totp, 8, 60
        '''
        TOKENS = linotp.lib.ImportOTP.parseOATHcsv(csv)

        assert len(TOKENS) == 4

        assert TOKENS["tok4"].get("timeStep") == 60

        assert TOKENS["tok3"].get("otplen") == 8

    def test_import_OATH(self):
        '''
        test to import token data
        '''
        csv = '''
        tok1, 1212
        tok2, 1212, totp, 6
        tok3, 1212, hotp, 8
        tok4, 1212, totp, 8, 60
        '''

        response = self.app.post(url(controller='admin', action='loadtokens'), params={'file':csv, 'type':'oathcsv'})

        assert '"imported": 4' in response

    def test_import_PSKC(self):
        '''
        Test to import PSKC data
        '''
        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':XML_PSKC,
                                         'type':'pskc',
                                         'pskc_type': 'plain',
                                         'pskc_password': "",
                                         'pskc_preshared': ""})
        print response
        assert '"imported": 6' in response

        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':XML_PSKC,
                                         'type':'pskc',
                                         'pskc_type': 'plain',
                                         'pskc_password': "",
                                         'pskc_preshared': "",
                                         'pskc_checkserial': 'true'})
        print response
        assert '"imported": 0' in response

    def test_import_empty_file(self):
        '''
        Test loading empty file
        '''
        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':"",
                                         'type':'pskc',
                                         'pskc_type': 'plain',
                                         'pskc_password': "",
                                         'pskc_preshared': ""})
        print response
        assert '"status": false' in response
        assert '"message": "Error loading tokens. File or Type empty!",' in response

    def test_import_unknown(self):
        '''
        Test to import unknown type
        '''
        response = self.app.post(url(controller='admin', action='loadtokens'),
                                 params={'file':XML_PSKC,
                                         'type':'XYZ'})
        print response
        assert '"status": false' in response
        assert 'Unknown file type' in response

    def test_import_XML(self):
        '''
        Test to import XML data
        '''
        xmls = '''
        <Tokens>
        <Token serial="00040008CFA5">
        <CaseModel>5</CaseModel>
        <Model>101</Model>
        <ProductionDate>02/19/2009</ProductionDate>
        <ProductName>Safeword Alpine</ProductName>
        <Applications>
        <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
        <Seed>123412354</Seed>
        <MovingFactor>1</MovingFactor>
        </Application>
        </Applications>
        </Token>

        <Token serial="00040008CFA52">
        <CaseModel>5</CaseModel>
        <Model>101</Model>
        <ProductionDate>02/19/2009</ProductionDate>
        <ProductName>Safeword Alpine</ProductName>
        <Applications>
        <Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
        <Seed>123456</Seed>
        <MovingFactor>1</MovingFactor>
        </Application>
        </Applications>
        </Token>

        </Tokens>
        '''
        response = self.app.post(url(controller='admin', action='loadtokens'), params={'file':xmls, 'type':'aladdin-xml'})
        assert '"imported": 2' in response
        return

    def test_import_Yubikey(self):
        '''
        Test to import Yubikey CSV
        '''
        csv = '''
        Static Password: Scan Code,17.04.12 12:25,1,051212172c092728,,,,,0,0,0,0,0,0,0,0,0,0
        Static Password: Scan Code,17.04.12 12:27,1,282828051212172c092728,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,17.04.12 12:29
        Static Password: Scan Code,17.04.12 12:29,1,2828282828051212172c092728,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 16:43
        Yubico OTP,11.12.13 16:43,1,cccccccirblh,b321173a2fb8,6faa3ce885fcd5eda7efa5195e5a5d44,,,0,0,0,0,0,0,0,0,0,1
        Yubico OTP,11.12.13 16:43,1,ccccccbgbhkl,9b19889fc5c1,11261596dbbeae6538b26ce0cfd4f9c9,,,0,0,0,0,0,0,0,0,0,1
        LOGGING START,11.12.13 18:55
        OATH-HOTP,11.12.13 18:55,1,cccccccccccc,,916821d3a138bf855e70069605559a206ba854cd,,,0,0,0,6,0,0,0,0,0,0
        LOGGING START,11.12.13 18:58
        Yubico OTP,11.12.13 18:58,1,,,a54c68c7c3d5a1fec8a0c85b8d60765b,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 19:00
        OATH-HOTP,11.12.13 19:00,1,cccccccccccc,,1390612c06ec6dd0fa077ce99bf9c86d2c058f42,,,0,0,0,6,0,0,0,0,0,0
        LOGGING START,11.12.13 19:01
        OATH-HOTP,11.12.13 19:01,1,,,d41845578effd750887edc70f04df754603e2b63,,,0,0,0,6,0,0,0,0,0,0
        LOGGING START,11.12.13 19:05
        Static Password: Scan Code,11.12.13 19:05,1,040716040416070416041607041607,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 19:06
        Static Password: Scan Code,11.12.13 19:06,1,1e1f201a1407048796,,,,,0,0,0,0,0,0,0,0,0,0
        Static Password: Scan Code,11.12.13 19:06,1,1e1f201a1407048796,,,,,0,0,0,0,0,0,0,0,0,0
        LOGGING START,11.12.13 19:07
        Static Password,11.12.13 19:07,1,,ba23877e747c,fe8abdf8c0c9b6ad6a1daabefa4d50b3,,,0,0,0,0,0,0,0,0,0,0
        Static Password,11.12.13 19:08,1,,d5a3d50327dc,0e8e37b0e38b314a56748c030f58d21d,,,0,0,0,0,0,0,0,0,0,0
        '''
        response = self.app.post(url(controller='admin', action='loadtokens'), params={'file':csv, 'type':'yubikeycsv'})
        print response
        assert '"imported": 5' in response
        return
