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
     This file contains some tests, which should become
     part of the functional tests
"""

from unittest import TestCase
from linotp.lib.pbkdf2 import pbkdf2
from linotp.lib.utils import config_get
from linotp.lib.ImportOTP.PSKC import parsePSKCdata
from linotp.lib.ImportOTP.DPWplain import parseDPWdata

import binascii
import tempfile



class PBKDF2(TestCase):

	def test_pbkdf(self):
		'''
		Test password based key derivation function
		'''
		expected_key = { 1000: "979d33c5e39bf7fc20ef",
						 10: "3c28a7f09aa19108a17d",
						 100: "303155b866685ad279fa" }
		for key_length in expected_key.keys():
			key = binascii.hexlify(pbkdf2("my password", "salt", 10, key_length))
			print key, expected_key[key_length]
			assert key == expected_key[key_length]


class TestUtils(TestCase):

	def test_get_config(self):
		'''
		Test get_config
		'''
		ini_file = '''
[section1]
key1 = value1
key2 = value2
[section2]
key3 = value3
'''
		t = tempfile.NamedTemporaryFile(delete=False)

		t.write(ini_file)
		t.close()
		print "section1,key1:", config_get("section1", "key1", ini_file=t.name)
		assert config_get("section1", "key1", ini_file=t.name) == "value1"
		assert config_get("section1", "key2", ini_file=t.name) == "value2"
		assert config_get("section2", "key3", ini_file=t.name) == "value3"
		assert config_get("section3", "key4", default="Hallo", ini_file=t.name) == "Hallo"
		assert config_get("section2", "key4", default="Bubu", ini_file=t.name) == "Bubu"


class TestPSKC(TestCase):

	XML1 = '''<?xml version="1.0" encoding="UTF-8"?>
	   <KeyContainer Version="1.0"
	       Id="exampleID1"
	       xmlns="urn:ietf:params:xml:ns:keyprov:pskc">
	       <KeyPackage>
	           <DeviceInfo>
	               <Manufacturer>Manufacturer</Manufacturer>
	               <SerialNo>987654321</SerialNo>
	               <UserId>DC=example-bank,DC=net</UserId>
	           </DeviceInfo>
	           <CryptoModuleInfo>
	               <Id>CM_ID_001</Id>
	           </CryptoModuleInfo>
	           <Key Id="12345678"
	               Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
	               <Issuer>Issuer</Issuer>
	               <AlgorithmParameters>
	                   <ResponseFormat Length="8" Encoding="DECIMAL"/>
	               </AlgorithmParameters>
	               <Data>
	                   <Secret>
	                       <PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
	                       </PlainValue>
	                   </Secret>
	                   <Counter>
	                       <PlainValue>0</PlainValue>
	                   </Counter>
	               </Data>
	               <UserId>UID=jsmith,DC=example-bank,DC=net</UserId>
	           </Key>
	       </KeyPackage>
	   </KeyContainer>
	   '''


	XML2 = '''<?xml version="1.0" encoding="UTF-8"?>
	   <KeyContainer Version="1.0"
	       Id="exampleID1"
	       xmlns="urn:ietf:params:xml:ns:keyprov:pskc">
	       <KeyPackage>
	           <DeviceInfo>
	               <Manufacturer>Manufacturer</Manufacturer>
	               <SerialNo>987654321</SerialNo>
	               <UserId>DC=example-bank,DC=net</UserId>
	           </DeviceInfo>
	           <CryptoModuleInfo>
	               <Id>CM_ID_001</Id>
	           </CryptoModuleInfo>
	           <Key Id="ABCD12345678"
	               Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
	               <Issuer>Issuer</Issuer>
	               <AlgorithmParameters>
	                   <ResponseFormat Length="8" Encoding="DECIMAL"/>
	               </AlgorithmParameters>
	               <Data>
	                   <Secret>
	                       <PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
	                       </PlainValue>
	                   </Secret>
	                   <Counter>
	                       <PlainValue>0</PlainValue>
	                   </Counter>
	               </Data>
	               <UserId>UID=jsmith,DC=example-bank,DC=net</UserId>
	           </Key>
	       </KeyPackage>
	       <KeyPackage>
	           <DeviceInfo>
	               <Manufacturer>Manufacturer</Manufacturer>
	               <SerialNo>987654321</SerialNo>
	               <UserId>DC=example-bank,DC=net</UserId>
	           </DeviceInfo>
	           <CryptoModuleInfo>
	               <Id>CM_ID_001</Id>
	           </CryptoModuleInfo>
	           <Key Id="A1C212345678"
	               Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
	               <Issuer>Issuer</Issuer>
	               <AlgorithmParameters>
	                   <ResponseFormat Length="8" Encoding="DECIMAL"/>
	               </AlgorithmParameters>
	               <Data>
	                   <Secret>
	                       <PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
	                       </PlainValue>
	                   </Secret>
	                   <Counter>
	                       <PlainValue>0</PlainValue>
	                   </Counter>
	               </Data>
	               <UserId>UID=jsmith,DC=example-bank,DC=net</UserId>
	           </Key>
	       </KeyPackage>
	   </KeyContainer>
	   '''

	XML3 = '''<?xml version="1.0" encoding="UTF-8"?>
 <KeyContainer Version="1.0"
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
                 <xenc:CipherValue>
     ESIzRFVmd4iZABEiM0RVZgKn6WjLaTC1sbeBMSvIhRejN9vJa2BOlSaMrR7I5wSX
                 </xenc:CipherValue>
             </xenc:CipherData>
         </MACKey>
     </MACMethod>
     <KeyPackage>
         <DeviceInfo>
             <Manufacturer>Manufacturer</Manufacturer>
             <SerialNo>987654321</SerialNo>
         </DeviceInfo>
         <CryptoModuleInfo>
         			 <Id>CM_ID_001</Id>
		 </CryptoModuleInfo>
		 <Key Id="12345678"
			 Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
			 <Issuer>Issuer</Issuer>
			 <AlgorithmParameters>
				 <ResponseFormat Length="8" Encoding="DECIMAL"/>
			 </AlgorithmParameters>
			 <Data>
				 <Secret>
					 <EncryptedValue>
						 <xenc:EncryptionMethod
			 Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
						 <xenc:CipherData>
							 <xenc:CipherValue>
	 AAECAwQFBgcICQoLDA0OD+cIHItlB3Wra1DUpxVvOx2lef1VmNPCMl8jwZqIUqGv
							 </xenc:CipherValue>
						 </xenc:CipherData>
					 </EncryptedValue>
					 <ValueMAC>Su+NvtQfmvfJzF6bmQiJqoLRExc=
					 </ValueMAC>
				 </Secret>
				 <Counter>
					 <PlainValue>0</PlainValue>
				 </Counter>
			 </Data>
		 </Key>
	 </KeyPackage>
 </KeyContainer>'''

  	XML4 = '''<?xml version="1.0" encoding="UTF-8"?>
  <pskc:KeyContainer
    xmlns:pskc="urn:ietf:params:xml:ns:keyprov:pskc"
    xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"
    xmlns:pkcs5=
    "http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#"
    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Version="1.0">
      <pskc:EncryptionKey>
          <xenc11:DerivedKey>
              <xenc11:KeyDerivationMethod
                Algorithm=
   "http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2">
                  <pkcs5:PBKDF2-params>
                      <Salt>
                          <Specified>Ej7/PEpyEpw=</Specified>
                      </Salt>
                      <IterationCount>1000</IterationCount>
                      <KeyLength>16</KeyLength>
                      <PRF/>
                  </pkcs5:PBKDF2-params>
              </xenc11:KeyDerivationMethod>
              <xenc:ReferenceList>
                  <xenc:DataReference URI="#ED"/>
              </xenc:ReferenceList>
              <xenc11:MasterKeyName>My Password 1</xenc11:MasterKeyName>
          </xenc11:DerivedKey>
      </pskc:EncryptionKey>
      <pskc:MACMethod
          Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
          <pskc:MACKey>
              <xenc:EncryptionMethod
              Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
              <xenc:CipherData>
                  <xenc:CipherValue>
  2GTTnLwM3I4e5IO5FkufoOEiOhNj91fhKRQBtBJYluUDsPOLTfUvoU2dStyOwYZx
                  </xenc:CipherValue>
              </xenc:CipherData>
          </pskc:MACKey>
      </pskc:MACMethod>
      <pskc:KeyPackage>
          <pskc:DeviceInfo>
              <pskc:Manufacturer>TokenVendorAcme</pskc:Manufacturer>
              <pskc:SerialNo>987654321</pskc:SerialNo>
          </pskc:DeviceInfo>
          <pskc:CryptoModuleInfo>
              <pskc:Id>CM_ID_001</pskc:Id>
          </pskc:CryptoModuleInfo>
          <pskc:Key Algorithm=		  "urn:ietf:params:xml:ns:keyprov:pskc:hotp" Id="123456">
			  <pskc:Issuer>Example-Issuer</pskc:Issuer>
			  <pskc:AlgorithmParameters>
				  <pskc:ResponseFormat Length="8" Encoding="DECIMAL"/>
			  </pskc:AlgorithmParameters>
			  <pskc:Data>
				  <pskc:Secret>
				  <pskc:EncryptedValue Id="ED">
					  <xenc:EncryptionMethod
						  Algorithm=
  "http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
						  <xenc:CipherData>
							  <xenc:CipherValue>
		oTvo+S22nsmS2Z/RtcoF8Hfh+jzMe0RkiafpoDpnoZTjPYZu6V+A4aEn032yCr4f
						  </xenc:CipherValue>
					  </xenc:CipherData>
					  </pskc:EncryptedValue>
					  <pskc:ValueMAC>LP6xMvjtypbfT9PdkJhBZ+D6O4w=
					  </pskc:ValueMAC>
				  </pskc:Secret>
			  </pskc:Data>
		  </pskc:Key>
	  </pskc:KeyPackage>
  </pskc:KeyContainer>'''

	def test_01_xml1(self):
		'''
		testing import PSKC #1 -- no valid OATH serial
		'''
		res = parsePSKCdata(self.XML1)
		print res
		assert res == {}

	def test_02_xml1(self):
		'''
		testing import PSKC #1 -- ignore OATH serial
		'''
		res = parsePSKCdata(self.XML1, 	do_checkserial=False)
		print res
		assert len(res) == 1
		assert res.get('12345678')
		assert res.get('12345678').get('otplen') == 8
		assert res.get('12345678').get('hmac_key') == '3132333435363738393031323334353637383930'

	def test_03_xml2(self):
		'''
		testing import PSKC #2 -- 2 valid OATH serials
		'''
		res = parsePSKCdata(self.XML2)
		print res
		assert len(res) == 2

	def test_04_preshared_key(self):
		'''
		testing import PSKC #3 -- preshared key
		'''
		res = parsePSKCdata(self.XML3, preshared_key_hex="12345678901234567890123456789012", do_checkserial=False)
		print res
		assert res.get('12345678').get('hmac_key') == "3132333435363738393031323334353637383930"

	def test_05_password_based(self):
		'''
		testing import PSKC #4 -- password based encryption
		'''
		res = parsePSKCdata(self.XML4, password="qwerty", do_checkserial=False)
		print res
		assert res.get('123456').get('hmac_key') == "3132333435363738393031323334353637383930"


class TestDPWImport(TestCase):

	DPW = '''dpw123456	12121212121212
dpw23456789		3434343434343434'''

	def test_01_Import(self):
		'''
		testing import of day password tokens
		'''
		res = parseDPWdata(self.DPW)
		print res
		assert len(res) == 2
		assert res.get("dpw23456789").get("hmac_key") == "3434343434343434"
		assert res.get("dpw123456").get("hmac_key") == "12121212121212"

