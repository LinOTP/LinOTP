import unittest
import os
from mock import patch
from M2Crypto import EVP, RSA
from linotp.lib.audit.SQLAudit import Audit, getAsString

this_directory = os.path.dirname(os.path.realpath(__file__))
public_key_file = "%s/keys/public.pem" % this_directory
private_key_file = "%s/keys/private.pem" % this_directory

mocked_signature=u"ac67a5392361b92d43f904e7a6c375d9de432d415a86e981a20f4c0f9f3544f577707b96a9536415d16688110a51eec0075a6c9d95f711131e2859d29f483e717fc782ce53c03f12267042b57f831298e3d52fcd595a5e3943c5699ca0fc938bc8b238fe4c91c41ac163b25976844f98b3e5d873bfeb270e0c789a3ad4d8a8083fe39e634c6e5dca78265ea442b970f356eb12aeca4065d07eb368894591c17f21ae9d566be223f19ff50cab3c7ba5aa55ea1d15b9088af8d0e452a2ab46b780c9002a04c6438375a3dd37dbeaaffb06c291fbe8805186798116fff84eaf4c68679bd92fd3ce1b9dc323398c7c7e0edfc9a8a6739cb2a43a381e5b838ad2e09e"


class MockedAuditLine:

    def __init__(self):
        self.id = u""
        self.timestamp = u""
        self.serial = u""
        self.action = u""
        self.action_detail = u""
        self.success = u""
        self.tokentype = u""
        self.user = u""
        self.realm = u""
        self.administrator = u""
        self.action_detail = u""
        self.info = u""
        self.linotp_server = u""
        self.client = u""
        self.log_level = u""
        self.clearance_level = u""
        self.signature = mocked_signature


class MockedAudit(Audit):

    def __init__(self):
        self.private = open(private_key_file, 'rb').read()
        self.public = open(public_key_file, 'rb').read()

        self.PublicKey = RSA.load_pub_key(public_key_file)
        self.VerifyEVP = EVP.PKey()
        self.VerifyEVP.reset_context(md='sha256')
        self.VerifyEVP.assign_rsa(self.PublicKey)
    
    @staticmethod
    def mocked_getAsString_with_wrong_unintended_utf8_convertion(line):
        return getAsString(line).encode('utf-8')


class TestAuditSignatureCase(unittest.TestCase):
    def setUp(self):
        self.audit = MockedAudit()

    def test_signature_sign(self):
        line = MockedAuditLine()
        signature = self.audit._sign(audit_line=line)
        assert signature == mocked_signature

    def test_signature_row2dcit(self):
        line = MockedAuditLine()
        res = self.audit.row2dict(audit_line=line)
        assert res['sig_check'] == 'OK'

    def test_sign_and_verify(self):
        line = MockedAuditLine()
        signature = self.audit._sign(audit_line=line)
        line.signature = signature
        res = self.audit.row2dict(audit_line=line)
        assert res['sig_check'] == 'OK'

    @patch("linotp.lib.audit.SQLAudit.getAsString", MockedAudit.mocked_getAsString_with_wrong_unintended_utf8_convertion)
    def test_signature_with_wrong_unintended_utf8_convertion(self):
        line = MockedAuditLine()
        signature = self.audit._sign(audit_line=line)
        assert signature != mocked_signature