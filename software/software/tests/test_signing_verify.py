#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import mock_open
from unittest.mock import MagicMock
from unittest.mock import patch
import tempfile
import os
import unittest
from software.tests import base  # noqa: F401
from software.release_signing import sign_files
from software.release_verify import verify_hash
from software.release_verify import get_public_certificates_by_type
from software.release_verify import get_public_certificates
from software.release_verify import read_RSA_key
from software.release_verify import verify_files


class TestSignFiles(unittest.TestCase):
    @patch('software.release_signing.PKCS1_PSS')
    @patch('software.release_signing.SHA256')
    @patch('software.release_signing.release_verify')
    def test_sign_with_provided_key(self, _mock_rv, mock_sha, mock_pss):
        mock_hash = MagicMock()
        mock_sha.new.return_value = mock_hash
        mock_signer = MagicMock()
        mock_signer.sign.return_value = b'sig'
        mock_pss.new.return_value = mock_signer
        key = MagicMock()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'data')
            fname = f.name
        sig_file = fname + '.sig'
        try:
            result = sign_files([fname], sig_file, private_key=key)
            self.assertFalse(result)
            self.assertTrue(os.path.exists(sig_file))
        finally:
            os.unlink(fname)
            if os.path.exists(sig_file):
                os.unlink(sig_file)

    @patch('software.release_signing.os.path.exists', return_value=True)
    @patch('software.release_signing.PKCS1_PSS')
    @patch('software.release_signing.SHA256')
    @patch('software.release_signing.release_verify')
    @patch('builtins.open', mock_open(read_data=b'data'))
    def test_sign_with_cert_type(
            self,
            mock_rv,
            mock_sha,
            mock_pss,
            _mock_exists):
        mock_hash = MagicMock()
        mock_sha.new.return_value = mock_hash
        mock_signer = MagicMock()
        mock_signer.sign.return_value = b'sig'
        mock_pss.new.return_value = mock_signer
        mock_rv.cert_type_dev_str = 'dev'
        mock_rv.cert_type_formal_str = 'formal'
        mock_rv.read_RSA_key.return_value = MagicMock()
        result = sign_files(['f1'], 'sig', cert_type='dev')
        self.assertFalse(result)

    @patch('software.release_signing.os.path.exists')
    @patch('software.release_signing.PKCS1_PSS')
    @patch('software.release_signing.SHA256')
    @patch('software.release_signing.release_verify')
    @patch('builtins.open', mock_open(read_data=b'data'))
    def test_sign_formal_fallback_to_dev(
            self, mock_rv, mock_sha, mock_pss, mock_exists):
        mock_hash = MagicMock()
        mock_sha.new.return_value = mock_hash
        mock_signer = MagicMock()
        mock_signer.sign.return_value = b'sig'
        mock_pss.new.return_value = mock_signer
        mock_rv.cert_type_dev_str = 'dev'
        mock_rv.cert_type_formal_str = 'formal'
        mock_rv.read_RSA_key.return_value = MagicMock()
        # formal key doesn't exist, dev key does
        mock_exists.side_effect = lambda path: 'dev' in path
        result = sign_files(['f1'], 'sig', cert_type='formal')
        self.assertTrue(result)  # need_resign_with_formal

    @patch('software.release_signing.os.path.exists', return_value=True)
    @patch('software.release_signing.PKCS1_PSS')
    @patch('software.release_signing.SHA256')
    @patch('software.release_signing.release_verify')
    @patch('builtins.open', mock_open(read_data=b'data'))
    def test_sign_search_keys(self, mock_rv, mock_sha, mock_pss, _mock_exists):
        mock_hash = MagicMock()
        mock_sha.new.return_value = mock_hash
        mock_signer = MagicMock()
        mock_signer.sign.return_value = b'sig'
        mock_pss.new.return_value = mock_signer
        mock_rv.cert_type_dev_str = 'dev'
        mock_rv.cert_type_formal_str = 'formal'
        mock_rv.read_RSA_key.return_value = MagicMock()
        result = sign_files(['f1'], 'sig')  # no cert_type, no key
        self.assertFalse(result)


class TestVerifyHash(unittest.TestCase):
    @patch('software.release_verify.PKCS1_v1_5')
    @patch('software.release_verify.PKCS1_PSS')
    def test_pss_verify_success(self, mock_pss, _mock_v15):
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True
        mock_pss.new.return_value = mock_verifier
        with patch('software.release_verify.RSA') as mock_rsa:
            mock_key = MagicMock()
            mock_rsa.importKey.return_value = mock_key
            result = verify_hash(MagicMock(), b'sig', [b'cert'])
        self.assertTrue(result)

    @patch('software.release_verify.PKCS1_v1_5')
    @patch('software.release_verify.PKCS1_PSS')
    def test_v15_fallback(self, mock_pss, mock_v15):
        mock_pss_v = MagicMock()
        mock_pss_v.verify.side_effect = ValueError("bad")
        mock_pss.new.return_value = mock_pss_v
        mock_v15_v = MagicMock()
        mock_v15_v.verify.return_value = True
        mock_v15.new.return_value = mock_v15_v
        with patch('software.release_verify.RSA') as mock_rsa:
            mock_rsa.importKey.return_value = MagicMock()
            result = verify_hash(MagicMock(), b'sig', [b'cert'])
        self.assertTrue(result)


class TestGetPublicCertificates(unittest.TestCase):
    def test_by_type_formal(self):
        certs = get_public_certificates_by_type(cert_type=['formal'])
        self.assertEqual(len(certs), 1)

    def test_by_type_all(self):
        certs = get_public_certificates_by_type()
        self.assertEqual(len(certs), 2)

    @patch('software.release_verify.os.path.exists', return_value=False)
    def test_get_public_no_dev_marker(self, _mock_exists):
        certs = get_public_certificates()
        self.assertEqual(len(certs), 1)

    @patch('software.release_verify.verify_hash', return_value=True)
    @patch('software.release_verify.SHA256')
    @patch('builtins.open', mock_open(read_data=b'sig'))
    @patch('software.release_verify.os.path.exists', return_value=True)
    def test_get_public_with_dev_marker(self, _mock_exists, _mock_sha, _mock_vh):
        certs = get_public_certificates()
        self.assertEqual(len(certs), 2)


class TestReadRSAKey(unittest.TestCase):
    @patch('software.release_verify.RSA')
    def test_direct_import(self, mock_rsa):
        mock_rsa.importKey.return_value = MagicMock()
        key = read_RSA_key(b'key_data')
        self.assertIsNotNone(key)

    @patch('software.release_verify.RSA')
    @patch('software.release_verify.DerSequence')
    def test_x509_fallback(self, mock_der, mock_rsa):
        mock_rsa.importKey.side_effect = [ValueError("bad"), MagicMock()]
        mock_seq = MagicMock()
        mock_seq.__getitem__ = MagicMock(return_value=b'data')
        mock_der.return_value = mock_seq
        key = read_RSA_key('BEGIN CERT aaaa END CERT')
        self.assertIsNotNone(key)


class TestVerifyFiles(unittest.TestCase):
    @patch('software.release_verify.verify_hash', return_value=True)
    @patch('software.release_verify.get_public_certificates',
           return_value=[b'cert'])
    @patch('software.release_verify.SHA256')
    @patch('builtins.open', mock_open(read_data=b''))
    def test_verify_files(self, mock_sha, _mock_certs, _mock_vh):
        mock_sha.new.return_value = MagicMock()
        result = verify_files(['f1'], 'sig')
        self.assertTrue(result)
