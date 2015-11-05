# -*- coding: utf-8 -*-
import inspect
import os
import unittest

from canary.messages import err_messages
from canary.gpg import gpg

d = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))

class TestGpg(unittest.TestCase):
    def setUp(self):
        self.fp = '2fa69032cba961ff8387ef06d2969d08c2dfb998'
        self.keyid = 'C2DFB998'
        self.files = os.path.join(d, 'files')

    def test_receive_keys(self):
        """Test that the keys can be retrieved from the default
        keyserver."""
        num_keys = len(gpg.keys())
        err = gpg.recv_keys('FAE962A1')
        self.assertTrue(err is None)
        self.assertEqual(len(gpg.keys()), num_keys + 1)
        gpg.delete_keys('096BA9B75722C367783BDD257F504009FAE962A1')

    def test_encrypt(self):
        """Test the encrypt function"""
        ciphertext = gpg.encrypt('test', self.fp)
        self.assertIn('-----BEGIN PGP MESSAGE-----', str(ciphertext))

    def test_verify_valid_signature(self):
        """Test verifying a message with a valid signature."""
        f = open(os.path.join(self.files, 'valid.sig'))
        valid = f.read()
        f.close()

        verified, _ = gpg.verify(valid)
        self.assertTrue(verified)

    def test_verify_invalid_signature(self):
        """Test verifying messages with invalid signatures."""
        f = open(os.path.join(self.files, 'invalid.sig'))
        invalid = f.read()
        f.close()

        verified, err_msg = gpg.verify('notasignedmessage')
        self.assertFalse(verified)
        self.assertEqual(err_msg, err_messages['not_signed'])

        verified, err_msg = gpg.verify(invalid)
        self.assertFalse(verified)
        self.assertEqual(err_msg, err_messages['invalid_sig'])

    def test_have_key(self):
        """Test that we can check for a key in the public keyring by
        keyid or fingerprint.
        """
        self.assertTrue(gpg.have_key(keyid=self.keyid))
        self.assertTrue(gpg.have_key(fingerprint=self.fp))
        self.assertFalse(gpg.have_key(keyid='notakeyid'))

if __name__ == '__main__':
    unittest.main()
