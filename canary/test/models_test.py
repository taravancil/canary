# -*- coding: utf-8 -*-
from hashlib import sha256
import os
import unittest

from canary import app
from canary.db import db_session, init_db
from canary.models import Challenge, User

class TestModels(unittest.TestCase):
    def setUp(self):
        init_db()
        self.user = User('C2DFB998',
                         '2fa69032cba961ff8387ef06d2969d08c2dfb998',
                         'Foo Bar <foo@bar.com>')
        self.sekrit = os.urandom(16).encode('hex')
        self.chal = Challenge(sha256(self.sekrit).hexdigest())
        db_session.add(self.user)
        db_session.add(self.chal)
        db_session.commit()

    def tearDown(self):
        db_session.remove()
        os.unlink(app.config.get('DATABASE_FILE'))

    def test_update_user(self):
        """Test that the update function works properly"""
        self.user.uid = 'old'

        # Update to original value
        self.user.update('Test User <test@test.com>')
        self.assertNotEqual(self.user.uid, 'old')

    def test_generate_challenge(self):
        """Test generating a challenge."""
        chal = str(Challenge.generate(self.user, self.user.fingerprint))
        self.assertIn('-----BEGIN PGP MESSAGE-----', chal)
        self.assertIn('-----END PGP MESSAGE-----', chal)
        chals = Challenge.query.all()
        self.assertEqual(self.user.chal_id, chals[1].id)

    def test_check_valid_challenge(self):
        """Test that submitting a valid challenge solution succeeds."""
        self.user.chal_id = self.chal.id
        self.assertTrue(Challenge.check(self.user, self.sekrit))

    def test_check_invalid_challenge(self):
        """Test that submitting an invalid challenge solution fails."""
        self.user.chal_id = self.chal.id
        self.assertFalse(Challenge.check(self.user, '0' * 32))

    def test_check_invalid_challenge_format(self):
        """Test that submitting an incorrectly-formatted solution fails.
        """
        self.user.chal_id = self.chal.id
        self.assertFalse(Challenge.check(self.user, '<#(!--'))

if __name__ == '__main__':
    unittest.main()
