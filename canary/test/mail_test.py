# -*- coding: utf-8 -*-
import hashlib
import unittest

from canary import config
from canary.mail import (mail, mails, notify, remind,
                         send_verification_email)
from canary.models import Alert, Canary, User

class TestMail(unittest.TestCase):
    def setUp(self):
        self.user = User('[keyid]',
                         '[fingerprint]',
                         'foo@bar.com')
        self.canary = Canary('random_sigid', 3, 'day')
        self.canary.user_id = self.user.id
        self.alert = Alert(
            self.user.uid, self.canary, True, True, True, 3, 'sekrit')

    def test_notify(self):
        """Test that the notify function sends emails that include the
        correct information.
        """
        with mail.record_messages() as outbox:
            u = self.user
            c = self.canary
            notify(c, u, 'test')

            body = outbox[0].body
            self.assertEqual(outbox[0].subject, mails['new_canary'][0])
            self.assertEqual(len(outbox), 1)
            self.assertTrue(u.uid in outbox[0].recipients)

            fake_canary_url = '{}/canary/{}'.format(
                config.URL, c.sigid_base64)
            inbody = [u.keyid, str(c.frequency), c.freq_type, 'test',
                      fake_canary_url,]

            for item in inbody:
                self.assertIn(item, body)

    def test_remind(self):
        """Test that the remind function sends emails that include the
        correct information.
        """
        with mail.record_messages() as outbox:
            u = self.user
            c = self.canary
            remind(c, u)

            body = outbox[0].body
            self.assertEqual(outbox[0].subject, mails['reminder'][0])
            self.assertEqual(len(outbox), 1)
            self.assertTrue(u.uid in outbox[0].recipients)
            self.assertFalse(c.active)

            fake_canary_url = config.URL + '/canary/{}'.format(
                c.sigid_base64)
            inbody = str(c.frequency), c.freq_type, fake_canary_url,

            for item in inbody:
                self.assertIn(item, body)

    def test_verify(self):
        """Test that the verify function sends emails that include the
        correct information.
        """
        with mail.record_messages() as outbox:
            a = self.alert
            c = self.canary

            send_verification_email(a, c)
            body = outbox[0].body
            self.assertEqual(
                outbox[0].subject, mails['verify_watch_canary'][0])
            self.assertEqual(len(outbox), 1)
            self.assertTrue(a.email in outbox[0].recipients)

            fake_canary_url = '{}/canary/{}'.format(
                config.URL, c.sigid_base64)
            fake_verify_url = '{}/verify/{}?canary={}?email={}'.format(
                config.URL, a.hash, c.id, a.email)

            inbody = fake_verify_url, fake_canary_url
            for item in inbody:
                self.assertIn(item, body)

if __name__ == '__main__':
    unittest.main()
