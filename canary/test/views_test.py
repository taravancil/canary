# -*- coding: utf-8 -*-
import inspect
import os
import unittest

from flask import session
from bs4 import BeautifulSoup

from canary import app
from canary import config
from canary.db import db_session, init_db
from canary.gpg import gpg
from canary.messages import messages, err_messages
from canary.models import Alert, Canary, User
from canary.utils import list_routes

d = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))

class TestViews(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        init_db()

        self.files = os.path.join(d, 'files')
        self.canaries_dir = app.config.get('CANARIES_DIR')
        self.fp = '2fa69032cba961ff8387ef06d2969d08c2dfb998'
        f = open(os.path.join(self.files, 'valid.sig'))
        self.valid_msg = f.read()
        f.close()

    def tearDown(self):
        db_session.remove()
        os.unlink(app.config.get('DATABASE_FILE'))

        # Delete canaries in self.canaries_dir
        for dir, _, files in os.walk(self.canaries_dir):
            for f in files:
                os.unlink(os.path.join(dir, f))

    def _submit_message(self, msg, frequencyNum=1, freq_type='day'):
        """Helper for posting a valid signed message to /new."""
        return self.app.post('/new', data=dict(
            signedMessage=msg,
            frequencyNum=frequencyNum,
            frequency=freq_type
        ))

    def _create_user(self):
        """Helper for creating a user."""
        u = User('C2DFB998', self.fp, 'Foo Bar <foo@bar.com>')
        db_session.add(u)
        db_session.commit()
        return u

    def _create_canary(self):
        """Helper for creating a canary."""
        with self.app as a:
            r = self._submit_message(self.valid_msg)
            sigid = session['canary']['sigid_base64']
            canary_url = '/canary/' + sigid

            r = a.post(
                canary_url,
                data=dict(decrypted=self._decrypt_challenge(r.data)),
                follow_redirects=True)

        return Canary.query.filter(Canary.sigid_base64 == sigid).one()

    def _decrypt_challenge(self, data):
        """Returns the value of the secret challenge."""
        soup = BeautifulSoup(data, 'html.parser')
        ciphertext = soup.pre.string
        return str(gpg.decrypt(ciphertext, 'test'))

    def _login(self):
        """Helper for logging in."""
        with self.app.session_transaction() as s:
            s['fp'] = self.fp
            s['uid'] = 1

    def test_request_methods(self):
        """Test the allowed methods for each route."""
        gets = list_routes('GET')
        posts = list_routes('POST')
        no_posts = '/', 'about', 'faq', '/canaries'

        for route in gets:
            r = self.app.get(route, follow_redirects=True)
            self.assertEqual(r.status_code, 200)

        for route in posts:
            r = self.app.post(route, follow_redirects=True)
            """Response can be 400 Bad Request since we don't send any
            data in the request."""
            self.assertTrue(r.status_code == 200 or r.status_code == 400)

        for route in no_posts:
            r = self.app.post(route, follow_redirects=True)
            self.assertEqual(r.status_code, 405)

        # Test that PUT, DELETE are forbidden
        for route in list_routes():
            r = self.app.delete(route)
            self.assertEqual(r.status_code, 405)
            r = self.app.put(route)
            self.assertEqual(r.status_code, 405)

    def test_index(self):
        """Test that the main page loads as expected."""
        r = self.app.get('/')
        self.assertIn(config.INTRO_TEXT, r.data)

    def test_404(self):
        """Test that the 404 page works."""
        r = self.app.get('/canary/xyz')
        self.assertEqual(r.status_code, 404)
        self.assertIn('Page Not Found', r.data)
        self.assertNotIn('Try these instead', r.data)

    def test_custom_404(self):
        """Test that the customized 404 page lists the correct URLs
        when the database is populated with Users and Canaries.
        """
        with self.app as a:
            """Submit a canary so there will be links to suggest on
            the 404 page."""
            r1 = self._submit_message(self.valid_msg)
            sigid_base64 = session['canary']['sigid_base64']
            url = '/canary/' + session['canary']['sigid_base64']

            a.post(url,
                   data=dict(decrypted=self._decrypt_challenge(r1.data)),
                   follow_redirects=True)
            r = a.get('/canary/xyz')
            self.assertIn('Page Not Found', r.data)
            self.assertIn('Try these instead', r.data)
            self.assertIn('/canary/{}'.format(sigid_base64), r.data)

    def test_submit_valid_signed_message(self):
        """Test submitting a valid signed message."""
        r = self._submit_message(self.valid_msg)
        self.assertIn(messages['verified'], r.data)

    def test_submit_invalid_signed_message(self):
        """Test submitting an invalid signed message."""
        r = self._submit_message('Not a PGP-signed message.')
        self.assertIn(err_messages['not_signed'], r.data)

        # Submit a signed message that's been modified.
        f = open(os.path.join(self.files, 'invalid.sig'))
        invalid_msg = f.read()
        f.close()
        r = self._submit_message(invalid_msg)
        self.assertIn(err_messages['invalid_sig'], r.data)

    def test_submit_message_missing_data(self):
        """Test submitting a valid message with invalid data."""
        default_args = [self.valid_msg, 1, 'day']
        for i in range(0, 3):
            args = default_args
            args[i] = None
            r = self._submit_message(*args)
            self.assertIn(err_messages['incomplete_form'], r.data)

    def test_submit_invalid_freq(self):
        """Test submitting invalid frequency data when submitting a new
        canary.
        """
        r = self._submit_message(self.valid_msg, -1, 'data')
        self.assertIn(err_messages['invalid_freq'], r.data)
        r = self._submit_message(self.valid_msg, 1, 'eon')
        self.assertIn(err_messages['invalid_freq'], r.data)

    def test_decrypt_success_publish_canary(self):
        """Test that decrypting the secret creates a new Canary."""
        with self.app as a:
            r1 = self._submit_message(self.valid_msg)
            sigid = session['canary']['sigid_base64']
            url = '/canary/' + sigid
            canary_file = os.path.join(self.canaries_dir, sigid)

            r = a.post(url,
                       data=dict(decrypted=self._decrypt_challenge(r1.data)),
                       follow_redirects=True)

            self.assertIn(messages['published'], r.data)
            self.assertEqual(db_session.query(Canary).count(), 1)

            # Check that the canary is in the filesystem
            self.assertTrue(os.path.isfile(canary_file))
            self.assertIn(self.valid_msg, open(canary_file).read())

    def test_decrypt_fail_publish_canary(self):
        """Test that submitting an invalid secret displays an error
        message and does not post a new Canary.
        """
        with self.app as a:
            self._submit_message(self.valid_msg)
            sigid = session['canary']['sigid_base64']
            canary_file = os.path.join(self.canaries_dir, sigid)

            r = a.post('/canary/{}'.format(sigid),
                       data={'decrypted': 'incorrect'},
                       follow_redirects=True)

            self.assertIn(err_messages['decrypt_fail'], r.data)
            self.assertEqual(db_session.query(Canary).count(), 0)
            self.assertFalse(os.path.isfile(canary_file))

    def test_logout(self):
        """Test that logging out edits the session appropriately."""
        with self.app as a:
            self._login()
            r = a.post('/logout', follow_redirects=True)
            self.assertFalse('uid' in session)
            self.assertFalse('fp' in session)
            self.assertIn(config.INTRO_TEXT, r.data)

    def test_login(self):
        """Test that logging in with a valid challenge succeeds."""
        with self.app as a:
            u = self._create_user()
            fp = u.fingerprint
            r1 = a.post('/login', data={'fingerprint': fp})
            r2 = a.post('/login/{}'.format(fp),
                        data={'decrypted': self._decrypt_challenge(r1.data)},
                        follow_redirects=True)
            self.assertIn('Logout', r2.data)
            self.assertTrue('uid' in session)
            self.assertEqual(session['fp'], fp)

    def test_login_uppercase_fingerprint(self):
        """Test logging in with an uppercase fingerprint."""
        with self.app as a:
            u = self._create_user()
            fp = u.fingerprint.upper()
            r1 = a.post('/login', data={'fingerprint': fp})
            r2 = a.post('/login/{}'.format(u.fingerprint),
                       data= {'decrypted': self._decrypt_challenge(r1.data)},
                       follow_redirects=True)
            self.assertIn('Logout', r2.data)
            self.assertTrue('uid' in session)
            # The fingerprint stored in the session should be lowercase
            self.assertEqual(session['fp'], self.fp)
            self.assertEqual(session['uid'], u.id)

    def test_login_invalid_secret(self):
        """Test that logging in with an invalid challenge fails."""
        with self.app as a:
            u = self._create_user()
            s = '0' * 32

            a.post('/login', data={'fingerprint': u.fingerprint})
            r = a.post('/login/{}'.format(u.fingerprint),
                       data={'decrypted': s},
                       follow_redirects=True)

            self.assertIn(err_messages['decrypt_fail'], r.data)
            self.assertFalse('uid' in session)

    def test_login_invalid_secret_format(self):
        """Test that logging in with a challenge that isn't the
        expected format fails.
        """
        with self.app as a:
            u = self._create_user()
            a.post('/login', data={'fingerprint': u.fingerprint})
            r = a.post('/login/{}'.format(u.fingerprint),
                       data={'decrypted': 'xyz@<*!'},
                       follow_redirects=True)

            self.assertIn(err_messages['decrypt_fail'], r.data)
            self.assertFalse('uid' in session)

    def test_login_invalid_fingerprint(self):
        """Test that logging in with an invalid fingerprint displays an
        error message.
        """
        invalid = ['test', '123']
        for fp in invalid:
            r = self.app.post('/login',
                              data=dict(fingerprint=fp),
                              follow_redirects=True)
            self.assertIn(err_messages['not_fp'], r.data)

    def test_login_valid_fingerprint(self):
        """Test that logging in with a valid fingerprint that's in the
        keyring and the database displays a ciphertext.
        """
        u = self._create_user()
        r = self.app.post('/login',
                          data=dict(fingerprint=u.fingerprint),
                          follow_redirects=True)

        self.assertIn('-----BEGIN PGP MESSAGE-----', r.data)

    def test_login_fingerprint_not_in_keyring(self):
        """Test that logging in with a fingerprint associated with a
        that's not in the keyring displays an error message.
        """
        fp = '096BA9B75722C367783BDD257F504009FAE962A2'
        r = self.app.post('/login',
                          data=dict(fingerprint=fp),
                          follow_redirects=True)

        self.assertIn(err_messages['no_account'], r.data)

    def test_login_user_not_in_database(self):
        """Test that logging in with a fingerprint that's in the
        keyring, but the user is not in the database, displays an error
        message.
        """
        r = self.app.post('/login',
                          data=dict(fingerprint=self.fp),
                          follow_redirects=True)

        self.assertIn(err_messages['no_account'], r.data)

    def test_canary_page(self):
        """Test that the canary template loads as expected."""
        c = self._create_canary()
        canary_url = '/canary/{}'.format(c.sigid_base64)
        r = self.app.get(canary_url)

        self.assertNotIn('Manage Canary', r.data)
        self.assertIn(self.fp, r.data)
        self.assertIn(c.date_posted.strftime('%Y-%m-%d'), r.data)
        self.assertIn(c.date_last_updated.strftime('%Y-%m-%d'), r.data)

    def test_canary_page_logged_in(self):
        """Test that when a logged in user visits the page for one of
        their canaries, they can manage the canary.
        """
        c = self._create_canary()
        self._login()
        canary_url = '/canary/{}'.format(c.sigid_base64)
        r = self.app.get(canary_url)

        self.assertIn('Manage Canary', r.data)

    def test_canary_page_logged_in_wrong_fingerprint(self):
        """If logged in, but session['fp'] doesn't match
        the fingerprint associated with the canary, the user should not
        be able to edit the canary.
        """
        pass

        """TODO: Figure out why this isn't changing the session data
        in the application context.
        c = self._create_canary()
        self._login()
        canary_url = '/canary/{}'.format(c.sigid_base64)

        with self.app.sessionh_transaction() as session:
            session['fp'] = 'notafingerprint'
            r = self.app.get(canary_url)
            self.assertNotIn('Manage Canary', r.data)"""

    def test_delete_canary(self):
        """Test that deleting a canary removes it from the database and
        the filesystem.
        """
        c = self._create_canary()
        self._login()
        r = self.app.post(
            '/canary/{}/delete'.format(c.sigid_base64),
            follow_redirects=True)

        canary_file = '{}/{}'.format(self.canaries_dir, c.sigid_base64)

        self.assertEqual(db_session.query(Canary).count(), 0)
        self.assertFalse(os.path.isfile(canary_file))
        self.assertIn(messages['deleted'], r.data)

    def test_verify_watch_canary(self):
        """Test that visiting a verification page changes an Alert from
        unverified to verified.
        """
        c = self._create_canary()
        a = Alert(c.user.uid, c, True, True, True, 3, 'sekrit')
        db_session.add(a)
        db_session.commit()

        with app.app_context():
            r = self.app.get('verify/{}'.format(a.hash),
                follow_redirects=True)
            self.assertTrue(a.active)
            self.assertIn(messages['alert_verified'], r.data)

if __name__ == '__main__':
    unittest.main()

