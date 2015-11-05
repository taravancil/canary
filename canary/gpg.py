# -*- coding: utf-8 -*-
from subprocess import Popen, PIPE

import gnupg

from canary import app
from canary import config
from canary.messages import err_messages
from canary.utils import formatter

class Gpg(object):
    """Interface for interacting with the gnupg module."""

    def __init__(self):
        self.gnupg = gnupg.GPG(homedir=app.config.get('HOMEDIR'), binary=config.GPG_PATH)

    def keys(self, private=False):
        """Return a collection of the keys in the the public keyring.
        Return private keys if ``private`` is True.
        """
        return self.gnupg.list_keys(private)

    def have_key(self, keyid=None, fingerprint=None):
        """Check if key ``keyid`` is in the public keyring."""
        keys = gpg.keys()
        for key in keys:
            if keyid is not None:
                """Compare short keyids since either the short or full
                keyid can be passed as an argument."""
                if key['keyid'][-8:] == keyid[-8:]:
                    return True
            elif fingerprint is not None:
                if key['fingerprint'] == fingerprint.upper():
                    return True
        return False

    def recv_keys(self, keyid):
        """Import a key from the default keyserver. Returns True on
        failure and None on success.
        """
        app.logger.info('Importing key {} from {}...'.format(
            keyid, config.KEYSERVER))

        p = Popen([
            config.GPG_PATH, '--batch', '--no-tty', '--keyserver',
            config.KEYSERVER, '--homedir', app.config.get('HOMEDIR'),
            '--recv-keys', keyid], stdout=PIPE, stderr=PIPE)

        _, err = p.communicate()
        if err is None:
            return True

        app.logger.info(err)
        short_keyid = keyid[-8:]
        for line in err.split('\n'):
            if line.startswith(
                    'gpg: key {}: public key '.format(
                        short_keyid)) and line.endswith('" imported'):
                return None

        return True

        """TODO: This doesn't work. Figure out why.
        import_result = self.gnupg.recv_keys(config.KEYSERVER, keyid)
        print import_result
        if import_result is None:
            return 'Unable to import {} from keyserver'.format(keyid)
        """

    def verify(self, message):
        """Verify the signature on the contents of the string
        ``message``.
        """
        for r in ['-----BEGIN PGP SIGNED MESSAGE---',
                  '-----BEGIN PGP SIGNATURE-----',
                  '-----END PGP SIGNATURE-----']:
            if r not in message:
                return None, err_messages['not_signed']

        verified = self.gnupg.verify(message)
        if not verified:
            if not gpg.have_key(keyid=verified.key_id):
                err = gpg.recv_keys(verified.key_id)
                if err:
                    return None, formatter(
                        'import_fail', err_messages, config.KEYSERVER)

                # Try to verify it again
                return gpg.verify(message)

            return None, err_messages['invalid_sig']

        return verified, None

    def encrypt(self, message, fingerprint):
        return self.gnupg.encrypt(message, fingerprint)

    def decrypt(self, message, passphrase):
        return self.gnupg.decrypt(message, passphrase=passphrase)

    def delete_keys(self, keyid):
        return self.gnupg.delete_keys(keyid)

gpg = Gpg()

