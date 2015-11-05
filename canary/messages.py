# -*- coding: utf-8 -*-
messages = dict(
    verified='Message verified.',
    alert_verified='Great! You will receive alerts for this canary.',
    published='Your canary was published!',
    deleted='Your canary was deleted.',
    canary_updated='Your canary was updated!'
)

err_messages = dict(
    not_signed='Not a PGP-signed message.',
    import_fail='Could not import your key from the keyserver. '
                'Upload it to {}.',
    invalid_sig='Invalid signature.',
    dupe_canary='That canary aleady exists.',
    generic='Oops. Something went wrong.',
    invalid_freq='Enter a valid frequency.',
    incomplete_form='Please include all required information.',
    decrypt_fail='Sorry, incorrect.',
    not_fp='Invalid fingerprint.',
    no_account='No canaries associated with that fingerprint. Publish '
               'a canary to get started!',
    invalid_email='Enter a valid email address.',
)

