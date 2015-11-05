__init__.py:    """TODO: Set up option for admin to receive an email if something
__init__.py-    serious goes wrong. See flask.pocoo.org/docs/0.10/errorhandling."""
--
gpg.py:        """TODO: This doesn't work. Figure out why.
gpg.py-        import_result = self.gnupg.recv_keys(config.KEYSERVER, keyid)
--
test/views_test.py:        """TODO: Figure out why this isn't changing the session data
test/views_test.py-        in the application context.
--
views.py:        # TODO: This is sloppy.
views.py-        session['canary'] = dict(fp=verified.fingerprint.lower(),
--
views.py:        # TODO: notify watchers when an canary is deleted
views.py-        # on_delete = request.form.get('onDelete') or False
