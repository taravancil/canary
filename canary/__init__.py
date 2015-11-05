# -*- coding: utf-8 -*-
import base64
import datetime
import os

from flask import Flask, abort, session, request
from flask.ext.mail import Mail

import canary.config

app = Flask(__name__)
app.config.from_object('canary.config')

if os.environ.get('CANARY_ENV') == 'test':
    app.config.from_object('canary.config.Testing')

app.secret_key = app.config.get('SECRET_KEY')

from canary.db import db_session, init_db
import canary.views

init_db()
mail = Mail(app)

if not app.debug or app.testing:
    import logging
    from logging import Formatter
    from logging.handlers import SysLogHandler

    loghandler = SysLogHandler()
    loghandler.setLevel(logging.INFO)
    loghandler.setFormatter(Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
        '[in %(pathname)s:%(lineno)d]'))

    app.logger.addHandler(loghandler)

    """TODO: Set up option for admin to receive an email if something
    serious goes wrong. See flask.pocoo.org/docs/0.10/errorhandling."""

def generate_csrf_token():
    """Generate a CSRF token for POST requests."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(16).encode('hex')
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    """Check that POST requests have a valid CSRF token."""
    if app.testing:
        # Don't require CSRF during testing
        return

    if request.method == 'POST':
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(405)

@app.before_request
def make_session_permanent():
    """Timeout the session after 30 minutes of inactivity."""
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=30)

@app.teardown_appcontext
def shutdown_db_session(exception=None):
    db_session.remove()

@app.context_processor
def template_funcs():
    """These functions are made available in the templates."""

    def print_fp(fingerprint):
        """Formats a fingerprint for printing."""
        formatted = ''
        while fingerprint:
            formatted += fingerprint[:4] + ' '
            fingerprint = fingerprint[4:]
        return formatted

    def format_frequency(days, freq_type):
        if freq_type == 'day':
            return days
        elif freq_type == 'week':
            return days // 7
        elif freq_type == 'month':
            return days // 30

    def time_since(d):
        """Calculates how many days have elapsed singe a canary was
        last published.
        """
        diff = datetime.datetime.now() - d
        return diff.days

    return dict(time_since=time_since,
                print_fp=print_fp,
                format_frequency=format_frequency)

