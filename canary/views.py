# -*- coding: utf-8 -*-
import base64
import datetime
from functools import wraps
import os
import re

from flask import (abort, flash, request, redirect, render_template,
                   session, url_for)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from canary import app
from canary.db import db_session
from canary.gpg import gpg
from canary.mail import notify, send_verification_email
from canary.messages import err_messages, messages
from canary.models import (Alert, Canary, Challenge, User,
                           IncorrectChallengeException)
from canary.utils import days, is_fingerprint, is_sigid

def template(template=None):
    """Decorator for routing to a specific template."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            template_name = template
            if template_name is None:
                template_name = request.endpoint \
                    .replace('.', '/') + '.html'
            ctx = f(*args, **kwargs)
            if ctx is None:
                ctx = {}
            elif not isinstance(ctx, dict):
                return ctx
            return render_template(template_name, **ctx)
        return decorated
    return decorator

def logged_in():
    """Logged in users' ids are stored in the session."""
    return 'uid' in session

@app.errorhandler(404)
def page_not_found(e):
    if e == 'canary':
        try:
            canaries = Canary.query.all()
            urls = []
            for c in canaries:
                urls.append(c.sigid_base64)
        except:
            urls = None

    elif e == 'user':
        try:
            users = User.query.all()
            urls = []
            for u in users:
                urls.append(u.fingerprint)
        except:
            urls = None
    else:
        urls = None
    return render_template('404.html', type=e, urls=urls), 404

@app.route('/', methods=['GET'])
@template('index.html')
def index():
    return None

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/faq', methods=['GET'])
def faq():
    return render_template('faq.html')

@app.route('/new', methods=['GET', 'POST'])
@template('new.html')
def new_canary():
    if request.method == 'GET':
        return None

    if request.method == 'POST':
        try:
            signed = request.form['signedMessage']
            frequency_num = int(request.form['frequencyNum'])
            frequency_type = request.form['frequency']
        except KeyError:
            flash(err_messages['incomplete_form'], 'error')
            return None

        allowed_freqs = 'day', 'week', 'month'
        in_range = 1 <= frequency_num <= 100
        if frequency_type not in allowed_freqs or not in_range:
            flash(err_messages['invalid_freq'], 'error')
            return None
        # Get the frequency in days
        frequency = days(frequency_num, frequency_type)

        verified, err = gpg.verify(signed)
        # Start over if the message wasn't verified.
        if err and not verified:
            flash(err, 'error')
            return None

        fp = verified.fingerprint
        sigid_base64 = base64.urlsafe_b64encode(verified.signature_id)

        try:
            canary = Canary(sigid_base64, frequency, frequency_type)
            db_session.add(canary)
            db_session.commit()
        except IntegrityError:
            # Throw an error if a canary with that sigid already exists
            db_session.rollback()
            db_session.flush()
            flash(err_messages['dupe_canary'], 'error')
            return redirect(url_for('new_canary'))
        except Exception as e:
            db_session.rollback()
            db_session.flush()
            app.logger.error(e)
            """An unexpected database error should not reveal any
               error details to the user."""
            flash(err_messages['generic'], 'error')
            return None

        ciphertext = Challenge.generate(canary, fp)
        # TODO: This is sloppy.
        session['canary'] = dict(fp=verified.fingerprint.lower(),
                                 text=signed,
                                 uid=verified.username,
                                 keyid=verified.key_id,
                                 sigid_base64=sigid_base64,
                                 frequency=frequency,
                                 freq_type=frequency_type,
                                 ciphertext=str(ciphertext))

        flash(messages['verified'], 'message')
        return dict(canary=session['canary'])

@app.route('/canaries', methods=['GET'])
@template('canaries.html')
def users():
    try:
        users = User.query.all()
    except:
        users = None
    return dict(users=users)

@app.route('/user/<fingerprint>', methods=['GET'])
@template('user.html')
def user(fingerprint):
    if not is_fingerprint(fingerprint):
        return page_not_found('user')

    try:
        user = User.query.filter(User.fingerprint == fingerprint).one()
    except NoResultFound:
        return page_not_found('user')

    return dict(user=user)

@app.route('/canary/<sigid_base64>', methods=['GET', 'POST'])
@template('canary.html')
def canary(sigid_base64):
    if request.method == 'GET':
        canary = get_canary(sigid_base64)
        if canary is None:
            return page_not_found('canary')

        pathstr = str(sigid_base64)
        path = os.path.join(app.config.get('CANARIES_DIR'), pathstr)
        f = open(path, 'r')
        text = f.read()
        f.close()
        return dict(canary=canary, text=text)

    if request.method == 'POST':
        if not is_sigid(sigid_base64):
            return redirect(url_for('index'))

        try:
            canary = Canary.query.filter(
                Canary.sigid_base64 == sigid_base64).one()
            decrypted = request.form['decrypted'].strip()
            if not Challenge.check(canary, decrypted):
                raise IncorrectChallengeException
        except KeyError:
            flash(err_messages['incomplete_form'], 'error')
            return None
        except IncorrectChallengeException:
            db_session.delete(canary)
            db_session.commit()
            flash(err_messages['decrypt_fail'], 'error')
            return redirect(url_for('new_canary'))
        except Exception as e:
            flash(err_messages['generic'], 'error')
            app.logger.error(e)
            return redirect(url_for('new_canary'))

        sess = session['canary']
        fp = sess['fp']
        try:
            user = User.query.filter(User.fingerprint == fp).one()
            """Update the existing user's key info, in case the username
            or email address has been edited since we last saw it."""
            user.update(canary['uid'])
        except NoResultFound:
            # Create a new user
            user = User(sess['keyid'], fp, sess['uid'])
            db_session.add(user)
            db_session.commit()

        canary.user_id = user.id
        canary.active = True
        db_session.commit()

        with app.app_context():
            text = sess['text']
            if app.testing:
                notify(canary, user, text)
            else:
                notify.delay(canary, user, text)

        pathstr = str(sigid_base64)
        path = os.path.join(app.config.get('CANARIES_DIR'), pathstr)

        with open(path, 'w') as f:
            f.write(text)
            f.close()

        flash(messages['published'], 'message')
        return redirect(url_for('canary', sigid_base64=sigid_base64))

@app.route('/canary/<sigid_base64>/edit', methods=['POST'])
@template('canary.html')
def edit_canary(sigid_base64):
    if not logged_in():
        return redirect(url_for('login'))

    canary = get_canary(sigid_base64)
    if canary is None:
        return page_not_found('canary')
    if logged_in and canary.user.fingerprint == session['fp']:
        freq_num = request.form['frequencyNum']
        freq = request.form['frequency']
        canary.freq_type = freq
        canary.frequency = days(freq_num, freq)
        canary.active = True
        db_session.commit()
        flash(messages['canary_updated'], 'message')
        return redirect(url_for('canary', sigid_base64=sigid_base64))
    else:
        abort(403)

@app.route('/canary/<sigid_base64>/delete', methods=['POST'])
def delete(sigid_base64):
    canary = get_canary(sigid_base64)
    if canary is None:
        return page_not_found('canary')

    fp = canary.user.fingerprint

    if not logged_in():
        return redirect(url_for('login'))

    if session['fp'] == fp:
        path = os.path.join(
            app.config.get('CANARIES_DIR'), str(sigid_base64))
        canary.delete(path)    
        flash(messages['deleted'], 'message')
        return redirect(url_for('index'))
    else:
        # Logged in, but the user isn't authorized to delete this canary
        abort(403)

@app.route('/canary/<sigid_base64>/watch', methods=['GET', 'POST'])
@template('watch.html')
def watch_canary(sigid_base64):
    canary = get_canary(sigid_base64)
    if canary is None:
        return page_not_found('canary')

    if request.method == 'GET':
        return dict(canary=canary)

    if request.method == 'POST':
        try:
            email = request.form['email']
        except KeyError:
            flash(err_messages['incomplete_form'], 'error')
            return dict(canary=canary)
        except Exception as e:
            flash(err_messages['generic'], 'error')
            app.logger.error(e)
            return dict(canary=canary)

        if not re.search('@', email) or len(email) > 254:
            flash(err_messages['invalid_email'], 'error')
            return dict(canary=canary)

        alerts = request.form.getlist('alerts')
        on_publish = 'onPublish' in alerts
        on_overdue = 'onOverdue' in alerts
        # on_delete = list['onDelete']

        delay_days = 0
        if on_overdue:
            delay = int(request.form['delay'])
            delay_type = request.form['delayType']

            if not delay or not delay_type:
                on_overdue = False
            
            allowed_delays = 'day', 'week', 'month'
            in_range = 1 <= delay <= 100

            if delay_type not in allowed_delays or not in_range:
                flash(err_messages['incomplete_form'], 'error')
                return dict(canary=canary)
            # Get the delay in days
            delay_days = days(delay, delay_type)

        # TODO: notify watchers when an canary is deleted
        # on_delete = request.form.get('onDelete') or False
        if not (on_publish or on_overdue):
            flash(err_messages['incomplete_form'], 'error')
            return dict(canary=canary)

        secret = os.urandom(16).encode('hex')
        alert = Alert(email, canary, False, on_overdue, on_publish,
                      delay_days, secret)
        db_session.add(alert)
        db_session.commit()

        # Send verification email
        send_verification_email.delay(alert, canary)
        return redirect(url_for('canary', sigid_base64=sigid_base64))

@app.route('/canary/<sigid_base64>/publish', methods=['GET', 'POST'])
@template('publish.html')
def publish_canary(sigid_base64):
    canary = get_canary(sigid_base64)
    if canary is None:
        return page_not_found('canary')

    fp = canary.user.fingerprint

    if request.method == 'GET':
        ciphertext = Challenge.generate(canary, fp)
        return dict(canary=canary, ciphertext=ciphertext)

    if request.method == 'POST':
        """If the request originated from a logged in user's manage canary
        page, republish the canary."""
        if logged_in() and session['fp'] == fp:
            return republish_canary(canary)

        else:
            if Challenge.check(canary, request.form['decrypted'].strip()):
                return republish_canary(canary)
            else:
                flash(err_messages['decrypt_fail'], 'error')
                return None

def republish_canary(canary):
    """Republish ``canary``."""
    try:
        canary.republish()
        flash(messages['published'], 'message')
    except Exception as e:
        flash(err_messages['generic'], 'error')
        app.logger.error(e)
  
    return redirect(url_for('canary', sigid_base64=canary.sigid_base64))

@app.route('/verify/<code>', methods=['GET'])
def verify_watch_canary(code):
    try:
        a = Alert.query.filter(Alert.hash == code).one()
        canary = Canary.query.filter(Canary.id == a.canary_id).one()
    except:
        return page_not_found('canary')

    if request.method == 'GET':
        a.active = True
        db_session.commit()
        flash(messages['alert_verified'], 'message')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
@template('login.html')
def login():
    if logged_in():
        return redirect(url_for('user',
                                fingerprint=session['fp']))

    if request.method == 'GET':
        if 'fingerprint' not in session:
            return None

    if request.method == 'POST':
        try:
            fp = request.form.get('fingerprint').replace(' ', '').lower()
            if not is_fingerprint(fp):
                flash(err_messages['not_fp'], 'error')
                return redirect(url_for('login'))
            user = User.query.filter(User.fingerprint == fp).one()
            session['fp'] = fp
            ciphertext = Challenge.generate(user, fp)
            return dict(ciphertext=ciphertext)
        except NoResultFound:
            flash(err_messages['no_account'], 'error')
        except Exception as e:
            flash(err_messages['generic'], 'error')
            app.logger.error(e)

        return redirect(url_for('login'))

@app.route('/login/<fingerprint>', methods=['POST'])
def login_user(fingerprint):
    try:
        decrypted = request.form.get('decrypted').strip()
        User.login(fingerprint, decrypted)
        return redirect(url_for('user', fingerprint=fingerprint))
    except KeyError:
        flash(err_messages['incomplete_form'], 'error')
    except IncorrectChallengeException:
        flash(err_messages['decrypt_fail'], 'error')
    except Exception as e:
        flash(err_messages['generic'], 'error')
        app.logger.error('Login error (fingerprint {}): {}'.format(
            fingerprint, e))
        
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.pop('uid')
        session.pop('fp')
    except:
        pass
    return redirect(url_for('index'))

def get_canary(sigid_base64):
    """Return a Canary if it exists in the filesystem and database."""
    if not is_sigid(sigid_base64):
        return None

    pathstr = str(sigid_base64)
    path = os.path.join(app.config.get('CANARIES_DIR'), pathstr)
    if not os.path.isfile(path):
        return None

    try:
        canary = Canary.query.filter(
            Canary.sigid_base64 == sigid_base64).one()
    except:
        return None

    return canary

