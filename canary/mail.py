# -*- coding: utf-8 -*-
import hashlib
from datetime import datetime
from smtplib import SMTPException

from flask.ext.mail import Mail, Message
from sqlalchemy.orm.exc import NoResultFound

from canary import app
from canary import config
from canary.db import db_session
from canary.models import Canary, User
from canary.tasks import celery, SqlAlchemyTask

mail = Mail(app)

mails = dict(
    new_canary=[
        'You published a canary!',
        'A new canary was posted with your key 0x{}.\n\nWe will '
        'remind you to re-publish your canary every {} {}s, but you '
        'can re-publish or cancel it any time by logging in at {}.\n\n'
        'Your canary:\n\n{}\n\nIf you did not authorize this, your key '
        'may have been compromised and you should take steps to '
        'transition to a new keypair.'],
    reminder=[
        'Republish your canary',
        'It\'s time to republish your canary! Visit {} to republish '
        'your canary.\n\nYou will be reminded again in {} {}s.'],
    overdue_alert=[
        'A canary you\'re watching is overdue',
        '{} should have published their canary {} days ago.\n\nYou can '
        'see more information about this canary at {}'],
    verify_watch_canary=[
        'Verify that you want to watch a canary',
        'Canary: {}\n\nClick the link below to confirm that you would like to '
        'receive alerts for this canary:{}'])

def format_message(message_type, recipients, *args):
    """Format a Message to be sent with the Mail module."""
    subject = mails[message_type][0]
    body = mails[message_type][1].format(*args)

    with app.app_context():
        return Message(subject, recipients, body)

@celery.task(base=SqlAlchemyTask)
def notify(canary, user, text):
    """Send an email to notify ``user`` that ``canary`` was published
    with their key and to give them information about republishing
    ``canary``.
    """
    canary = db_session.merge(canary)
    user = db_session.merge(user)

    canary_url = config.URL + '/canary/{}'.format(canary.sigid_base64)
    msg = format_message('new_canary', [user.uid], user.keyid,
                         canary.frequency, canary.freq_type, canary_url,
                         text)

    with app.app_context():
        try:
            mail.send(msg)
        except SMTPException as e:
            app.logger.error(e)

@celery.task(base=SqlAlchemyTask)
def remind(canary, user):
    """Send an email to remind ``user`` to republish ``canary``.
    The email includes a link to a page with a challenge to decrypt.
    """
    if not app.testing:
        canary = db_session.merge(canary)
        user = db_session.merge(user)

    canary_url = config.URL + '/canary/{}'.format(canary.sigid_base64)
    msg = format_message('reminder', [user.uid], canary_url,
                         canary.frequency, canary.freq_type)

    """Set active to False so we don't send another reminder email
    unless the user republishes the canary."""
    canary.active = False
    db_session.commit()
    with app.app_context():
        try:
            mail.send(msg)
        except SMTPException as e:
            app.logger.error(e)

@celery.task(base=SqlAlchemyTask)
def send_verification_email(alert, canary):
    """Send a verification email when someone signs up to watch a 
    canary."""
    if not app.testing:      
        alert = db_session.merge(alert)
        canary = db_session.merge(canary)

    verify_url = config.URL + '/verify/{}?canary={}?email={}'.format(
        alert.hash, canary.id, alert.email)
    canary_url = config.URL + '/canary/{}'.format(canary.sigid_base64)
    msg = format_message('verify_watch_canary', [alert.email],
                         canary_url, verify_url)
    with app.app_context():
        try:
            mail.send(msg)
        except SMTPException as e:
            app.logger.error(e)

@celery.task(base=SqlAlchemyTask)
def send_overdue_alert(alert, canary, days_overdue):
    """Send a reminder to canary watchers the canary is overdue."""
    if days_overdue >= alert.delay:
        canary_url = config.URL + '/canary/{}'.format(
            canary.sigid_base64)

        msg = format_message('overdue_alert', [alert.email],
                             canary.user.uid, canary.user.uid,
                             days_overdue, canary_url)

        """Set active to False so we don't send another alert unless
        the canary owner republishes or deletes the canary."""
        alert.active = False
        db_session.commit()
        with app.app_context():
            try:
                mail.send(msg)
            except SMTPException as e:
                app.logger.error(e)

@celery.task(base=SqlAlchemyTask)
def check_canaries():
    """Check active canaries to see if their publishers need to be
    reminded to republish, or if watchers should be sent an alert.
    """
    try:
        canaries = Canary.query.all()
    except NoResultFound:
        return
    except Exception as e:
        app.logger.error(e)

    for canary in canaries:
        diff = datetime.now() - canary.date_last_updated

        for alert in canary.watchers:
            # If the alert is not active, don't resend it.
            if alert.active and alert.on_overdue:
                send_alert.delay(alert, canary, diff.days)

        """If the canary is not active, the user has been reminded
        once, so we shouldn't send any more reminders until the canary
        is republished or edited."""
        if diff.days >= canary.frequency and canary.active:
            user = User.query.filter(User.id == canary.user_id).one()
            remind.delay(canary, user)

