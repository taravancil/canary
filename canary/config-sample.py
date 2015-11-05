# -*- coding: utf-8 -*-
import os
import inspect

from celery.schedules import crontab

INTRO_TEXT = 'Canary is an application for publishing and managing \
             cryptographically-verified canary statements.'

DEBUG = False
SECRET_KEY = os.urandom(24)

# For development, set this to http://localhost:5000
URL = 'http://localhost:5000'

d = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))

DATABASE_FILE=os.path.join(d, 'prod.db')

# Path to a GPG binary on your machine
GPG_PATH=''
# Path where the GPG keyring will be stored
HOMEDIR=os.path.join(d, 'homedir')
KEYSERVER='hkp://pool.sks-keyservers.net'

CANARIES_DIR=os.path.join(d, 'canaries')
TEST_DIR=os.path.join(d, 'test')

"""These do not need to be set for running tests, but if you want to
actually send emails, fill these out and run celery -A canary.tasks worker"""
# MAIL_SERVER = ''
# MAIL_DEFAULT_SENDER = ''
# MAIL_USE_TLS =
# MAIL_USE_SSL = 
# MAIL_USERNAME = ''
# MAIL_PASSWORD = ''

class Testing(object):
    TESTING=True
    DATABASE_FILE=os.path.join(TEST_DIR, 'test.db')
    HOMEDIR=os.path.join(TEST_DIR, 'homedir')
    CANARIES_DIR=os.path.join(TEST_DIR, 'canaries')

class Celery(object):
    # Change this to the URL for your message broker
    BROKER_URL='amqp://guest@localhost//',
    CELERYBEAT_SCHEDULE = {
        'check-canaries-every-day': {
            'task': 'canary.mail.check_canaries',
            # Execute every day at 0:00
            'schedule': crontab(minute=0, hour=0),
            'args': ()
        }
    }

