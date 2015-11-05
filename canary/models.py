# -*- coding: utf-8 -*-
import datetime
import hashlib
import os

from flask import session
from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer,
                        String)
from sqlalchemy.orm import relationship

from canary.db import Base, db_session
from canary.gpg import gpg
from canary.utils import is_hex_challenge

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    keyid = Column(String(16))
    fingerprint = Column(String(40), unique=True)
    uid = Column(String(150))
    chal_id = Column(Integer())

    canaries = relationship('Canary', backref='users')

    def __init__(self, keyid, fingerprint, uid):
        self.keyid = keyid
        self.fingerprint = fingerprint
        self.uid = uid
        self.chal_id = None

    def __repr__(self):
        return '<User {} (keyid={}, fingerprint={}, uid={})>'.format(
            self.id, self.keyid, self.fingerprint, self.uid)

    def update(self, uid):
        """Updates the user's uid if it has changed."""
        if uid != self.uid:
            self.uid = uid

        db_session.commit()

    @classmethod
    def login(cls, fingerprint, decrypted):
        """Try logging a user in."""
        user = User.query.filter(User.fingerprint == fingerprint).one()
        if Challenge.check(user, decrypted):
            session['uid'] = user.id
            session['fp'] = user.fingerprint
        else:
            raise IncorrectChallengeException

class Canary(Base):
    __tablename__ = 'canaries'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    sigid_base64 = Column(String(36), unique=True)
    date_posted = Column(DateTime)
    date_last_updated = Column(DateTime)
    active = Column(Boolean, default=False)
    frequency = Column(Integer)
    freq_type = Column(String(5))
    chal_id = Column(Integer)

    user = relationship('User', back_populates='canaries')
    watchers = relationship('Alert', backref='canaries')

    def __init__(self, sigid_base64, frequency, freq_type):
        self.sigid_base64 = sigid_base64
        self.date_posted = datetime.datetime.now()
        self.date_last_updated = datetime.datetime.now()
        self.active = False
        self.frequency = frequency
        self.freq_type = freq_type
        self.chal_id = None

    def __repr__(self):
        return '<Canary {}>'.format(self.sigid_base64)

    def republish(self):
        """Republish the canary."""
        self.date_last_updated = datetime.datetime.now()
        self.active = True
        db_session.commit()

    def delete(self, path):
        """Delete the canary in the filesystem and database, and delete
        the canary's publisher if this is the user's only canary.
        """
        os.unlink(path)
        if len(self.user.canaries) == 1:
            db_session.delete(self.user)
            if 'uid' in session:
                session.pop('uid')
            if 'fp' in session:
                session.pop('fp')
        db_session.delete(self)
        db_session.commit()

class Challenge(Base):
    __tablename__ = 'challenges'
    id = Column(Integer, primary_key=True)
    hash = Column(String())

    def __init__(self, hash):
        self.hash = hash

    def __repr__(self):
        return '<Challenge {}>'.format(self.id)

    @classmethod
    def generate(cls, obj, fingerprint):
        """Generate a challenge and return the hash of the challenge and 
        the challenge encrypted with GPG.
        """
        secret = os.urandom(16).encode('hex')
        hash = hashlib.sha256(secret).hexdigest()
        ciphertext = gpg.encrypt(secret, fingerprint)

        chal = Challenge(hash)
        db_session.add(chal)
        db_session.commit()
        obj.chal_id = chal.id
        db_session.commit()
        return ciphertext

    @classmethod
    def check(cls, obj, solution):
        """Check if the SHA-255 hash of ``solution`` matches the
        challenge.
        """
        if not is_hex_challenge(solution):
            return False

        chal = Challenge.query.filter(Challenge.id == obj.chal_id).one()
        # Set obj.chal_id to None so chal is never used again
        obj.chal_id = None
        db_session.commit()
        return chal.hash == hashlib.sha256(solution).hexdigest()

class Alert(Base):
    __tablename__ = 'alerts'
    id = Column(Integer, primary_key=True)
    canary_id = Column(Integer, ForeignKey('canaries.id'))
    active = Column(Boolean, default=False)
    email = Column(String(254))
    on_publish = Column(Boolean, default=False)
    on_overdue = Column(Boolean, default=False)
    on_delete = Column(Boolean, default=False)
    delay = Column(Integer)
    hash = Column(String)

    def __init__(self, email, canary, on_delete, on_overdue, on_publish,
                 delay, secret):
        self.email = email
        self.canary_id = canary.id
        self.alert_on_delete = on_delete
        self.alert_on_overdue = on_overdue
        self.alert_on_publish = on_publish
        self.delay = delay
        self.hash = hashlib.sha256(
            secret + email + str(canary.id)).hexdigest()

    def __repr__(self):
        return '<Alert (email={} canary_id={})>'.format(
            self.email, self.canary_id)

class IncorrectChallengeException(Exception):

    """Raised when a user fails to decrypt a challenge."""

