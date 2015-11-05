# -*- coding: utf-8 -*-
import re

from canary import app

def formatter(key, dictionary, *args):
    """Format a string from ``dictionary`` with ``*args``."""
    return dictionary[key].format(*args)

def list_routes(method='', show_args=False):
    """List the app routes filtered by ``method``. Exclude routes that
    require arguments unless ``show_args`` is true.
    """
    routes = []
    for rule in app.url_map.iter_rules():
        if (not show_args and rule.arguments) or rule.methods == 'static':
            break
        if method in rule.methods:
            routes.append(rule.rule)
        elif method == '':
            routes.append(rule.rule)
    return routes

def is_sigid(sigid_base64):
    """Return True if ``sigid`` matches the expected sigid format."""
    return re.match(r'^[a-zA-Z0-9_-]{36}$', sigid_base64)

def is_fingerprint(fingerprint):
    """Return True if ``fingerprint`` matches a fingerprint regex."""
    return re.match(r'^[a-fA-F\d]{40}$', fingerprint)

def is_hex_challenge(string):
    """Return True if ``string`` is a hex-encoded string the same
    length as the session secret.
    """
    return re.match(r'^[a-f\d]{32}$', string)

def days(n, type):
    """Return ``n`` ``type``s as an integer representation of days."""
    if type == 'day':
        return int(n)
    elif type == 'week':
        return int(n) * 7
    elif type == 'month':
        return int(n) * 30

