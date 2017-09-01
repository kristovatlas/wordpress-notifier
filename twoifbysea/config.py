"""Manages app configuration, such as stored credentials for an email account

https://github.com/kristovatlas/twoifbysea

Default method of obtaining configuration is to read from the encrypted_kv_store
table in the user database; as a fallback, environment variables may be set.

Environment variables:
    * TWOIFBYSEA_DEFAULT_GMAIL_USERNAME
    * TWOIFBYSEA_DEFAULT_GMAIL_PASSWORD
    * TWOIFBYSEA_DEFAULT_TELEGRAM_TOKEN
"""

#Python Standard Library 2.7
import os

#twoifbysea modules
import datastore #datastore.py
import common #common.py

KEY_FALLBACKS = {'gmail_username': 'TWOIFBYSEA_DEFAULT_GMAIL_USERNAME',
                 'gmail_password': 'TWOIFBYSEA_DEFAULT_GMAIL_PASSWORD',
                 'telegram_token': 'TWOIFBYSEA_DEFAULT_TELEGRAM_TOKEN'}

class KeyNotStoredAndNoFallbackError(Exception):
    """The requested key has not value stored, and there is no fallback stored."""
    pass

def get_value(key, app_id=None, app_secret=None):
    """Fetch configuration value stored for key

    Args:
        key (str): The plaintext key that you want to look up
        app_id (Optional[str]): If specified, the base64-encoded id assigned
            to the app that wants to query its data
        app_secret (Optional[str]): If specified, the base64-encoded secret
            assigned to the app that wants to query its data. This is a
            decryption key.

    Raises: KeyNotStoredAndNoFallbackError
    """
    assert isinstance(key, str)
    if app_id is not None and app_secret is not None:
        assert isinstance(app_id, str)
        assert isinstance(app_secret, str)
        common.b64decode(app_id)
        common.b64decode(app_secret)

        with datastore.DatabaseConnection() as db_con:
            try:
                return db_con.get_key_val(app_id, app_secret, key)
            except datastore.DecryptionFailError:
                pass

    #try fallback
    if key in KEY_FALLBACKS.keys():
        val = os.getenv(KEY_FALLBACKS[key], None)
        if val is not None:
            return val
    err_msg = "Unable to acquire value for '{0}'".format(key)
    if key in KEY_FALLBACKS.keys():
        err_msg = ''.join([err_msg,
                           ' (set environment variable {0})'.format(KEY_FALLBACKS[key])])
    raise KeyNotStoredAndNoFallbackError(err_msg)
