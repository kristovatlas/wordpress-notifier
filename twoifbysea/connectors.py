"""Connectors that Python clients can use to connect to notification service

https://github.com/kristovatlas/twoifbysea

Examples:
    >>> recipients = ['bob@example.com', 'fred@example.com']
    >>> body = 'This is an important alert message!'
    >>> error_recipients = ['admin@example.com']
    >>> with connectors.HTTPConnector(gmail_username, gmail_password) as http_con:
    ...     http_con.notify(subject, body, recipients,
    ...                     channel=common.SupportedChannels.GMAIL,
    ...                     error_channel=None, error_recipients=error_recipients))

TODO: remember that app_id and app_secret should be optional.

"""

#Python Standard Library 2.7
import sys
import warnings
import json
import urllib

#pip modules
import requests

#twoifbysea modules
import common #common.py
import config #config.py
import webserver #webserver.py

GET_SECRETS_URL = 'http://127.0.0.1:51337/get_app_secrets'

STORE_URL = 'http://127.0.0.1:51337/store?'

NOTIFICATION_URL = 'http://127.0.0.1:51337/notify?'

GITHUB_ISSUES = 'https://github.com/kristovatlas/twoifbysea/issues'

GMAIL_USERNAME_STR = 'gmail_username'
GMAIL_PASSWORD_STR = 'gmail_password'

class ConnectionFailureError(Exception):
    """Could not connect to notification service"""
    pass

class HTTPConnector(object):
    """Connects Python classes to the notification service via localhost HTTP"""

    def __enter__(self):
        return self

    def __init__(self, gmail_username=None, gmail_password=None):
        """Establish connection to the localhost web server

        Args:
            gmail_username (Optional[str]): Your GMail account username, if
                using GMail as a notification channel.
            gmail_password (Optional[str]): Your GMail account password, if
                using GMail as a notification channel.

        Raises: ConnectionFailureError
        """
        self.gmail_username = gmail_username #TODO: read from me if set
        self.gmail_password = gmail_password #TODO: read from me if set

        if not is_server_up():
            msg = ("Unable to connect to web server. Try starting it with "
                   "`make start`.")
            raise ConnectionFailureError(msg)

    def __exit__(self, exec_type, exec_value, exec_traceback):
        pass

    def notify(self, subject, body, recipients,
               channel=common.SupportedChannels.GMAIL, error_channel=None,
               error_recipients=None):
        """Send a notification request to the web server
        Args:

            body (str): The body of the message
            subject (str): The subject of the message
            recipients (List[str]): A list of recipients
            channel (Optional[common.SupportedChannels]): The channel over which
                to communicate. Default: GMail account
            error_channel (Optional[common.SupportedChannels]): The channel over
                which the service will attempt to communicate sending errors.
                Default: None
            error_recipients (Optional[List(str)]): A list of error message
                recipients, if you desire for error messages to be sent out and
                recipients are relevant (e.g. for email but not logging).
        """
        if channel == common.SupportedChannels.GMAIL:
            username, password = get_username_pass()
            app_id, app_secret = get_app_secrets()
            print "DEBUG: Acquired app id: {0}".format(app_id)
            store_creds(username, password, app_id, app_secret)
            print "DEBUG: Stored credentials successfully."
            submitted = submit_notif_req(
                app_id=app_id, app_secret=app_secret, body=body, subject=subject,
                recipients=recipients, channel=channel,
                error_channel=error_channel, error_recipients=error_recipients)
            if submitted:
                print "DEBUG: Notification request submitted successfully."
            else:
                print "DEBUG: Notification request failed."

        else:
            raise NotImplementedError("Channel not yet implemented in HTTPConnecor.")


def is_server_up():
    """Check if web server is up"""
    url = 'http://{0}:{1}/'.format(webserver.HOST_NAME, webserver.PORT_NUMBER)
    try:
        requests.get(url)
        return True
    except requests.exceptions.ConnectionError:
        return False

def _concat_arg(arg_string, arg_name, arg_value):
    return ''.join([arg_string, '&', arg_name, '=', urllib.quote(arg_value)])

def get_notify_url(app_id, app_secret, body, subject, recipients,
                   channel=common.SupportedChannels.GMAIL,
                   error_channel=None, error_recipients=None):
    """Get the url used for placing a notification request

    Args:
        app_id (str): Base-64 encoded string
        app_secret (str): Base-64 encoded string
        body (str): The body of the message
        subject (str): The subject of the message
        recipients (List[str]): A list of recipients
        channel (Optional[common.SupportedChannels]): The channel over which
            to communicate. Default: email
        error_channel (Optional[common.SupportedChannels]): The channel over
            which the service will attempt to communicate sending errors.
            Default: None
        error_recipients (Optional[List(str)]): A list of error message
            recipients, if you desire for error messages to be sent out and
            recipients are relevant (e.g. for email but not logging).

    Returns: str: A url-encoded URL
    """
    assert isinstance(body, str)
    assert isinstance(subject, str)

    assert isinstance(recipients, list)
    if len(recipients) > 1:
        raise NotImplementedError()
    recipient = recipients[0]
    assert isinstance(recipient, str)

    assert isinstance(channel, common.SupportedChannels)
    channel_str = channel.name.lower()

    args = _concat_arg('', 'app_id', app_id)
    args = _concat_arg(args, 'app_secret', app_secret)
    args = _concat_arg(args, 'channel', channel_str)
    args = _concat_arg(args, 'subject', subject)
    args = _concat_arg(args, 'body', body)
    args = _concat_arg(args, 'recipient', recipient)

    if error_channel is not None:
        isinstance(error_channel, common.SupportedChannels)
        error_channel_str = error_channel.name.lower()
        args = _concat_arg(args, 'error_channel', error_channel_str)

    if error_recipients is not None:
        assert isinstance(error_recipients, list)
        if len(error_recipients) > 1:
            raise NotImplementedError()
        error_recipient = error_recipients[0]
        assert isinstance(error_recipient, str)
        args = _concat_arg(args, 'error_recipient', error_recipient)

    return ''.join([NOTIFICATION_URL, args])


def _get_store_url(app_id, app_secret, key, val):
    return '{0}app_id={1}&app_secret={2}&key={3}&value={4}'.format(
        STORE_URL, app_id, app_secret, key, val)

def get_username_pass():
    """Get username and password from env vars"""
    username = None
    password = None
    try:
        username = config.get_value(GMAIL_USERNAME_STR)
        assert username is not None and username != ''
    except config.KeyNotStoredAndNoFallbackError, err:
        print "Unable to fetch GMail username: {0}".format(str(err))
        sys.exit(1)
    try:
        password = config.get_value(GMAIL_PASSWORD_STR)
        assert password is not None and password != ''
    except config.KeyNotStoredAndNoFallbackError, err:
        print "Unable to fetch GMail password: {0}".format(str(err))
        sys.exit(1)

    return (username, password)

def _get_resp(url):
    req = None
    try:
        req = requests.get(url)
    except requests.exceptions.ConnectionError:
        print "Web server not availabe. Try starting it with `make start`."
        sys.exit(1)

    if req.status_code != 200:
        print "Web server response is bad. Please report to {0}".format(
            GITHUB_ISSUES)
        sys.exit(1)

    if 'application/json' not in req.headers['content-type']:
        warnings.warn('JSON content type missing')

    return json.loads(req.text)

def get_app_secrets():
    """Fetch app_id and app_secret"""
    resp = _get_resp(GET_SECRETS_URL)
    return (resp['app_id'], resp['app_secret'])

def store_creds(username, password, app_id, app_secret):
    """Store Gmail credentials for notifications"""
    url1 = _get_store_url(app_id, app_secret, GMAIL_USERNAME_STR, username)
    resp1 = _get_resp(url1)
    if resp1['status'] != 'success':
        print "Storage of username failed with error message: {0}".format(
            resp1['message'])
        sys.exit(1)
    url2 = _get_store_url(app_id, app_secret, GMAIL_PASSWORD_STR, password)
    resp2 = _get_resp(url2)
    if resp2['status'] != 'success':
        print "Storage of password failed with error message: {0}".format(
            resp2['message'])
        sys.exit(1)
    assert resp1['status'] == 'success' and resp2['status'] == 'success'

def submit_notif_req(app_id, app_secret, body, subject, recipients, channel,
                     error_channel, error_recipients):
    """Submit a notification request to the web server and handle resp errors

    Returns: bool: Whether the request was successfully submitted
    """
    url = get_notify_url(app_id, app_secret, body, subject, recipients, channel,
                         error_channel, error_recipients)
    resp = _get_resp(url)
    return resp['status'] == 'success'
