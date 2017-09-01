"""This processes JSON-formatted notification requests as local web server.

https://github.com/kristovatlas/twoifbysea

Security note: Communication occurs over HTTP without TLS encryption, so it is
assumed that additional encryption layers will be used if required in transit.
As programs running on the same machine can often sniff localhost traffic,
this is a somewhat perilous configuration; it should be improved upon in the
future, probably by using protocols other than HTTP.

Paths:
    /get_app_secrets -- generates a new app_id and app_secret

    Ex.
    http://127.0.0.1:51337/get_app_secrets

    Responds with:
        {'app_id': 'abcdefg...', 'app_secret': 'abcdefg...'}
        where both 'app_id' and 'app_secret' are base64-encoded strings, and
        'app_secret' is an AES-256 decryption key specific to the app.

    /start_digest -- start a digest aler to be sent regularly

    Ex. http://127.0.0.1:51337/start_digest?app_id=bXkgYXBwIGlkIGlzIHRoaXM-&
        app_secret=dGhpcyBpcyBteSBhcHAgc2VjcmV0&frequency=1day&
        recipient=bob@example.com

    Responds with:
    {'status:' 'success|error', 'message':'...'}
    If the status is 'success' then the message will be a base64-encoded string
    representing the "topic" identifier for this digest. The "topic" parameter
    can then be supplied to the /notify endpoint.

    /store -- KV store arbitrary data to be stored encrypted and fetched later

    Ex. http://127.0.0.1:51337/store?app_id=bXkgYXBwIGlkIGlzIHRoaXM-&
        app_secret=dGhpcyBpcyBteSBhcHAgc2VjcmV0&key=gmail_username&
        value=mypassword

    Responds with:
        {'status': 'success|error', 'message':'...'}

    Keys to store with special meaning:
        * gmail_username
        * gmail_password

    /notify -- add a notification to the send queue

    TODO: It would probably be better to receive lists of recipients and error_recipients?????

    Ex.
    http://127.0.0.1:51137/notify?channel=email&subject=My%20Subject&recipient=
        bob@example.com&body=This%20Is%20My%20URL-encoded%20message&
        error_channel=email&error_recipient=disappointed%40admin.com&
        app_id=W1MaBNIwveunv4UHBCtv97rpcgmzApnJxa4WuOx1Xcc=&
        app_secret=Tuf2L3uxDjzG8JkftVpmhjstUe9iI3U5RPKiRyQGf7s=

    Required fields:
        * channel
        * subject
        * recipient
        * body

    Optional fields:
        * when
        * error_channel
        * error_recipient
        * app_id
        * app_secret
        * topic -- genereated from call to /start_digest

    Responds with:
        {'status': 'success|error', 'message': '...'}

Caveats:
    * Arguments provided that are not expected are simply ignored.
    * Duplicate values for arguments are ignored (first used)
    * Arguments must be URL-encoded
    * Arguments may be UTF-8 encoded
    * Arguments will be decoded before storage in the message queue

Returns responses with the following HTTP status codes:
    * 200 (OK)
    * 400 (Bad Request)
    * 500 (Internal Server Error)
"""

#Standard Python Library 2.7
import urllib
import time
import json
import logging
import BaseHTTPServer
import sys
from collections import OrderedDict
from urlparse import urlparse, parse_qs

#twoifbysea modules
import common #common.py
import datastore #datastore.py

DEBUG_MODE = True

if DEBUG_MODE:
    import traceback

HOST_NAME = '127.0.0.1'
#Not commonly taken: http://www.speedguide.net/port.php?port=51337&print=friendly
PORT_NUMBER = 51337

JSON_TYPE = "application/json"

NOTIFY_REQUIRED_ARGS = ['channel', 'subject', 'recipient', 'body']

STORE_REQUIRED_ARGS = ['app_id', 'app_secret', 'key', 'value']

START_DIGEST_REQUIRED_ARGS = ['app_id', 'app_secret', 'frequency', 'recipient']

SUPPORTED_CHANNELS = {
    #Maps string repr of channel to enum
    'gmail': common.SupportedChannels.GMAIL
}
SUPPORTED_TIMES = {
    #maps string repr of time to enum
    'once_next_batch': common.SupportedTimes.ONCE_NEXT_BATCH,
    'repeat_daily': common.SupportedTimes.REPEAT_DAILY
}

ALLOWED_STATUSES = ['success', 'error']

class ServerResponse(object):
    """The information returned to the HTTP requester for notification requests"""
    def __init__(self, status, message):
        assert isinstance(status, str)
        assert isinstance(message, str)
        assert status in ALLOWED_STATUSES
        self.response = OrderedDict()
        self.response = {'status': status, 'message': message}

    def __str__(self):
        return json.dumps(self.response)

    def __repr__(self):
        return self.__str__()

def process_store(handler, arguments, db_con=None):
    """Process a request to store a key/val pair in db

    Returns: None
    """
    assert isinstance(handler, BaseHTTPServer.BaseHTTPRequestHandler)
    assert isinstance(arguments, dict)
    assert isinstance(db_con, datastore.DatabaseConnection) or db_con is None

    if db_con is None:
        try:
            db_con = datastore.DatabaseConnection()
        except datastore.DatabaseReadError:
            return handler.server_error('Unable to connect to database.')

    #ensure required args are present
    for required_arg in STORE_REQUIRED_ARGS:
        if required_arg not in arguments:
            return handler.invalid_request(
                "Missing argument '{0}' from arguments".format(required_arg))

    #handle URL encoding
    for key, val_list in arguments.items():
        val = val_list[0] #only use first value for specified GET param
        arguments[key] = urllib.unquote(val).decode('utf8')

        if DEBUG_MODE:
            print "DEBUG: URL params: {0}={1}".format(key, val)

    #validate args
    try:
        arguments['app_id'] = str(arguments['app_id'])
        common.b64decode(arguments['app_id'])
        assert arguments['app_id'] != ''
        arguments['app_secret'] = str(arguments['app_secret'])
        common.b64decode(arguments['app_secret'])
        assert arguments['app_id'] != ''
        arguments['key'] = str(arguments['key'])
        arguments['value'] = str(arguments['value'])
    except (AssertionError, TypeError), err:
        if DEBUG_MODE:
            print 'One of the arguments failed validation: {0}'.format(err)
        handler.invalid_request('Invalid app_id or app_secret')

    try:
        db_con.store_key_val(app_id=arguments['app_id'],
                             app_secret=arguments['app_secret'],
                             key=arguments['key'],
                             val=arguments['value'])
    except datastore.DatabaseWriteError:
        handler.invalid_request('Failed to store key/value pair.')

    return handler.success('Key/value pair stored.')


def process_secrets(handler, arguments, db_con=None):
    """Process a request to get app secrets.

    Returns: None
    """
    assert isinstance(handler, BaseHTTPServer.BaseHTTPRequestHandler)
    assert isinstance(arguments, dict)
    assert isinstance(db_con, datastore.DatabaseConnection) or db_con is None

    if db_con is None:
        try:
            db_con = datastore.DatabaseConnection()
        except datastore.DatabaseReadError:
            return handler.server_error('Unable to connect to database.')

    new_app_id = datastore.generate_app_id()
    new_app_secret = datastore.generate_app_secret()

    return handler.response_secrets(new_app_id, new_app_secret)


def process_notification(handler, arguments, db_con=None):
    """Process a request for a notification.

    TODO: Add handling of 'topic' argument

    Args:
        handler (BaseHTTPServer.BaseHTTPRequestHandler): The handler handling
            the HTTP request tp notify.
        arguments (dict): The parsed version of the HTTP query extracted from
            the URL following '?'
        db_con (Optional[datastore.DatabaseConnection]): A connection to the
            database that handles the notification queue.

    Arguments are url-decoded (including UTF-8 encoding) before being added to
    a sending queue.

    Returns: None
    """
    assert isinstance(handler, BaseHTTPServer.BaseHTTPRequestHandler)
    assert isinstance(arguments, dict)
    assert isinstance(db_con, datastore.DatabaseConnection) or db_con is None

    if db_con is None:
        try:
            db_con = datastore.DatabaseConnection()
        except datastore.DatabaseReadError:
            return handler.server_error('Unable to connect to database.')

    #ensure required args are included
    for required_arg in NOTIFY_REQUIRED_ARGS:
        if required_arg not in arguments:
            return handler.invalid_request(
                "Missing argument '{0}' from arguments".format(required_arg))

    #handle URL encoding
    for key, val_list in arguments.items():
        val = val_list[0] #only use first value for specified GET param
        arguments[key] = urllib.unquote(val).decode('utf8')
        if DEBUG_MODE:
            print "DEBUG: key={0} val={1}".format(key, val)

    #validate channel
    if arguments['channel'] not in SUPPORTED_CHANNELS:
        return handler.invalid_request('Invalid channel specified')

    #try to set up notification request object
    notif = common.NotificationRequest()
    try:
        notif.set_channel(SUPPORTED_CHANNELS[arguments['channel']])
    except AssertionError:
        return handler.invalid_request('Channel not supported')

    try:
        notif.add_recipient(arguments['recipient'])
    except AssertionError, err:
        err_msg = 'Invalid recipient'
        if DEBUG_MODE:
            err_msg += " ({0})".format(err)
        return handler.invalid_request(err_msg)
    except common.CommunicationChannelNotYetSetError:
        return handler.server_error()
    except common.IncompatibleRecipientAddedError:
        return handler.server_error()

    try:
        notif.set_subject(arguments['subject'])
    except AssertionError:
        return handler.invalid_request('Invalid subject')

    if 'when' in arguments:
        if arguments['when'] not in SUPPORTED_TIMES:
            return handler.invalid_request("Invalid 'when' argument specified.")
        else:
            notif.set_when(SUPPORTED_TIMES[arguments['when']])

    try:
        notif.set_message(arguments['body'])
    except AssertionError:
        return handler.invalid_request('Invalid message body')

    try:
        db_con.add_notification(notif)
    except datastore.DatabaseWriteError, err:
        err_msg = ("Web server encountered error attempting to add "
                   "notification to queue: {0}").format(err)
        common.log(msg=err_msg, level=logging.ERROR)
        return handler.notif_add_fail()

    return handler.success()


def process_start_digest(handler, arguments, db_con=None):
    """Process a request to start a digest alert.

    A digest alert accumulates multiple messages into a batch and then sends
    a summary in a single alert message to the recipient on a regular basis.
    If no messages have been accumulated during that time period, an alert
    is sent indicating that no messages were accumulated.

    Args:
        handler (BaseHTTPServer.BaseHTTPRequestHandler): The handler handling
            the HTTP request tp notify.
        arguments (dict): The parsed version of the HTTP query extracted from
            the URL following '?'
        db_con (Optional[datastore.DatabaseConnection]): A connection to the
            database that handles the notification queue.

    Returns: None
    """
    assert isinstance(handler, BaseHTTPServer.BaseHTTPRequestHandler)
    assert isinstance(arguments, dict)
    assert isinstance(db_con, datastore.DatabaseConnection) or db_con is None

    if db_con is None:
        try:
            db_con = datastore.DatabaseConnection()
        except datastore.DatabaseReadError:
            return handler.server_error('Unable to connect to database.')

    #ensure required args are included
    for required_arg in START_DIGEST_REQUIRED_ARGS:
        if required_arg not in arguments:
            return handler.invalid_request(
                "Missing argument '{0}' from arguments".format(required_arg))

    #handle URL encoding
    for key, val_list in arguments.items():
        val = val_list[0] #only use first value for specified GET param
        arguments[key] = urllib.unquote(val).decode('utf8')
        if DEBUG_MODE:
            print "DEBUG: key={0} val={1}".format(key, val)

    #TODO: store this digest in db and return a topic id






FUNCTIONS = {
    #Maps an endpoint to a function that handles the request
    '/notify': process_notification,
    '/get_app_secrets': process_secrets,
    '/store': process_store,
    '/start_digest': process_start_digest
}


class DummyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """Used only for unit testing."""
    def do_GET(self):
        """Fake GET hanlder."""
        pass

    def success(self, _json):
        """Fake success function."""
        pass

    def invalid_request(self, message):
        """Fake function."""
        pass


#From https://wiki.python.org/moin/BaseHttpServer
class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """Handler for HTTP requests.

    Returns: None
    """
    def do_GET(self):
        """Respond to a GET request.

        Returns: None
        """

        db_con = None
        try:
            db_con = datastore.DatabaseConnection()
        except datastore.DatabaseReadError:
            return self.server_error('Unable to connect to database.')

        #Match path to processing function
        urlparsed = urlparse(self.path)
        if urlparsed.path not in FUNCTIONS:
            return self.invalid_request(
                'Path specified is not in the list of valid paths.')

        try:
            FUNCTIONS[urlparsed.path](self, parse_qs(urlparsed.query), db_con)
        except Exception, err:
            err_msg = 'Uncaught error exception'
            if DEBUG_MODE:
                err_msg += ": {0}".format(err)
                err_msg += str(traceback.format_exc())
            return self.invalid_request(err_msg)

    def success(self, msg=None):
        """Communicate successful addition of the notification to queue"""
        if msg is None:
            msg = 'notification was added to send queue.'
        self.send_response(200)
        self.send_header("Content-type", JSON_TYPE)
        self.end_headers()
        resp = ServerResponse(status='success', message=msg)
        self.wfile.write(resp)

    def response_secrets(self, app_id, app_secret):
        """Communicate newly generated secrets to requester"""
        self.send_response(200)
        self.send_header("Content-type", JSON_TYPE)
        self.end_headers()
        resp = {'app_id': app_id, 'app_secret': app_secret}
        self.wfile.write(json.dumps(resp))

    def invalid_request(self, message):
        """Reply with message about why request is invalid.

        HTTP 400:
        "The server cannot or will not process the request due to an apparent
        client error (e.g., malformed request syntax, too large size, invalid
        request message framing, or deceptive request routing)."
        """
        self.send_response(400)
        self.send_header("Content-type", JSON_TYPE)
        self.end_headers()

        resp = ServerResponse(status='error', message=message)
        self.wfile.write(resp)

    def server_error(self, message=None):
        """Reply with generic server error.

        HTTP 500:
        A generic error message, given when an unexpected condition was
        encountered and no more specific message is suitable.
        """
        self.send_response(500)
        self.send_header("Content-type", JSON_TYPE)
        self.end_headers()
        if message is None:
            message = 'Uncaught server error handling request'

        resp = ServerResponse(status='error', message=message)
        self.wfile.write(resp)

    def notif_add_fail(self):
        """Server failed to add notification to queue."""
        self.send_response(500)
        self.send_header("Content-type", JSON_TYPE)
        self.end_headers()

        message = 'Server failed to add notification to queue.'
        resp = ServerResponse(status='error', message=message)
        self.wfile.write(resp)

def _main():
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    msg = "Server Starts - {0}:{1}".format(HOST_NAME, PORT_NUMBER)
    common.log(msg=msg, level=logging.INFO)
    print time.asctime(), msg

    #confirm db is accessible and properly initialized
    try:
        datastore.DatabaseConnection()
    except datastore.DatabaseReadError:
        httpd.server_close()
        msg = 'Error: Webserver unable to access database. Exiting.'
        common.log(msg=msg, level=logging.CRITICAL)
        sys.exit(msg)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    msg = "Server Stops - {0}:{1}".format(HOST_NAME, PORT_NUMBER)
    common.log(msg=msg, level=logging.INFO)
    print time.asctime(), msg

if __name__ == '__main__':
    _main()
