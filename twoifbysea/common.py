# -*- coding: utf-8 -*-
"""Common functions for twoifbysea

https://github.com/kristovatlas/twoifbysea
"""

#Standard Python Library 2.7
import re
from email.utils import parseaddr
import logging
import sys
import uuid
from enum import Enum
import os
import base64

#pip modules
import appdirs
from validate_email import validate_email

APPNAME = 'twoifbysea'
AUTHOR = 'atlas'

LOG_FILENAME = 'twoifbysea.log'

DISALLOWED_EMAIL_ADDR_CHARS = ['#', ' ']
EMAIL_ADDR_REGEX = r'^[^@]+@[^-@][^@]*\.[^@]+$'

EMAIL_ADDR_SEPARATOR = ','

URL_SAFE_ALT_CHARS = '-_' #for url-safe base64-encoded strings

def log(msg, level=logging.INFO, do_exit=False):
    """Add a string to the log file and optionally exit with error msg"""
    logging.basicConfig(filename=LOG_FILENAME,
                        format='%(asctime)s:%(levelname)s:%(message)s',
                        level=logging.INFO)
    if level == logging.DEBUG:
        logging.debug(msg)
    elif level == logging.INFO:
        logging.info(msg)
    elif level == logging.WARNING:
        logging.warning(msg)
    elif level == logging.ERROR:
        logging.error(msg)
    elif level == logging.CRITICAL:
        logging.critical(msg)
    else:
        raise ValueError(str(level))

    if do_exit:
        sys.exit(msg)


#pylint: disable=R0903
class SupportedChannels(Enum):
    """Communication channels by which notifications can be sent"""
    EMAIL = 0   #Send an email to a recipient email address
    LOGFILE = 1 #Log to file locally
    GMAIL = 2   #Send an email to a recipient email address via GMail
    TELEGRAM = 3 #Send via Telegram bot account

class SupportedTimes(Enum):
    """When notifications can be sent"""
    #ONCE_NOW = 0 (TODO)
    ONCE_NEXT_BATCH = 1
    REPEAT_DAILY = 100

DEFAULT_CHANNEL = SupportedChannels.GMAIL
DEFAULT_TIME = SupportedTimes.ONCE_NEXT_BATCH
DEFAULT_ERROR_CHANNEL = SupportedChannels.LOGFILE

class SubjectNotSupportedError(Exception):
    """The 'subject' field isn't supported for this notification channel"""
    pass

class CommunicationChannelNotYetSetError(Exception):
    """Comm channel must be selected before doing things such as adding recipients."""
    pass

class IncompatibleRecipientAddedError(Exception):
    """The recipient designated is not valid for this type of comm channel."""
    pass

class NotificationRequest(object):
    """Definition of a request sent to sender to send a notification

    Setting of attributes should be achieved through setter methods, e.g.
    `set_channel` or `add_recipient`.

    Getting of attributes should be achieved by referencing the appropriate
    attribute using dot notation, e.g. `nr.channel` or `nr.recipients`.
    """
    def __init__(self):
        self.channel = DEFAULT_CHANNEL
        self.recipients = set()
        self.sender = None
        self.subject = None
        self.message = None
        self.when = DEFAULT_TIME

        #In the event sending fails, where should the error be sent?
        self.error_channel = DEFAULT_ERROR_CHANNEL
        self.error_recipients = set()

        self.uuid = None

    def set_channel(self, channel):
        """Set the channel over which to send notification."""
        assert isinstance(channel, SupportedChannels)
        self.channel = channel

    def add_recipient(self, recipient):
        """Add notificiation recipient

        Raises:
            * CommunicationChannelNotYetSetError
            * IncompatibleRecipientAddedError: When channel is a logfile
        """
        assert type(recipient) in (str, unicode)
        assert recipient != '', "recipient is emtpy string"

        try:
            self.channel
        except AttributeError:
            raise CommunicationChannelNotYetSetError()

        if self.channel is None:
            raise CommunicationChannelNotYetSetError()

        #Validate recipient appears valid
        if self.channel in (SupportedChannels.EMAIL, SupportedChannels.GMAIL):
            assert is_valid_email_addr(recipient), "Email address not valid"
        elif self.channel == SupportedChannels.LOGFILE:
            raise IncompatibleRecipientAddedError(
                "Log file cannot have recipients.")

        self.recipients.add(recipient)

    def set_sender(self, sender):
        """Set the sender of the notification. Separate from authentication"""
        assert type(sender) in (str, unicode)
        assert sender != ''

        #Validate sender appears valid
        if self.channel in (SupportedChannels.EMAIL, SupportedChannels.GMAIL):
            assert is_valid_email_addr(sender)

        self.sender = sender

    def set_subject(self, subject):
        """Set the subject of the notification, if relevant to channel.

        Subject MAY be empty string.
        """
        assert type(subject) in (str, unicode)

        if self.channel in (SupportedChannels.EMAIL, SupportedChannels.GMAIL):
            self.subject = subject
        else:
            raise SubjectNotSupportedError(
                "Subject not supported for channel {0}".format(self.channel))

    def set_when(self, _time):
        """Set when the notification should be sent"""
        assert isinstance(_time, SupportedTimes)
        self.when = _time

    def set_message(self, message):
        """Set the contents of the notification"""
        assert type(message) in (str, unicode)
        self.message = message

    def set_error_channel(self, channel):
        """Set the channel for communication sending errors"""
        assert isinstance(channel, SupportedChannels)
        self.error_channel = channel

    def add_error_recipient(self, recipient):
        """Add a recipient of sending error messages"""
        assert type(recipient) in (str, unicode)
        assert recipient != ''

        try:
            self.error_channel
        except AttributeError:
            raise CommunicationChannelNotYetSetError("Error channel not set")

        if self.error_channel is None:
            raise CommunicationChannelNotYetSetError("Error channel not set")
        elif self.error_channel == SupportedChannels.LOGFILE:
            raise IncompatibleRecipientAddedError(
                "Errors logged to log file cannot have recipients.")

        self.error_recipients.add(recipient)

    def assign_random_uuid(self):
        """Assign this notification request a random UUID so it can be tracked

        Users of this class can ignore this method and attribute; it's only Used
        by the database class to track notfiication requests that cannot be
        serviced successfully and need to be re-added to the notification
        queue.
        """
        if not hasattr(self, 'uuid') or self.uuid is None:
            self.uuid = str(uuid.uuid4())

def is_valid_email_addr(email_addr):
    """Test if email address is valid

    Reference:
    http://stackoverflow.com/questions/8022530/python-check-for-valid-email-address#8022584

    See tests/test_common.py for unit tests.
    """
    try:
        for char in DISALLOWED_EMAIL_ADDR_CHARS:
            assert char not in email_addr

        assert re.match(EMAIL_ADDR_REGEX, email_addr)
        assert validate_email(email_addr)
        #should be alphabetical TLD or hostname is IPv4 address
        assert email_addr.split('.')[-1].isalpha() or \
            is_valid_ip(email_addr.split('@')[-1])
        _, address = parseaddr(email_addr)
        assert '@' in address

    except AssertionError:
        return False
    return True

def is_valid_ip(address):
    """Test if IP address is valid

    Reference:
    http://stackoverflow.com/questions/11264005/using-a-regex-to-match-ip-addresses-in-python#11264379
    """
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b<=255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False

def email_list_to_str(email_list):
    """Convert list of email addresses into a string repr"""
    return EMAIL_ADDR_SEPARATOR.join(email_list)

def email_str_to_list(email_str):
    """Convert email list represented as string to a list"""
    return email_str.split(EMAIL_ADDR_SEPARATOR)

def get_app_file_loc(filename):
    """Get string repr of file path for specified filename in application's dir"""
    app_dir = appdirs.user_data_dir(APPNAME, AUTHOR)
    if not os.path.isdir(app_dir):
        os.makedirs(app_dir)
    return os.path.join(app_dir, filename)

def b64encode(_str):
    """URL-safe base-64 encode string"""
    return base64.b64encode(_str, altchars=URL_SAFE_ALT_CHARS)

def b64decode(_str):
    """URL-safe base-64 decode string"""
    return base64.b64decode(_str, altchars=URL_SAFE_ALT_CHARS)
