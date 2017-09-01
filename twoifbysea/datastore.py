"""Stores notifications in a queue until they can be processed for sending.

https://github.com/kristovatlas/twoifbysea

Todos:
    * When an error occurs, allow user to config channel to communicate an error
        alert to be sent out. Catch-22: Can't use normal notification mechanism;
        maybe requires 'now' as a time parameter to be implemented.
    * Consider using multihash protocol for blake2 hashing fo key:
        https://github.com/multiformats/multihash

Version 2 Schema:
    * info:
        * version (INTEGER)
        * date_created (INTEGER)
    * msg_queue
        * id (INTEGER PRIMARY KEY AUTOINCREMENT)
        * date_added (INTEGER)
        * channel (INTEGER)
        * recipients (TEXT)
        * sender (TEXT)
        * subject (TEXT)
        * message (TEXT)
        * time_to_send (INTEGER) note: 'WHEN' is a SQL keyword
        * error_channel (INTEGER)
        * error_recipients (TEXT)
        * uuid (TEXT)
    * encrypted_kv_store
        * app_id (TEXT)
        * key (TEXT)
        * value (TEXT)
        * value_iv (TEXT)
    *
"""

#Standard Python Library 2.7
import sqlite3
import logging
import os
import uuid

#pip modules
import blake2

#twoifbysea modules
import common #common.py
from crypt import encrypt, decrypt #crypt.py

DB_FILENAME_DEFAULT = '{0}.db'.format(common.APPNAME)
DB_VERSION = 1

ENCRYPTION_MAGIC_NUMBER = 'twoifbysea'

DB_SELECT_RETURNED_NULL_MSG = 'Received null value instead of row.'

APP_ID_BYTES = 32
APP_SECRET_BYTES = 32

class DatabaseWriteError(Exception):
    """There was a problem writing to the database."""
    pass

class DatabaseReadError(Exception):
    """There was a problem reading from the database."""
    pass

class EmptyQueueError(Exception):
    """The notification queue is currently empty."""
    pass

class DecryptionFailError(Exception):
    """The decryption failed, possibly due to wrong app secret."""
    pass

class DatabaseTable(object):
    """Represents a table in the database"""
    def __init__(self):
        self.name = ''
        self.cols = tuple() # ((col_name1, col_type1), (col_name2, col_type2)..)

    def get_create_statement(self):
        """Generate SQL statement to create this table"""
        assert isinstance(self.cols, tuple)
        stmt = 'CREATE TABLE {0} ('.format(self.name)

        name_type_pairs = ["{n} {t}".format(n=n, t=t) for n, t in self.cols]
        stmt += ','.join(name_type_pairs)
        stmt += ')'
        return stmt

TBL_INFO = DatabaseTable()
TBL_INFO.name = 'info'
TBL_INFO.cols = (('version', 'INTEGER'),
                 ('date_created', 'INTEGER'))

TBL_MSG_QUEUE = DatabaseTable()
TBL_MSG_QUEUE.name = 'msg_queue'
TBL_MSG_QUEUE.cols = (('id', 'INTEGER PRIMARY KEY AUTOINCREMENT'),
                      ('date_added', 'INTEGER'),
                      ('channel', 'INTEGER'),
                      ('recipients', 'TEXT'),
                      ('sender', 'TEXT'),
                      ('subject', 'TEXT'),
                      ('message', 'TEXT'),
                      ('time_to_send', 'INTEGER'),
                      ('error_channel', 'INTEGER'),
                      ('error_recipients', 'TEXT'),
                      ('uuid', 'TEXT'))

TBL_CRYPT_KV_STORE = DatabaseTable()
TBL_CRYPT_KV_STORE.name = 'encrypted_kv_store'
TBL_CRYPT_KV_STORE.cols = (('app_id', 'TEXT'),
                           ('key', 'TEXT'),
                           ('value', 'TEXT'),
                           ('value_iv', 'TEXT'))

ALL_TABLES = [TBL_INFO, TBL_MSG_QUEUE, TBL_CRYPT_KV_STORE]

class DatabaseConnection(object):
    """A connection to the database.
    Usage:
        with datastore.DatabaseConnection() as db_con:
            db_con.foo()
            ...
    """

    def __init__(self, filename=DB_FILENAME_DEFAULT, file_path_abs=False):
        """Note -- may be prone to a few TOCTOU issues related to the db flie if
        changed externally.

        Args:
            filename (str): Absolute or relative filename of the db file
            file_path_abs (Optional[bool]): Determines whether filename is
                interpretted as absolute or relative. If relative, file will
                be referenced with the default application data directory.

        Raises: DatabaseReadError: If database version in sqlite file is not
            supported.
        """
        if file_path_abs:
            self.filename = filename
        else:
            self.filename = common.get_app_file_loc(filename)

        if os.path.isfile(self.filename):
            #TODO: handle unreadability and unwritability with alert notifications
            self.conn = sqlite3.connect(self.filename)
            assert os.access(self.filename, os.W_OK)

            if os.stat(self.filename).st_size == 0:
                self.table_init()

            if self.check_version() != 1:
                msg = "Unsupported database version!"
                common.log(msg=msg, level=logging.CRITICAL)
                raise DatabaseReadError(msg)

        else:
            common.log(msg="Database file does not exist. Initializing.",
                       level=logging.INFO)
            self.conn = sqlite3.connect(self.filename)
            self.table_init()

    def __enter__(self):
        return self

    def __exit__(self, exec_type, exec_value, exec_traceback):
        self.conn.close()

    def fetch_one_row(self, stmt, arglist=None, err_msg=None,
                      err_log_level=logging.ERROR):
        """Fetch one row according to SQL select statement

        Returns: A row; never None

        Raises: DatabaseReadError
        """
        if arglist is None:
            arglist = ()

        try:
            row = self.conn.cursor().execute(stmt, arglist).fetchone()
            if row is not None:
                return row
            raise ValueError(DB_SELECT_RETURNED_NULL_MSG)
        except (sqlite3.OperationalError, ValueError), err:
            msg = combine_err_msgs(err, err_msg)
            common.log(msg=msg, level=err_log_level)
            raise DatabaseReadError(msg)

    def fetch_first_col(self, stmt, arglist=None, err_msg=None,
                        err_log_level=logging.ERROR):
        """Return the 0th item of the first row according to SQL select stmt

        Returns: A single variable or None if the value is NULL
        """
        try:
            return self.fetch_one_row(stmt, arglist, err_msg, err_log_level)[0]
        except (DatabaseReadError, IndexError), err:
            msg = combine_err_msgs(err, err_msg)
            common.log(msg=msg, level=err_log_level)
            raise DatabaseReadError(msg)

    def fetch_first_int(self, stmt, arglist=None, err_msg=None,
                        err_log_level=logging.ERROR):
        """Return the 0th integer item of the first row according SQL select stmt

        Returns: An integer; never None

        Raises: DatabaseReadError if unable to read from db or value is None
        """
        try:
            col = int(self.fetch_first_col(
                stmt, arglist, err_msg, err_log_level))
            if col is not None:
                return col
            raise ValueError("Value is NULL")
        except (DatabaseReadError, ValueError, TypeError), err:
            msg = combine_err_msgs(err, err_msg)
            common.log(msg=msg, level=err_log_level)
            raise DatabaseReadError(msg)

    def _create_table(self, stmt):
        """Execute CREATE TABLE statement

        Raises: DatabaseWriteError if table cannot be created
        """
        try:
            self.sql_execute(stmt)
        except sqlite3.OperationalError, err:
            msg = "Error creating table: {0}".format(err)
            common.log(msg=msg, level=logging.ERROR)
            raise DatabaseWriteError(msg)

    def table_init(self):
        """Initialize database w/ required tables and return num of failures

        Raises: DatabaseWriteError if database's tables cannot be initialized
        """
        for table in ALL_TABLES:
            stmt = table.get_create_statement()
            try:
                self._create_table(stmt)
            except DatabaseWriteError, err:
                raise DatabaseWriteError(str(err))

        stmt = 'INSERT INTO {0} VALUES (?, CURRENT_TIMESTAMP)'.format(
            TBL_INFO.name)
        arglist = (DB_VERSION,)
        try:
            self.sql_execute(stmt, arglist)
        except sqlite3.OperationalError, err:
            msg = "Error initializing table: {0}".format(err)
            common.log(msg, logging.CRITICAL)
            raise DatabaseWriteError(msg)

    def sql_execute(self, stmt, arglist=None):
        """Execute the SQL statement and return number of db changes

        Raises: DatabaseWriteError if statement couldn't be executed
        """
        try:
            if arglist is not None:
                self.conn.cursor().execute(stmt, arglist)
            else:
                self.conn.cursor().execute(stmt)
            self.conn.commit()
            num_changes = self.conn.total_changes
        except sqlite3.OperationalError, err:
            msg = "Unable to execute statement: {0}: {1}".format(stmt, err)
            common.log(msg, logging.ERROR)
            raise DatabaseWriteError(msg)
        return num_changes

    def check_version(self):
        """Get the version of this database

        Raises: DatabaseReadError if the version cannot be fetched
        """
        stmt = 'SELECT version FROM {0}'.format(TBL_INFO.name)
        try:
            return self.fetch_first_int(
                stmt,
                arglist=None,
                err_msg='Failed to select version from table',
                err_log_level=logging.CRITICAL)
        except DatabaseReadError, err:
            raise DatabaseReadError(str(err))

    def add_notification(self, notif_req):
        """Add a notification to the queue.

        Raises: DatabaseWriteError if notification was not added to the queue
        """
        assert isinstance(notif_req, common.NotificationRequest)
        stmt = ('INSERT INTO {0} (date_added, channel, recipients, sender, '
                'subject, message, time_to_send, error_channel, '
                'error_recipients, uuid) VALUES (CURRENT_TIMESTAMP, '
                '?, ?, ?, ?, ?, ?, ?, ?, ?)').format(TBL_MSG_QUEUE.name)
        nr_uuid = None
        if hasattr(notif_req, 'uuid'):
            nr_uuid = notif_req.uuid

        arglist = (notif_req.channel.value,
                   common.email_list_to_str(notif_req.recipients),
                   notif_req.sender,
                   notif_req.subject,
                   notif_req.message,
                   notif_req.when.value,
                   notif_req.error_channel.value,
                   common.email_list_to_str(notif_req.error_recipients),
                   nr_uuid)
        try:
            self.sql_execute(stmt, arglist)
        except sqlite3.Error, err:
            msg = "Error adding notification to queue: {0}".format(err)
            common.log(msg=msg, level=logging.ERROR)
            common.log(msg="Bad statement was: {0}".format(stmt),
                       level=logging.ERROR)
            common.log(msg="Bad arglist was: {0}".format(str(arglist)),
                       level=logging.ERROR)
            raise DatabaseWriteError(msg)

    def get_queue_size(self):
        """Get the number of messages currently in the queue.

        Raises: DatabaseReadError if queue size cannot be read
        """
        stmt = 'SELECT COUNT(*) FROM {0}'.format(TBL_MSG_QUEUE.name)
        try:
            return self.fetch_first_int(
                stmt, arglist=None, err_msg='Unable to measure queue size')
        except DatabaseReadError, err:
            raise DatabaseReadError(str(err))

    def pop_notif(self):
        """Pop the oldest message from the queue.

        Returns: NotificationRequest object

        Raises:
            * EmptyQueueError if it's empty
            * DatabaseReadError if the queue cannot be read from
            * DatabaseWriteError if the message fails to be removed from the
                queue aftering being read
        """
        try:
            queue_size = self.get_queue_size()
        except DatabaseReadError, err:
            msg = ('Unable to measure queue size -- cannot pop message from '
                   'queue: {0}').format(err)
            common.log(msg, logging.ERROR)
            raise DatabaseReadError(msg)
        if queue_size == 0:
            raise EmptyQueueError()

        select = 'SELECT * FROM {0} ORDER BY id LIMIT 1'.format(
            TBL_MSG_QUEUE.name)
        row = None
        try:
            row = self.fetch_one_row(
                select, arglist=None,
                err_msg='Unable to fetch a message from the queue')

        except DatabaseReadError, err:
            raise DatabaseReadError(str(err))
            #TODO: Send out notification of failed pop once supported

        row_id = -1
        try:
            row_id = int(row[0])
        except ValueError, err:
            err_msg = ("Attemtped to decode row id but encountered non-int "
                       "vaule: {0}").format(err)
            common.log(msg=err_msg, level=logging.ERROR)
            raise DatabaseWriteError(err_msg)

        delete = 'DELETE FROM {0} WHERE id = ?'.format(TBL_MSG_QUEUE.name)
        arglist = (row_id,)

        try:
            self.sql_execute(delete, arglist)
        except DatabaseWriteError, err:
            err_msg = str(err)
            err_msg += ' (failed to delete message popped from queue)'
            common.log(msg=err_msg, level=logging.ERROR)
            raise DatabaseWriteError(err_msg)

        return msg_queue_row_to_notif(row)

    def get_iv(self, app_id, hashed_key):
        """Fetch the IV used to value referenced by the hashed key

        Args:
            app_id (str): The base-64 encoded string assigned to the app
                performing the query
            hashed_key (str): The base64-encoded string representation of the
                keyed-hashed version of the key.

        Returns val_iv where both are base64-encoded strings
        """
        assert isinstance(app_id, str)
        assert isinstance(hashed_key, str)
        common.b64decode(app_id)
        common.b64decode(hashed_key)

        stmt = 'SELECT value_iv FROM {0} WHERE app_id = ? AND key = ?'.format(
            TBL_CRYPT_KV_STORE.name)
        arglist = (app_id, hashed_key)
        val_iv = str(self.fetch_first_col(stmt, arglist))
        assert isinstance(val_iv, str)
        common.b64decode(val_iv)

        return val_iv

    def get_key_val(self, app_id, app_secret, key):
        """Get plaintext of encrypted val from database
        Args:
            app_id (str): Base64-encoded string identifying the app for whom we
                are storing data
            app_secret (str): Base64-encoded string unique to the app that is
                used to encrypt and decrypt data
            key (str): The plaintext name of the value being stored. Not to be
                confused with the encryption key.

        The following are stored in the database:
        * app_id
        * hash of key with hash-key app_secret; keying the hash helps protect
            the contents of the key being stored against an attacker that does
            not know the app_secret.
        * value_iv, the iv used to encrypt the value using AES256-CBC
        * encrypted value, encrypted with value_iv using AES256-CBC and padding

        Returns: str: The plaintext value decrypted

        Raises: DecryptionFailError: If the plaintext value cannot be returned
        """
        assert isinstance(app_id, str)
        assert isinstance(app_secret, str)
        assert isinstance(key, str)
        common.b64decode(app_id)
        common.b64decode(app_secret)

        hashed_key = blake2.blake2(data=key, hashSize=64, key=app_secret)

        stmt = 'SELECT value, value_iv FROM {0} WHERE app_id = ? AND key = ?'.format(
            TBL_CRYPT_KV_STORE.name)
        arglist = (app_id, hashed_key)
        try:
            row = self.fetch_one_row(stmt, arglist)
        except DatabaseReadError, err:
            if str(err) == DB_SELECT_RETURNED_NULL_MSG:
                raise DecryptionFailError('Failed to decrypt value')

        assert len(row) == 2
        value_ciphertext = str(row[0])
        value_iv = str(row[1])
        common.b64decode(value_ciphertext)
        common.b64decode(value_iv)

        value = decrypt(ciphertext=value_ciphertext, key=app_secret, iv=value_iv)

        #This sanity check is probably not required, but we add a magic prefix
        #value to ensure that the plaintext proudced from decryption looks good.
        if value[0:len(ENCRYPTION_MAGIC_NUMBER)] != ENCRYPTION_MAGIC_NUMBER:
            raise DecryptionFailError('Failed to decrypt value')

        return value[len(ENCRYPTION_MAGIC_NUMBER):]

    def store_key_val(self, app_id, app_secret, key, val):
        """Stores key and val and encrypted form

        Args:
            app_id (str): Base64-encoded string identifying the app for whom we
                are storing data
            app_secret (str): Base64-encoded string unique to the app that is
                used to encrypt and decrypt data
            key (str): The plaintext name of the value being stored. Not to be
                confused with the encryption key.
            val (str): The plaintext value being stored

        Raises: DatabaseWriteError if storage fails
        """
        assert isinstance(app_id, str)
        assert isinstance(app_secret, str)
        assert isinstance(key, str)
        assert isinstance(val, str)
        common.b64decode(app_id)
        common.b64decode(app_secret)

        val = ''.join([ENCRYPTION_MAGIC_NUMBER, val])

        hashed_key = blake2.blake2(data=key, hashSize=64, key=app_secret)
        key = None #forbidden
        val_iv, val_ciphertext = encrypt(data=val, key=app_secret)
        val = None #forbidden

        stmt = ('INSERT INTO {0} (app_id, key, value, value_iv) '
                'VALUES (?, ?, ?, ?)').format(TBL_CRYPT_KV_STORE.name)
        arglist = (app_id, hashed_key, val_ciphertext, val_iv)
        try:
            self.sql_execute(stmt, arglist)
        except DatabaseWriteError, err:
            err_msg = "Unable to store key/val pair for app '{0}'".format(app_id)
            extended_msg = err_msg = ": {0}".format(str(err))
            common.log(msg=extended_msg, level=logging.ERROR)
            raise DatabaseWriteError(err_msg)

def msg_queue_row_to_notif(row):
    """Convert a row from the db into a NotificationRequest object"""
    #id, date_added, channel, recipients, sender, subject, message, time_to_send,
    #error_channel, error_recipients
    notif = common.NotificationRequest()
    notif.set_channel(common.SupportedChannels(int(row[2])))
    if row[3] is not None:
        recipients = common.email_str_to_list(row[3])
    for recipient in recipients:
        if recipient != '':
            notif.add_recipient(recipient)
    if row[4] is not None:
        notif.set_sender(row[4])
    if row[5] is not None:
        notif.set_subject(row[5])
    if row[6] is not None:
        notif.set_message(row[6])
    notif.set_when(common.SupportedTimes(int(row[7])))
    notif.set_error_channel(common.SupportedChannels(int(row[8])))
    error_recipients = common.email_str_to_list(row[9])
    for error_recipient in error_recipients:
        if error_recipient != '':
            notif.add_error_recipient(error_recipient)
    if row[10] is not None:
        notif.uuid = str(uuid.UUID(row[10]))

    return notif

def combine_err_msgs(err, err_msg):
    """Take the message from the specified err and concatenate err_msg"""
    assert isinstance(err, Exception)
    msg = str(err)
    if err_msg is not None:
        msg += " ({0})".format(err_msg)
    return msg

def generate_app_id():
    """Generate a new app id using random data, base64-encoded"""
    return common.b64encode(os.urandom(APP_ID_BYTES))

def generate_app_secret():
    """Generate a new app secret using random data, base64-encoded"""
    return common.b64encode(os.urandom(APP_SECRET_BYTES))
