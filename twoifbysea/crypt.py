"""Handles encrpytion and decryption of strings.

https://github.com/kristovatlas/twoifbysea

Usage:
    >>> key = os.urandom(32)
    >>> (iv, ciphertext) = crypt.encrypt(data, key)
    >>> plaintext = crypt.decrypt(ciphertext, key, iv)


Encryption specifications:
    * os.urandom is used for random data. "This function returns random bytes
      from an OS-specific randomness source. The returned data should be
      unpredictable enough for cryptographic applications, though its exact
      quality depends on the OS implementation. On a UNIX-like system this will
      query /dev/urandom, and on Windows it will use CryptGenRandom(). If a
      randomness source is not found, NotImplementedError will be raised."
    * Message is padded with random prefix and suffix to defend known-plaintext
      attacks, probably unnecessarily, given that a random IV is used.
    * A random IV is used for each encryption operation, to be stored along with
      the ciphertext for decryption.
    * AES-256 is used in CBC mode.

"""

#Standard Python Library 2.7
import os

#pip modules
from Crypto.Cipher import AES #pycrypto

#twoifbysea modules
import common #common.py

PREFIX_PAD_LENGTH = 128
SUFFIX_PAD_LENGTH = 128

STANDARD_PAD_LENGTH = 64

def encrypt(data, key, iv=None):
    """Encrypts the data using specified key and IV (specified or random)

    Args:
        data: The data to be encrypted in raw form
        key (str): The base64-encoded key to use for AES-256 encryption
        iv (Optional[str]): If specified, the base64-encoed iv used for AES-256
            encryption. If not specified, a random one is generated.


    Returns: (iv, ciphertext) where both IV and ciphertext are base64-encoded
    strings.
    """
    assert isinstance(key, str)
    assert isinstance(iv, str) or iv is None
    key_raw = common.b64decode(key)
    assert len(key_raw) == 32 #AES-256

    iv_raw = None
    if iv is None:
        #IV : byte string
        #...
        #For all other modes, it must be `block_size` bytes long.
        iv_raw = os.urandom(AES.block_size)
        iv = common.b64encode(iv_raw)
    else:
        assert isinstance(iv, str)
        iv_raw = common.b64decode(iv)
        assert len(iv_raw) == AES.block_size

    padded = pad(str(data)) #defend known-plaintext attacks and length analysis

    cipher = AES.new(key_raw, AES.MODE_CBC, iv_raw)
    ciphertext_raw = cipher.encrypt(padded)
    ciphertext = common.b64encode(ciphertext_raw)
    return (iv, ciphertext)


def decrypt(ciphertext, key, iv):
    """Decrypts the data using specified key and IV

    Args:
        ciphertext (str): The base64-encoded data to be AES-256 decrypted
        key (str): The base64-encoded AES-256 key to decrypt with
        iv (str): The base64-encoded IV to decrypt with

    Returns: msg in raw form
    """
    assert isinstance(ciphertext, str)
    assert isinstance(key, str)
    assert isinstance(iv, str)
    ciphertext_raw = common.b64decode(ciphertext)
    key_raw = common.b64decode(key)
    iv_raw = common.b64decode(iv)

    assert len(key_raw) == 32 #AES-256

    #IV : byte string
    #...
    #For all other modes, it must be `block_size` bytes longs.
    assert len(iv_raw) == AES.block_size

    cipher = AES.new(key_raw, AES.MODE_CBC, iv_raw)
    padded_msg = cipher.decrypt(ciphertext_raw)
    msg = unpad(padded_msg)
    return msg

def pad(data):
    """Protect plaintext with padding"""
    mod_padded = standard_pad(data)
    fix_padded = random_pad(mod_padded)
    return fix_padded

def unpad(data):
    """Reverse process applied by pad()"""
    fix_removed = random_unpad(data)
    original = standard_unpad(fix_removed)
    return original

def standard_pad(raw_str):
    """Add standard padding to prepare for encryption and protect length

    Perl CBC padds to nearest 16 bytes; this is required by AES.encrpyt().
    To further protect the plaintext, we will pad to a higher value, and
    also round up for empty messages; this makes it more difficult for an
    attacker to examine the ciphertext and determine the length of the
    original string with any decent accuracy.

    This must be done BEFORE adding prefix/suffix random pads in order to
    protect blank messages; otherwise the length isn't zero.

    Reference:
    http://search.cpan.org/~lds/Crypt-CBC-2.24/CBC.pm#Padding_methods

    Returns: str: padded raw_str
    """
    assert isinstance(raw_str, str)

    padding_to_add = STANDARD_PAD_LENGTH
    if len(raw_str) > 0:
        padding_to_add = STANDARD_PAD_LENGTH - (len(raw_str) % STANDARD_PAD_LENGTH)

    padding = chr(padding_to_add) * padding_to_add
    return ''.join([raw_str, padding])

def standard_unpad(padded_str):
    """Remove standard padding added by stanard_pad"""
    assert isinstance(padded_str, str)

    last_chr = ord(padded_str[-1])
    if list(i == last_chr for i in padded_str[-last_chr]):
        return padded_str[:-last_chr]
    return padded_str

def random_pad(data):
    """Add prefix/suffix random data to protect against known plaintext attack"""
    prefix_pad = os.urandom(PREFIX_PAD_LENGTH)
    suffix_pad = os.urandom(SUFFIX_PAD_LENGTH)
    padded = ''.join([str(prefix_pad), str(data), str(suffix_pad)])
    return padded

def random_unpad(data):
    """Remove prefix and suffix pads assigned by random_pad()"""
    return data[PREFIX_PAD_LENGTH:-SUFFIX_PAD_LENGTH]
