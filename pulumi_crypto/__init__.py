# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""
Package pulumi_crypto provides a command-line tool as well as a runtime API for Pulumi-compatible encryption and decryption
of secret strings using a passphrase. It can also be used for general passphrase-based encryption/decryption of secret strings.
"""

from .version import __version__

from .constants import (
    KEY_SIZE_BITS,
    KEY_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    TAG_SIZE_BYTES,
    PBKDF2_COUNT,
    VERIFICATION_PLAINTEXT,
    PASSPHRASE_SALT_SIZE_BYTES,
  )

from .util import (
    generate_key,
    generate_nonce,
    encrypt_string,
    decrypt_string,
    generate_key_from_passphrase,
  )

from .passphrase_cipher import PassphraseCipher
from .internal_types import Jsonable
from .exceptions import (
    PulumiCryptoError,
    PulumiCryptoBadPassphraseError,
    PulumiCryptoNoPassphraseError
  )
