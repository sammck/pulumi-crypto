# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""
Package pulumi_crypto provides a command-line tool as well as a runtime API for Pulumi-compatible encryption and decryption
of secret strings using a passphrase. It can also be used for general passphrase-based encryption/decryption of secret strings.
"""

from .version import __version__

from .passphrase_cipher import PassphraseCipher
from .internal_types import Jsonable
from .exceptions import (
    PulumiCryptoError,
    PulumiCryptoBadPassphraseError,
    PulumiCryptoNoPassphraseError
  )
