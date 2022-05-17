#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Exceptions defined by this package"""

from typing import Optional

class PulumiCryptoError(Exception):
  """Base class for all error exceptions defined by this package."""
  #pass

class PulumiCryptoNoPassphraseError(PulumiCryptoError):
  """Exception indicating failure because a passphrase was not provided."""
  #pass

class PulumiCryptoBadPassphraseError(PulumiCryptoError):
  """Exception indicating failure because an incorrect passphrase was provided."""
  #pass
