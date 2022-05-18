#!/usr/bin/env python3
#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Pulumi-compatible passphrase encryption/decryption"""

from typing import Optional, cast


import Cryptodome
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Cipher._mode_gcm import GcmMode
from Cryptodome.Random import get_random_bytes
from base64 import b64encode, b64decode
from binascii import hexlify
import sys
import json

from .internal_types import Jsonable
from .exceptions import PulumiCryptoError, PulumiCryptoBadPassphraseError
from .constants import (
    KEY_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    TAG_SIZE_BYTES,
    PBKDF2_COUNT,
    VERIFICATION_PLAINTEXT,
    PASSPHRASE_SALT_SIZE_BYTES,
  )
from .util import (
    generate_key,
    generate_key_from_passphrase,
    generate_nonce,
    encrypt_string,
    decrypt_string,
    PBKDF2_HASH_MODULE,
  )

class PassphraseCipher:
  """A pulumi-compatible encrypter/decrypter derived from a passphrase and a salt

  Class PassphraseCipher performs passphrase-based encryption/decryption of stack Pulumi stack secrets in the same
  way as is done by the Pulumi CLI. It can also be used for general-purpose passphrase-based encryption
  and decryption of secret strings.

  Symmetric 256-bit AES encryption in GCM mode is used, with a 12-byte nonce, resulting in ciphertext
  that has a 16-byte validation digest attached. This ensures integrity of roundtrip encrypt/decrypt
  and hard failure if the wrong key is used to decrypt.

  The 256-bit key is deterministically derived from the passphrase and a random 64-bit salt using PBKDF2,
  with 1,000,000 iterations of SHA-256 HMAC. This takes around a second to compute on average hardware.

  The random salt for stack inputs is persisted in the Pulumi stack config file in property
  "encryptionsalt", and for stack output is persisted in the backend stack deployment object
  under deployment["secrets_providers"]["state"]["salt"].  In both cases, the persisted string is of the
  format:

          "v1:" + b64encode(salt) + ":" + self.encrypt("pulumi")

  The encrypted representation of "pulumi" is included as a waty to verify that a decryption passphrase
  is correct--the passphrase is correct iff it decrypts back to "pulumi".

  As used by Pulumi, the plaintext strings passed to this encrypter are themselves serialized JSON; this
  allows arbitrary Jsonable values to be encrypted. For this reason, the return value from self.decrypt()
  is typically a quoted string with escapes, or other JSON serialization. It should be run through json.loads()
  to get the actual value.

  Within the stack deployment object, retrieved with:

     pulumi stack export

  or:

     pulumi stack export --show-secrets

  Encrypted secret values are represented as dicts:

    {
      "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
      "ciphertext": encrypter.encrypt(json.dumps(unencrypted_secret_jsonable_value))
    }

  where "4dabf18193072939515e22adb298388d" and "1b47061264138c4ac30d75fd1eb44270" are
  hard-coded, unlikely-to-collide values used to identify the dict as containing
  a secret value.

  Similary, decrypted secret values are  represented as:
    {
      "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
      "plaintext": json.dumps(unencrypted_secret_jsonable_value)
    }

  For example:
      $ pulumi stack --stack dev export
      ...
        outputs: {
          exposed_input: "Paul is alive",
          public_ip: "192.168.1.1",
          secret_input: {
            4dabf18193072939515e22adb298388d: "1b47061264138c4ac30d75fd1eb44270",
            ciphertext: "v1:NlYqG/v5PGnurF8e:Ih/CeRbpVH/nqNdAwlU8GphacTkgQTdYay9nRxJqqg=="
          },
          secret_output: {
            4dabf18193072939515e22adb298388d: "1b47061264138c4ac30d75fd1eb44270",
            ciphertext: "v1:C7zJC50FGL7rIvrq:6wLzal+3/7n3kMD5sZfBmUsYJcrN1WlTrc1jid4HnanyJHhZ"
          },
          url: "http://192.168.1.1"
        }
      ...
      $ pulumi stack --stack dev export --show-secrets
      ...
        "outputs": {
          "exposed_input": "Paul is alive",
          "public_ip": "192.168.1.1",
          "secret_input": {
              "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
              "plaintext": "\"Paul is alive\""
          },
          "secret_output": {
              "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
              "plaintext": "\"John is the Walrus\""
          },
          "url": "http://192.168.1.1"
        },
      ...


  In the case of the Pulumi CLI "stack output" command, such wrapping dicts are removed--encrypted
  values are replaced with the string "[secret]", and decryped values are deserialized from their
  JSON representation and inserted into the stack output object; e.g., .

      $ pulumi stack --stack dev output --json --show-secrets
      {
        "exposed_input": "Paul is alive",
        "public_ip": "192.168.1.1",
        "secret_input": "Paul is alive",
        "secret_output": "John is the Walrus",
        "url": "http://192.168.1.1"
      }
      $ pulumi stack --stack dev output --json
      {
        "exposed_input": "Paul is alive",
        "public_ip": "192.168.1.1",
        "secret_input": "[secret]",
        "secret_output": "[secret]",
        "url": "192.168.1.1"
      }
  """

  # ==========
  # The following parameters are set by Pulumi, and cannot be changed without breaking Pulumi compatibility
  KEY_SIZE_BYTES = KEY_SIZE_BYTES
  """Number of bytes in the derived symmetric AES encryption key"""

  PBKDF2_COUNT = PBKDF2_COUNT
  """Number of hash iterations from passphrase to generate key (large value ensures dictionary attack is slow)"""

  PBKDF2_HASH_MODULE = PBKDF2_HASH_MODULE
  """Type of hash used to generate AES 256-bit key from passphrase"""

  VERIFICATION_PLAINTEXT = VERIFICATION_PLAINTEXT
  """Plaintext that is encrypted and saved with salt as a way to verify correctness of a passphrase"""

  PASSPHRASE_SALT_SIZE_BYTES = PASSPHRASE_SALT_SIZE_BYTES
  """Number of bytes of salt added to passphrase to uniqueify key for the deployment"""

  TAG_SIZE_BYTES = TAG_SIZE_BYTES
  """Size of the HMAC verification tag appended to each encrypted ciphertext. Used to validate round-trip encrypt/decrypt"""

  NONCE_SIZE_BYTES = NONCE_SIZE_BYTES
  """Number of random bytes used for the nonce on each encrypted value"""

  # ===========

  _key: bytes
  """AES 256-bit symmetric key deterministically derived from salt and passphrase"""

  _salt: bytes
  """8-byte random salt data associated with an encrypted config file or deployment state; used to salt
     the passphrase, so encryptions across deployments and config files cannot be correlated."""

  _salt_state: str
  """A Pulumi-compatible encryption state string that includes the salt and
     a verifier in the form "v1:" + b64encode(salt) + ":" + self.encrypt("pulumi").
     This is found in the Pulumi stack config file under 'encryptionsalt'."""

  def __init__(
        self,
        passphrase: str,
        salt_state: Optional[str]=None,
        salt: Optional[bytes]=None,
        pbkdf2_count: Optional[int]=None,
        verification_plaintext: Optional[str]=None,
      ):
    """Create a Pulumi-compatible passphrase-based encrypter/decrypter.

    Args:
        passphrase (str):     The passphrase to be used for encryption/decryption.
        salt_state (Optional[str], optional):
                              A Pulumi-compatible encryption state string that includes the salt and a
                              a verifier, in the form "v1:" + b64encode(salt) + ":" + self.encrypt(verification_plaintext).
                              This is found in the Pulumi stack config file under 'encryptionsalt'. If
                              provided, then the embedded salt will be used, and the embedded encrypted
                              verification_plaintext will be verified against the expected verification_plaintext
                              to ensure that the provided passphrase is correct; if not, an Exception will
                              be raised. If None, then a new encryption salt_state string will be generated--
                              in this case it is important that the caller record the generated salt_state
                              string (or at least the generated salt) for future use in decryption, since
                              the salt is required to properly decrypt ciphertext. Defaults to None.
        salt (Optional[bytes], optional):
                              If salt_state is None, this parameter may be provided to force the use of a
                              specific salt when generating salt_state. Must be None if salt_state is not None.
                              If both this and salt_state are None, then a random salt will be generated.
                              Defaults to None.
        pbkdf2_count(Optional[int], optional):
                              Number of iterations of the hash function to apply to the passphrase to generate
                              a symmetric 256-bit AES key. A large number will make initialization of the cipher
                              slow, but will defend against dictionary attack if the passphrase is weak.
                              For compatibility with Pulumi secrets, this must be 1,000,000, which will take
                              up to one second to compute. If None, the Pulumi-compatible value will be used.
                              Defaults to None.
        verification_plaintext(Optional[str], optional):
                              An arbitrary but well-known, public short plaintext string that will be encrypted using
                              the other parameters to produce a "salt_state" that can be used for verification
                              of a passphrase. For compatibility with Pulumi secrets, this must be "pulumi".
                              If None, the Pulumi-compatible value will be used. Defaults to None.

    Raises:
        PulumiCryptoError: Both salt and salt_state were provided
        PulumiCryptoError: Badly formed salt_state
        PulumiCryptoBadPassphraseError: Passphrase does not match the validator in the provided salt_state
    """
    if pbkdf2_count is None:
      pbkdf2_count = self.PBKDF2_COUNT
    if verification_plaintext is None:
      verification_plaintext = self.VERIFICATION_PLAINTEXT
    if salt is None:
      if salt_state is None:
        salt = get_random_bytes(8)
      else:
        parts = salt_state.split(':', 2)
        if len(parts) != 3 or parts[0] != 'v1':
          raise PulumiCryptoError(f"Badly formed salt_state value: {salt_state}")
        salt = b64decode(parts[1])
    elif not salt_state is None:
      raise PulumiCryptoError("Salt and salt_state cannot both be provided to PassphraseCipher")
    self._salt = salt
    key = generate_key_from_passphrase(
        passphrase,
        salt,
        key_size_bytes=self.KEY_SIZE_BYTES,
        pbkdf2_count=pbkdf2_count,
        hmac_hash_module=self.PBKDF2_HASH_MODULE
      )
    self._key = key
    if salt_state is None:
      verification_ciphertext = self.encrypt(verification_plaintext)
      b64_salt = b64encode(self._salt).decode('utf-8')
      salt_state = f"v1:{b64_salt}:{verification_ciphertext}"
    self._salt_state = salt_state
    verification_ciphertext = salt_state.split(':', 2)[2]
    try:
      test_verification_plaintext = self.decrypt(verification_ciphertext)
    except Exception as e:
      raise PulumiCryptoBadPassphraseError(f"Provided passphrase [redacted] does not match salt state validator: {salt_state}") from e
    if test_verification_plaintext != verification_plaintext:
      raise PulumiCryptoBadPassphraseError(f"Provided passphrase [redacted] does not match salt state validator: {salt_state}")

  @property
  def key(self) -> bytes:
    """The 256-bit AES key derived from the passphrase and the salt"""
    return self._key

  @property
  def salt(self) -> bytes:
    """The 64-bit salt, used to uniqueify the key associated with a passphrase across multiple deployments"""
    return self._salt

  @property
  def salt_state(self) -> str:
    """A Pulumi-compatible encryption state string
       that includes the salt and a a verifier, in the form
           "v1:" + b64encode(salt) + ":" + self.encrypt("pulumi").
       This is found in the Pulumi stack config file under 'encryptionsalt',
       and also in the backend stack state object.
       It is important that the caller record this state string
       use in decryption, since the salt is required to properly decrypt ciphertext."""
    return self._salt_state

  def encrypt(self, plaintext: str, nonce: Optional[bytes]=None) -> str:
    """Encrypt a plaintext string into a ciphertext string that is pulumi-compatible.

    Note: As used by Pulumi, plaintext Jsonable values (including strings) are first
          serialized to JSON, and the serialized form is used as plaintext for encryption.
          This means that plaintext strings typically include double quotes and
          standard JSON quoted string escaping.

          After ciphertext is generated, Pulumi represents the secret value as a dict:

          {
            "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
            "ciphertext": "<generated-ciphertext>"
          }

          where "4dabf18193072939515e22adb298388d" and "1b47061264138c4ac30d75fd1eb44270" are
          hard-coded unlikely-to-collide values used to identify the dict as containing
          a secret item.

    Args:
        plaintext (str):   An unencrypted string to be represented as ciphertext.
                           Normally this is serialized JSON including quotes and
                           escaping (see above).
        nonce (Optional[bytes], optional):
                           An optional 12-byte nonce value, to force the use of a specific nonce.
                           If None, a random nonce will be generated. Defaults to None.

    Returns:
        str: The Pulumi-compatible ciphertext string, encrypted with passphrase+salt, which will
             decrypt back to plaintext. The format of this string is:
                   "v1:" + b64encode(nonce) + ":" b64encode(encrypted_data + validation_tag_16_bytes)
    """
    result = encrypt_string(plaintext, self._key, nonce=nonce)
    return result

  def encrypt_jsonable(self, obj: Jsonable, nonce: Optional[bytes]=None) -> str:
    """Encrypt a JSON-able value into a minimally sized ciphertext string that is pulumi-compatible.

    Note: As used by Pulumi, JSON-able values (including strings) are first
          serialized to JSON, and the serialized form is used as plaintext for encryption.
          This means that plaintext strings typically include double quotes and
          standard JSON quoted string escaping.

          After ciphertext is generated, Pulumi represents the secret value as a dict:

          {
            "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
            "ciphertext": "<generated-ciphertext>"
          }

          where "4dabf18193072939515e22adb298388d" and "1b47061264138c4ac30d75fd1eb44270" are
          hard-coded unlikely-to-collide values used to identify the dict as containing
          a secret item.

    Args:
        obj (Jsonable):    A simple JSON-serializable value to be represented as ciphertext.
        nonce (Optional[bytes], optional):
                           An optional 12-byte nonce value, to force the use of a specific nonce.
                           If None, a random nonce will be generated. Defaults to None.

    Returns:
        str: The Pulumi-compatible ciphertext string, encrypted with passphrase+salt, which will
             decrypt back to a plaintext JSON representation of obj. The format of this string is:
                   "v1:" + b64encode(nonce) + ":" b64encode(encrypted_data + validation_tag_16_bytes)
    """
    plaintext = json.dumps(obj, sort_keys=True, separators=(',', ':'))
    result = self.encrypt(plaintext, nonce=nonce)
    return result

  def decrypt(self, ciphertext: str) -> str:
    """Decrypt a pulumi-compatible cyphertext string into a plaintext string.

    Note: As used by Pulumi, cyphertext decrypts to serialized JSON that
          includes double quotes and escape sequences for strings. So normally
          the result of decryption should be run through json.loads()

          Pulumi represents encrypted secret values as a dict:

          {
            "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
            "ciphertext": "<decryptable-ciphertext>"
          }

          where "4dabf18193072939515e22adb298388d" and "1b47061264138c4ac30d75fd1eb44270" are
          hard-coded unlikely-to-collide values used to identify the dict as containing
          a secret item.

    Args:
        ciphertext (str):  A Pulumi-compatible ciphertext string, encrypted with passphrase+salt, which will
                           decrypt back to plaintext. The format of this string is:
                              "v1:" + b64encode(nonce) + ":" b64encode(encrypted_data + validation_tag_16_bytes)

    Returns:
        str: The plaintext corresponding to ciphertext, as it was provided to encrypt(). Note that
             as Pulumi uses it, this is typically serialized JSON that must be run through json.loads() to
             transform it into an actual value.

    Raises:
        PulumiCryptoError: The ciphertext is not properly formed
        PulumiCryptoError: The ciphertext was not the result of encryption with the passphrase and salt provided
                           at construction time
    """
    plaintext = decrypt_string(ciphertext, self._key)
    return plaintext

  def decrypt_jsonable(self, ciphertext: str) -> Jsonable:
    """Decrypt a pulumi-compatible encrypted ciphertext into a JSON-able value.

    Note: As used by Pulumi, cyphertext decrypts to serialized JSON that
          includes double quotes and escape sequences for strings. So normally
          the result of decryption should be run through json.loads(). This
          method does that as a convenience.

          Pulumi represents encrypted secret values as a dict:

          {
            "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
            "ciphertext": "<decryptable-ciphertext>"
          }

          where "4dabf18193072939515e22adb298388d" and "1b47061264138c4ac30d75fd1eb44270" are
          hard-coded unlikely-to-collide values used to identify the dict as containing
          a secret item.

    Args:
        ciphertext (str):  A Pulumi-compatible ciphertext string, encrypted with passphrase+salt, which will
                           decrypt back to serialized JSON text. The format of this string is:
                              "v1:" + b64encode(nonce) + ":" b64encode(encrypted_data + validation_tag_16_bytes)

    Returns:
        Jsonable: The decrypted, deserialized JSON-able value corresponding to ciphertext, as it was provided to
        encrypt_jsonable().

    Raises:
        PulumiCryptoError: The ciphertext is not properly formed
        PulumiCryptoError: The ciphertext was not the result of encryption with the passphrase and salt provided
                           at construction time
        JSONDecodeError:   The decrypted plaintext is no valid JSON
    """
    plaintext = self.decrypt(ciphertext)
    result: Jsonable = json.loads(plaintext)
    return result
