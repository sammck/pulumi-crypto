#!/usr/bin/env python3
#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""AES-256 encryption/decryption of strings"""

from typing import Optional, cast
from types import ModuleType

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

from .exceptions import PulumiCryptoError, PulumiCryptoBadPassphraseError

from .constants import (
    KEY_SIZE_BYTES,
    TAG_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    PBKDF2_COUNT
  )

PBKDF2_HASH_MODULE: ModuleType = SHA256
"""Type of hash used to generate AES key from passphrase"""

def generate_nonce(n_bytes: int=12) -> bytes:
  """Generate a cryptographically random nonce.

  Args:
      n_bytes (int, optional): The number of bytes to generate. Default is 12.

  Returns:
      bytes: a cryptographically random 256-bit (32-byte) key
  """
  return get_random_bytes(n_bytes)

def generate_key() -> bytes:
  """Generate a cryptographically random 256-bit AES key.

  Returns:
      bytes: a cryptographically random 256-bit (32-byte) key
  """
  return get_random_bytes(KEY_SIZE_BYTES)

def generate_key_from_passphrase(
      passphrase: str,
      passphrase_salt: bytes,
      pbkdf2_count: Optional[int]=None,
      key_size_bytes: int=KEY_SIZE_BYTES,
      hmac_hash_module: ModuleType=PBKDF2_HASH_MODULE
    ) -> bytes:
  """Generate a deterministic AES-256 key from a passphrase and a passphrase salt.

  Args:
      passphrase (str):     The passphrase to be used for encryption/decryption.
      passphrase_salt (bytes):
                            An arbitrary salt used to uniqueify the key. Should be at least 8 bytes
                            long. The value is not secret but must be preserved to reliably regenerate the
                            same key during decryption.
      pbkdf2_count(Optional[int], optional):
                            Number of iterations of the hash function to apply to the passphrase to generate
                            a symmetric 256-bit AES key. A large number will make initialization of the cipher
                            slow, but will defend against dictionary attack if the passphrase is weak.
                            For compatibility with Pulumi secrets, this must be 1,000,000, which will take
                            up to one second to compute. If None, the Pulumi-compatible value will be used.
                            Defaults to None.
      key_size_bytes(int, optional):
                            Size of the generated key in bytes.  Default is 32 (256-bits).
      hmac_hash_module(ModuleType, optional):
                            The crytographic hashing module to use.  Default is SHA256.

  Returns:
      An AES symmetric key of length key_size_bytes that is deterministically derived
      from the passphrase and passphrase salt.
  """
  assert isinstance(passphrase, str)
  assert isinstance(passphrase_salt, bytes)
  assert isinstance(key_size_bytes, int)
  assert isinstance(hmac_hash_module, ModuleType)
  if pbkdf2_count is None:
    pbkdf2_count = PBKDF2_COUNT
  else:
    assert isinstance(pbkdf2_count, int)
  if len(passphrase_salt) < 8:
    raise PulumiCryptoError("Passphrase salt must be at least 8 bytes in length")
  key = PBKDF2(passphrase, passphrase_salt, dkLen=key_size_bytes, count=pbkdf2_count, hmac_hash_module=hmac_hash_module)
  return key

def encrypt_string(plaintext: str, key: bytes, nonce: Optional[bytes]=None) -> str:
  """Encrypt a string using AES-256 GCM mode

  Encrypts the plaintext string, returning a ciphertext string of the form:

    "v1:" + b64encode(nonce) + ":" + b64encode(aes_encrypt(plaintext.encode('utf-8')))

  Args:
      plaintext (str): A plaintext string to be encrypted
      key (bytes): A 256-bit (32-byte) symmetric AES key
      nonce (Optional[bytes], optional): An optional random nonce sequence. If None, a random 12-byte
                                         nonce will be generated. Defaults to None.

  Raises:
      PulumiCryptoError: Wrong size key
      PulumiCryptoError: Wrong size nonce

  Returns:
      str: An encrypted representation of plaintext, which may be decrypted with decrypt_string().
  """
  assert isinstance(plaintext, str)
  assert isinstance(key, bytes)
  if len(key) != KEY_SIZE_BYTES:
    raise PulumiCryptoError(f"Wrong key size for AES-256, expected {KEY_SIZE_BYTES} bytes, got {len(key)}")
  if nonce is None:
    nonce = get_random_bytes(NONCE_SIZE_BYTES)
  else:
    assert isinstance(nonce, bytes)
    if len(nonce) < 8:
      raise PulumiCryptoError("Nonce must be at least 8 bytes in length")
  cipher = cast(GcmMode, AES.new(key, AES.MODE_GCM, nonce=nonce))
  bin_plaintext = plaintext.encode('utf-8')
  ciphertext_data, tag = cipher.encrypt_and_digest(bin_plaintext)
  assert len(tag) == TAG_SIZE_BYTES
  ciphertext_data_and_tag = ciphertext_data + tag
  b64_nonce = b64encode(nonce).decode('utf-8')
  b64_ciphertext = b64encode(ciphertext_data_and_tag).decode('utf-8')
  ciphertext = f"v1:{b64_nonce}:{b64_ciphertext}"
  return ciphertext

def decrypt_string(ciphertext: str, key: bytes) -> str:
  """Decrypt a string previously encrypted with encrypt_string()

  Args:
      ciphertext (str): An encrypted string in the form:
                          "v1:" + b64encode(nonce) + ":" +
                             b64encode(aes_encrypt(plaintext.encode('utf-8')))
      key (bytes): A 256-bit (32-byte) symmetric AES key

  Raises:
      PulumiCryptoError: Wrong size key
      PulumiCryptoError: Badly formed ciphertext
      PulumiCryptoError: Key is incorrect

  Returns:
      str: The original plaintext, as passed to encrypt_string
  """
  assert isinstance(ciphertext, str)
  assert isinstance(key, bytes)
  if len(key) != KEY_SIZE_BYTES:
    raise PulumiCryptoError(f"Wrong key size for AES-256, expected {KEY_SIZE_BYTES} bytes, got {len(key)}")
  parts = ciphertext.split(':')
  if len(parts) != 3 or parts[0] != 'v1':
    raise PulumiCryptoError(f"Badly formed ciphertext value: {ciphertext}")
  try:
    nonce = b64decode(parts[1])
    if len(nonce) < 8:
      raise PulumiCryptoError("Nonce must be at least 8 bytes in length")
    ciphertext_data_and_tag = b64decode(parts[2])
    if len(ciphertext_data_and_tag) < TAG_SIZE_BYTES:
      raise PulumiCryptoError(f"Ciphertext not long enough to include {TAG_SIZE_BYTES}-byte HMAC tag")
    ciphertext_data = ciphertext_data_and_tag[:-TAG_SIZE_BYTES]
    ciphertext_tag = ciphertext_data_and_tag[-TAG_SIZE_BYTES:]
  except Exception as e:
    raise PulumiCryptoError(f"Badly formed ciphertext value: {ciphertext}") from e
  try:
    cipher = cast(GcmMode, AES.new(key, AES.MODE_GCM, nonce=nonce))
    bin_plaintext = cipher.decrypt_and_verify(ciphertext_data, ciphertext_tag)
    plaintext = bin_plaintext.decode('utf-8')
  except Exception as e:
    raise PulumiCryptoError("Ciphertext cannot be decrypted with the given key") from e
  return plaintext
