#!/usr/bin/env python3
#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Constants defined by this package"""

KEY_SIZE_BITS = 256
"""Size of symmetric AES encryption key in bits"""

KEY_SIZE_BYTES = KEY_SIZE_BITS // 8
"""Size of symmetric AES encryption key in bytes"""

TAG_SIZE_BYTES = 16
"""Size of the HMAC verification tag appended to each encrypted ciphertext. Used to validate round-trip encrypt/decrypt"""

NONCE_SIZE_BYTES = 12
"""Number of random bytes used for the nonce on each encrypted value"""

PBKDF2_COUNT = 1000000
"""Number of hash iterations from passphrase to generate key (large value ensures dictionary attack is slow)"""

VERIFICATION_PLAINTEXT = "pulumi"
"""Plaintext that is encrypted and saved with salt as a way to verify correctness of a passphrase"""

PASSPHRASE_SALT_SIZE_BYTES = 8
"""Number of bytes of salt added to passphrase to uniqueify key for the deployment"""
