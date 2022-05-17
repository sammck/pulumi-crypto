pulumi-crypto: Python implementation of Pulumi passphrase encryption and decryption
=================================================

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Latest release](https://img.shields.io/github/v/release/sammck/pulumi-crypto.svg?style=flat-square&color=b44e88)](https://github.com/sammck/pulumi-crypto/releases)

A Python commandline tool and cipher library that can verify Pulumi passphrases and encrypt/decrypt Pulumi passphrase-protected secrets as found in stack config files and exported stack state files. Can also be used for general passphrase-based encryption/decryption of string values.

Table of contents
-----------------

* [Introduction](#introduction)
* [Details](#pulumi-passphrase-encryption-details)
* [Installation](#installation)
* [Usage](#usage)
  * [Command line](#command-line)
  * [API](api)
* [Known issues and limitations](#known-issues-and-limitations)
* [Getting help](#getting-help)
* [Contributing](#contributing)
* [License](#license)
* [Authors and history](#authors-and-history)


Introduction
------------

Python package `pulumi-crypto` provides a command-line tool as well as a runtime API for Pulumi-compatible encryption and decryption of secret strings using a passphrase. It can also be used for general passphrase-based encryption/decryption of secret strings.

Some key features of pulumi-crypto:

* 100% compatible with current Pulumi passphrase secret provider.
* Does not depend on any installed pulumi tools or libraries.
* Can operate on secrets in pulumi stack config files and backend state files without having a complete or consistent stack.
* Can be used to automate construction of stack config files before a stack exists.
* Allows separation of reading/writing Pulumi config files and deployment export data (which does not
  require knowledge of the correct passphrase) from encryption/decryption of secrets (which requires knowledge of the passphrase).

This package was originally developed as part of a solution to work around a limitation of the current pulumi release--there is currently no easy way to get/set nonsecret config properties or stack deployment outputs without knowing the correct passphrase, even if the passphrase is irrelevant for that task. By directly implementing a private version of `pulumi config` and `pulumi stack output` it is possible to defer use of the passphrase until it is needed, and allow working with encrypted inputs/outputs as well as nonsecret inputs and outputs, without knowledge of the passphrase.

Pulumi passphrase encryption details
------------------------------------
Symmetric 256-bit AES encryption in GCM mode is used, with a 12-byte nonce, resulting in ciphertext
for each secret that has a 16-byte validation digest attached. This prevents correlation of repeated encryption of identical plaintext, and ensures integrity of roundtrip encrypt/decrypt and a hard
failure if the wrong key is used to decrypt.

The 256-bit AES key is deterministically derived from the passphrase and a random 64-bit salt using PBKDF2,
with 1,000,000 iterations of SHA-256 HMAC. This takes around a second to compute on average hardware, making it resistant to dictionary attacks if a weak passphrase is used. A single salt, and hence a single 256-bit AES key, is used for encryption of all secrets in a given stack config file, or in a given stack's backend deployment state, so this expensive hashing is only done once each time a config file or deployment state needs to be encrypted/decrypted.

### Salt state string
To recover the 256-bit symmetric AES key, and hence to decrypt secrets, the decrypter must know the passphrase as well as the passphrase salt that was used to generate the key. For this reason, the passphrase salt must be stored alongside encrypted data. Since the same passphrase salt and AES key are used to encrypt all secrets in a single document (e.g., a Pulumi stack config file or exported stack deployment document), the passphrase salt only needs to be recorded once per document. To serve that purpose, and also to provide a way to verify correctness of a passphrase without decrypting secrets, Pulumi defines a "salt state" string as:
```python
"v1:" + b64encode(passphrase_salt) + ":" + encrypt("pulumi")
```
where `encrypt("pulumi")` is the result of encrypting the literal string "pulumi" with the AES key derived from the passphrase and attached
passphrase_salt. This provides a way to verify the correctness of a passphrase with only the passphrase and the "salt state" string.

For Pulumi stack config files (e.g., "Pulumi._stack-name_.yaml"), the salt state string is persisted in top-level property "encryptionsalt". 

For Pulumi stack deployment export JSON documents, the salt state string is persisted in `deployment["secrets_providers"]["state"]["salt"]`

Note that either the passphrase or the passphrase salt salt may be changed at any time if the salt state string is updated in the relevant document and all secrets are reencrypted using the new passphrase and salt.

It is not necessary for the passphrase salt or the salt state string to be the same for the Pulumi stack config file and the backend deployment state. While not technically required, as a practical matter, the passphrase must be the same for both, since the Pulumi CLI and SDK provide no means to differentiate between the two.

### Pulumi stack config files
Pulumi stack config files are YAML documents (e.g., "Pulumi._stack-name_.yaml") that represent a dict. They maintain the salt state string in top-level property "encryptionsalt".

Configuration properties are presented in a child dict named "config". Each property of this dict represents a single stack configuration
property. All configuration properties are simple strings; however _secret_ configuration properties are represented in the config file
as dicts with a single property, "secure", which holds a string that is the ciphertext that when decrypted will produce the configuration property's plaintext value.

### Pulumi stack deployment export document
A Pulumi stack deployment export document including encrypted secrets can be produced with:

```bash
pulumi stack export
```

The result is is a JSON document that represent a dict. It maintains the salt state string in `deployment["secrets_providers"]["state"]["salt"]`.

Encrypted secret values may appear anywhere within the deployment export document. Secrets may be any JSON value type.
Prior to encryption, each secret value is serialized to JSON. Each encrypted secret value is represented as a dict:

```json
{
  "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
  "ciphertext": encrypter.encrypt(json.dumps(unencrypted_secret_jsonable_value))
}
```

where "4dabf18193072939515e22adb298388d" and "1b47061264138c4ac30d75fd1eb44270" are
hard-coded, unlikely-to-collide values used to identify the dict as containing
a secret value.

Similary, decrypted secret values seen by `pulumi stack export --show-secrets` are represented as:
```json
{
  "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
  "plaintext": json.dumps(unencrypted_secret_jsonable_value)
}
```

For example:
```bash
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
```

Note that even the plaintext values in this case contain JSON text that must be run through `json.loads()`
to get the actual secret value.

In the case of the convenient Pulumi CLI `stack output --json` command (which is really just a filter
on `pulumi stack export`), such wrapping dicts are removed--encrypted
values are replaced with the string "[secret]", and decrypted values are deserialized from their
JSON representation and inserted into the stack output object; e.g., .
```bash
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
```
For this reason, if you wish to work with encrypted Pulumi secret outputs without relying on the Pulumi command line or runtime to perform decryption, you can get the encrypted outputs directly from the exported deployment state.

Installation
------------

### Prerequisites

**Python**: Python 3.7+ is required. See your OS documentation for instructions.

### From PyPi

The current released version of `pulumi-crypto` can be installed with 

```bash
pip3 install pulumi-crypto
```

### From GitHub

[Poetry](https://python-poetry.org/docs/master/#installing-with-the-official-installer) is required; it can be installed with:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Clone the repository and install pulumi-crypto into a private virtualenv with:

```bash
cd <parent-folder>
git clone https://github.com/sammck/pulumi-crypto.git
cd pulumi-crypto
poetry install
```

You can then launch a bash shell with the virtualenv activated using:

```bash
poetry shell
```

Usage
=====

Command Line
------------

Example usage:

```bash
$ export PULUMI_PASSPHRASE='very-hard-to-guess'
$ export PULUMI_SALT_STATE="$(pulumi-crypto get-salt-state --new)"
$ PLAINTEXT="My Secret"
$ CIPHERTEXT="$(pulumi-crypto encrypt "$PLAINTEXT")"
$ echo "CIPHERTEXT=$CIPHERTEXT"
$ DECRYPTED="$(pulumi-crypto -r decrypt "$CIPHERTEXT")"
$ echo "DECRYPTED=$DECRYPTED"
```

API
---

```python
#!/usr/bin/env python3

import os
from pulumi_crypto import PassphraseCipher

passphrase = 'very-hard-to-guess'

# if salt_state is set to None here, then a new salt and a new salt_state will be generated
salt_state = 'v1:yBsIOwOeOOU=:v1:jIw90Zn+5pikf6dI:SM6iyYeEiHNoQ3i55lR9T4EtfpyUZw=='

cipher = PassphraseCipher(
    passphrase,
    salt_state=salt_state
  )

print(f"salt state={cipher.salt_state}")

plaintext = 'My Secret'
print(f"plaintext={plaintext}")

ciphertext = cipher.encrypt(plaintext)
print(f"ciphertext={ciphertext}")

decrypted = cipher.decrypt(ciphertext)
print(f"decrypted={decrypted}")
```

Known issues and limitations
----------------------------

* TBD.

Getting help
------------

Please report any problems/issues [here](https://github.com/sammck/pulumi-crypto/issues).

Contributing
------------

Pull requests welcome.

License
-------

pulumi-crypto is distributed under the terms of the [MIT License](https://opensource.org/licenses/MIT).  The license applies to this file and other files in the [GitHub repository](http://github.com/sammck/pulumi-crypto) hosting this file.

Authors and history
---------------------------

The author of pulumi-crypto is [Sam McKelvie](https://github.com/sammck).
