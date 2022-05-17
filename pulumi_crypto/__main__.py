#!/usr/bin/env python3
#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Command-line interface for secret_kv package"""


from typing import Optional, Sequence, List, Union, Dict, TextIO, cast, Tuple

import base64
import os
import sys
import argparse
#import argcomplete # type: ignore[import]
import json
import yaml
from base64 import b64encode, b64decode
import colorama # type: ignore[import]
from colorama import Fore, Back, Style
import subprocess
from io import TextIOWrapper
from pygments import highlight, lexers, formatters

# NOTE: this module runs with -m; do not use relative imports
from pulumi_crypto import (
    PassphraseCipher,
    Jsonable,
    PulumiCryptoError,
    PulumiCryptoBadPassphraseError,
    PulumiCryptoNoPassphraseError,
    __version__ as pkg_version,
  )

def is_colorizable(stream: TextIO) -> bool:
  is_a_tty = hasattr(stream, 'isatty') and stream.isatty()
  return is_a_tty

class CmdExitError(RuntimeError):
  exit_code: int

  def __init__(self, exit_code: int, msg: Optional[str]=None):
    if msg is None:
      msg = f"Command exited with return code {exit_code}"
    super().__init__(msg)
    self.exit_code = exit_code

class ArgparseExitError(CmdExitError):
  pass

class NoExitArgumentParser(argparse.ArgumentParser):
  def exit(self, status=0, message=None):
    if message:
      self._print_message(message, sys.stderr)
    raise ArgparseExitError(status, message)

class CommandHandler:
  _argv: Optional[Sequence[str]]
  _parser: argparse.ArgumentParser
  _args: argparse.Namespace
  _passphrase: Optional[str] = None
  _raw_stdout: TextIO = sys.stdout
  _raw_stderr: TextIO = sys.stderr
  _colorize_stdout: bool = False
  _colorize_stderr: bool = False
  _compact: bool = False
  _raw: bool = False
  _encoding: str
  _output_file: Optional[str] = None
  _cipher: Optional[PassphraseCipher] = None
  _salt: Optional[bytes] = None
  _salt_state: Optional[str] = None
  _have_salt: bool = False

  def __init__(self, argv: Optional[Sequence[str]]=None):
    self._argv = argv

  def ocolor(self, codes: str) -> str:
    return codes if self._colorize_stdout else ""

  def ecolor(self, codes: str) -> str:
    return codes if self._colorize_stderr else ""

  def pretty_print(
        self,
        any_value: Union[Jsonable, bytes],
        compact: Optional[bool]=None,
        colorize: Optional[bool]=None,
        raw: Optional[bool]=None,
      ):
    if raw is None:
      raw = self._raw
    raw = raw or isinstance(any_value, (bytes, bytearray))
    if raw:
      if isinstance(any_value, str):
        self._raw_stdout.write(any_value)
        return
      if isinstance(any_value, (bytes, bytearray)):
        self._raw_stdout.flush()
        with os.fdopen(self._raw_stdout.fileno(), "wb", closefd=False) as bin_stdout:
          bin_stdout.write(any_value)
          bin_stdout.flush()
        return
    value = cast(Jsonable, any_value)

    if compact is None:
      compact = self._compact
    if colorize is None:
      colorize = True

    def emit_to(f: TextIO):
      final_colorize = colorize and ((f is sys.stdout and self._colorize_stdout) or (f is sys.stderr and self._colorize_stderr))

      if compact:
        json_text = json.dumps(value, separators=(',', ':'), sort_keys=True)
      else:
        json_text = json.dumps(value, indent=2, sort_keys=True)
      if final_colorize:
        json_text = highlight(json_text, lexers.JsonLexer(), formatters.TerminalFormatter())  # pylint: disable=no-member
      else:
        json_text += '\n'
      f.write(json_text)

    output_file = self._output_file
    if output_file is None:
      emit_to(sys.stdout)
    else:
      with open(output_file, "w", encoding=self._encoding) as f:
        emit_to(f)

  def get_passphrase(self) -> str:
    if self._passphrase is None:
      passphrase: str = self._args.passphrase or ''
      if passphrase == '':
        passphrase = os.environ.get('PULUMI_PASSPHRASE', '')
        if passphrase == '':
          raise PulumiCryptoNoPassphraseError('A passphrase must be provided with --passphrase or in environment variable PULUMI_PASSPHRASE')
      self._passphrase = passphrase

    return self._passphrase

  def get_salt_and_salt_state(self) -> Tuple[Optional[bytes], Optional[str]]:
    if not self._have_salt:
      salt_state: Optional[str] = self._args.salt_state
      b64_salt: Optional[str] = self._args.salt
      config_file: Optional[str] = self._args.config_file
      if salt_state is None:
        if not config_file is None:
          with open(config_file, encoding='utf-8') as f:
            config_obj = yaml.safe_load(f)
          if not isinstance(config_obj, dict) or not isinstance(config_obj.get('encryptionsalt', None), str):
            raise PulumiCryptoError(f"No 'encryptionsalt' string property in config file {config_file}")
          salt_state = cast(str, config_obj['encryptionsalt'])
      else:
        if not config_file is None:
          raise PulumiCryptoError("--config-file and --salt-state cannot both be provided")
      if salt_state is None and b64_salt is None:
        salt_state = os.environ.get('PULUMI_SALT_STATE', '')
        if salt_state == '':
          salt_state = None
      if salt_state is None:
        if b64_salt is None:
          b64_salt = os.environ.get('PULUMI_SALT', '')
          if b64_salt == '':
            b64_salt = None
      else:
        parts = salt_state.split(':', 2)
        if len(parts) != 3 or parts[0] != 'v1':
          raise PulumiCryptoError(f"Badly formed salt_state value: {salt_state}")
        embedded_b64_salt = parts[1]
        if b64_salt is None:
          b64_salt = embedded_b64_salt
        elif b64_salt != embedded_b64_salt:
          raise PulumiCryptoError("--salt-state and --salt do not agree on salt value")
      salt: Optional[bytes] = None if b64_salt is None else b64decode(b64_salt)
      self._salt = salt
      self._salt_state = salt_state
      self._have_salt = True
    return self._salt, self._salt_state

  def get_cipher(self, force_new_salt_state: bool=False) -> PassphraseCipher:
    if self._cipher is None or force_new_salt_state:
      salt: Optional[bytes] = None
      salt_state: Optional[str] = None
      if not force_new_salt_state:
        salt, salt_state = self.get_salt_and_salt_state()
      if not salt_state is None:
        salt = None
      hash_iterations: Optional[int] = self._args.hash_iterations
      verification_string: Optional[str] = self._args.verification_string
      passphrase = self.get_passphrase()
      self._cipher = PassphraseCipher(
          passphrase,
          salt_state=salt_state,
          salt=salt,
          pbkdf2_count=hash_iterations,
          verification_plaintext=verification_string,
        )

    return self._cipher

  def get_vtype(self, default: str='raw-str') -> str:
    args = self._args
    cmd_name = 'pulumi-crypto'
    value_type_s: Optional[str] = args.value_type
    if args.vtype_json:
      if value_type_s is None:
        value_type_s = 'json'
      elif value_type_s != 'json':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and json")
    if args.vtype_str:
      if value_type_s is None:
        value_type_s = 'str'
      elif value_type_s != 'str':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and str")
    if args.vtype_int:
      if value_type_s is None:
        value_type_s = 'int'
      elif value_type_s != 'int':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and int")
    if args.vtype_float:
      if value_type_s is None:
        value_type_s = 'float'
      elif value_type_s != 'float':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and float")
    if args.vtype_bool:
      if value_type_s is None:
        value_type_s = 'bool'
      elif value_type_s != 'bool':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and bool")
    if args.vtype_base64:
      if value_type_s is None:
        value_type_s = 'base64'
      elif value_type_s != 'base64':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and base64")
    if args.vtype_raw_str:
      if value_type_s is None:
        value_type_s = 'raw-str'
      elif value_type_s != 'raw-str':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and raw-str")
    if args.vtype_raw_base64:
      if value_type_s is None:
        value_type_s = 'raw-base64'
      elif value_type_s != 'raw-base64':
        raise ValueError(f"{cmd_name}: Conflicting value types {value_type_s} and raw-base64")
    if value_type_s is None:
      value_type_s = default
    return value_type_s

  def cmd_bare(self) -> int:
    print("A command is required", file=sys.stderr)
    return 1

  def get_nonce(self) -> Optional[bytes]:
    tnonce: Optional[str] = self._args.nonce
    result: Optional[bytes] = None if tnonce is None else b64decode(tnonce)
    return result

  def cmd_get_salt_state(self) -> int:
    args = self._args
    force_new_salt_state: bool = args.new_salt_state
    cipher = self.get_cipher(force_new_salt_state=force_new_salt_state)
    salt_state = cipher.salt_state
    output_file: Optional[str] = args.output_file
    if output_file is None:
      sys.stdout.write(salt_state)
    else:
      with open(output_file, 'w', encoding='utf-8') as f2:
        f2.write(salt_state)
    return 0

  def cmd_encrypt(self) -> int:
    args = self._args
    value: Optional[Union[str, bytes]] = args.value
    use_stdin: bool = args.use_stdin
    input_file: Optional[str] = args.input_file
    if use_stdin:
      if input_file is None:
        input_file = '/dev/stdin'
      else:
        raise PulumiCryptoError("Only one of --use-stdin and --input can be provided")
    if value is None:
      if input_file is None:
        raise PulumiCryptoError("One of value parameter, --use-stdin, or --input must be provided")
      with open(input_file, 'rb') as f:
        value = f.read()
    else:
      if not input_file is None:
        raise PulumiCryptoError("Only one of value parameter, --use-stdin, and --input can be provided")
    vtype = self.get_vtype('raw-str')
    tvalue: str
    if vtype in ('base64', 'raw-base64'):
      if isinstance(value, str):
        value = value.encode('utf-8')
      tvalue = b64encode(value).decode('utf-8')
    else:
      if isinstance(value, str):
        tvalue = value
      else:
        tvalue = value.decode('utf-8')
    plaintext: str
    if vtype in ('raw-str', 'raw-base64'):
      plaintext = tvalue
    else:
      pobj: Jsonable
      if vtype in ('str', 'base64'):
        pobj = tvalue
      elif vtype == 'int':
        pobj = int(tvalue.strip())
      elif vtype == 'json':
        pobj = json.loads(tvalue)
      elif vtype == 'float':
        pobj = float(tvalue.strip())
      elif vtype == 'bool':
        lvalue = tvalue.strip().lower()
        if lvalue in [ 'true', 't', 'yes', 'y', '1' ]:
          pobj = True
        elif lvalue in [ 'false', 'f', 'no', 'n', '0' ]:
          pobj = False
        else:
          raise ValueError(f"pulumi-crypto: Invalid boolean literal: '{tvalue}'")
      plaintext = json.dumps(pobj, sort_keys=True, separators=(',', ':'))
    cipher = self.get_cipher()
    nonce = self.get_nonce()
    ciphertext = cipher.encrypt(plaintext, nonce=nonce)
    write_salt_state_file: Optional[str] = args.write_salt_state
    if not write_salt_state_file is None:
      with open(write_salt_state_file, 'w', encoding='utf-8') as f3:
        yaml.safe_dump(dict(encryptionsalt=cipher.salt_state), f3)
    output_file: Optional[str] = args.output_file
    if output_file is None:
      sys.stdout.write(ciphertext)
    else:
      with open(output_file, 'w', encoding='utf-8') as f2:
        f2.write(ciphertext)
    return 0

  def cmd_decrypt(self) -> int:
    args = self._args
    ciphertext: Optional[str] = args.ciphertext
    use_stdin: bool = args.use_stdin
    input_file: Optional[str] = args.input_file
    if use_stdin:
      if input_file is None:
        input_file = '/dev/stdin'
      else:
        raise PulumiCryptoError("Only one of --use-stdin and --input can be provided")
    if ciphertext is None:
      if input_file is None:
        raise PulumiCryptoError("One of ciphertext parameter, --use-stdin, or --input must be provided")
      with open(input_file, encoding='utf-8') as f:
        ciphertext = f.read()
    else:
      if not input_file is None:
        raise PulumiCryptoError("Only one of ciphertext parameter, --use-stdin, and --input can be provided")
    cipher = self.get_cipher()
    plaintext = cipher.decrypt(ciphertext)
    value: Union[bytes, Jsonable]

    vtype = self.get_vtype('raw-str')
    if vtype == 'raw-str':
      value = plaintext
    elif vtype == 'raw-base64':
      value = b64decode(plaintext)
    else:
      print(f"plaintext=[{plaintext}]", file=sys.stderr)
      pobj: Jsonable = json.loads(plaintext)
      if vtype == 'base64':
        assert isinstance(pobj, str)
        value = b64decode(pobj)
      elif vtype == 'str':
        value = str(pobj)
      else:
        value = pobj
    write_salt_state_file: Optional[str] = args.write_salt_state
    if not write_salt_state_file is None:
      with open(write_salt_state_file, 'w', encoding='utf-8') as f3:
        yaml.safe_dump(dict(encryptionsalt=cipher.salt_state), f3)
    self.pretty_print(value)
    return 0

  def cmd_version(self) -> int:
    self.pretty_print(pkg_version)
    return 0

  def run(self) -> int:
    """Run the pulumi-crypto command-line tool with provided arguments

    Args:
        argv (Optional[Sequence[str]], optional):
            A list of commandline arguments (NOT including the program as argv[0]!),
            or None to use sys.argv[1:]. Defaults to None.

    Returns:
        int: The exit code that would be returned if this were run as a standalone command.
    """
    parser = argparse.ArgumentParser(description="Encrypt and decrypt secrets in a Pulumi-compatible way.")


    # ======================= Main command

    self._parser = parser
    parser.add_argument('--traceback', "--tb", action='store_true', default=False,
                        help='Display detailed exception information')
    parser.add_argument('-M', '--monochrome', action='store_true', default=False,
                        help='Output to stdout/stderr in monochrome. Default is to colorize if stream is a compatible terminal')
    parser.add_argument('-c', '--compact', action='store_true', default=False,
                        help='Compact instead of pretty-printed output')
    parser.add_argument('-r', '--raw', action='store_true', default=False,
                        help='''Output raw strings and binary content directly, not json-encoded.
                                Values embedded in structured results are not affected.''')
    parser.add_argument('-o', '--output', dest="output_file", default=None,
                        help='Write output value to the specified file instead of stdout')
    parser.add_argument('--text-encoding', default='utf-8',
                        help='The encoding used for text. Default  is utf-8')
    parser.add_argument('-p', '--passphrase', default=None,
                        help='''The passphrase to be used for encryption/decryption. By default,
                                environment variable PULUMI_PASSPHRASE is used''')
    parser.add_argument('-s', '--salt-state', default=None,
                        help='''The "salt state" string, containing the salt and validation ciphertext, as
                                it appears in the "encryptionsalt" property of a Pulumi stack config file.
                                By default, environment variable PULUMI_SALT_STATE is used.''')
    parser.add_argument('--config-file', '-C', default=None,
                        help='''A YAML document (e.g., a Pulumi stack config file) that has a "salt state" string,
                                containing the salt and validation ciphertext, in the top level dict's
                                "encryptionsalt" property. By default environment variable PULUMI_SALT_STATE
                                is used''')
    parser.add_argument('--salt', default=None,
                        help='''A base64-encoded binary "salt" blob to be used for encryption/decryption without
                                validation of the passphrase. By default, environment
                                variable PULUMI_SALT is used''')
    parser.add_argument('--verification-string', default=None,
                        help='''The well-known string that should be encrypted and attached to the "salt-state" as a validator
                                for the passphrase. By default, "pulumi" is used, which is required for
                                compatibility with Pulumi.''')
    parser.add_argument('--hash-iterations', '-n', type=int, default=None,
                        help='''The number of SHA-256 hash iterations to apply to the passphrase/salt to generate the
                                AES-256 symmetric key used for encryption. A large number makes a weak passphrase more resistant
                                to dictionary attacks, at the expense of very slow initialization of the cipher. The
                                default is 1,000,000, which takes on the order of one second to initialized and is required to
                                be compatible with Pulumi.''')
    parser.set_defaults(func=self.cmd_bare)

    subparsers = parser.add_subparsers(
                        title='Commands',
                        description='Valid commands',
                        help='Additional help available with "<command-name> -h"')


    # ======================= version

    parser_version = subparsers.add_parser('version',
                            description='''Display version information. JSON-quoted string. If a raw string is desired, use -r.''')
    parser_version.set_defaults(func=self.cmd_version)

    # ======================= get-salt-state

    parser_get_salt_state = subparsers.add_parser('get-salt-state', description="Get or create a salt-state string")
    parser_get_salt_state.add_argument('--new', dest='new_salt_state', action='store_true', default=False,
                        help='''Force creation of a new salt state even if one is already defined by parameters/env vars.''')
    parser_get_salt_state.set_defaults(func=self.cmd_get_salt_state)

    # ======================= encrypt

    parser_encrypt = subparsers.add_parser('encrypt', description="Encrypt a secret")
    parser_encrypt.add_argument(
        '-t', '--type',
        dest='value_type',
        default=None,
        choices= [ 'raw-str', 'str', 'int', 'float', 'bool', 'json', 'base64', 'raw-base64'],
        help='''Specify how the provided input for the value is interpreted. All types
                except "raw-str" and "raw-base64" will be serialized as JSON before encrypting.
                "json" will interpret the input as JSON and reencode it in a compressed
                format. "base64" and "raw-base64" will encode arbitrary binary data as a
                base64 string before encrypting. Default is "raw-str".''')
    parser_encrypt.add_argument('--json', '-j', dest="vtype_json", action='store_true', default=False,
                        help='short for --type=json. The provided value is JSON text to be reserialized in compact form.')
    parser_encrypt.add_argument('--str', dest="vtype_str", action='store_true', default=False,
                        help='short for --type=str. The provided value is a string that should be serialized as JSON.')
    parser_encrypt.add_argument('--int', dest="vtype_int", action='store_true', default=False,
                        help='short for --type=int. The provided value is an integer that should be serialized as JSON.')
    parser_encrypt.add_argument('--float', dest="vtype_float", action='store_true', default=False,
                        help='short for --type=float. The provided value is a float that should be serialized as JSON.')
    parser_encrypt.add_argument('--bool', dest="vtype_bool", action='store_true', default=False,
                        help='short for --type=bool. The provided value is a boolean that should be serialized as JSON.')
    parser_encrypt.add_argument('--base64', dest="vtype_base64", action='store_true', default=False,
                        help='short for --type=base64. The provided value is binary data that should be encoded with base64'
                            ' then serialized as a JSON string.')
    parser_encrypt.add_argument('--raw-str', dest="vtype_raw_str", action='store_true', default=False,
                        help='short for --type=raw-str. The provided value is a string that should be directly encrypted.')
    parser_encrypt.add_argument('--raw-base64', dest="vtype_raw_base64", action='store_true', default=False,
                        help='short for --type=raw-base64. The provided value is binary data that should be encoded with '
                             'bas64 then directly encrypted')
    parser_encrypt.add_argument('--stdin', dest="use_stdin", action='store_true', default=False,
                        help='Read the value from stdin instead of the commandline')
    parser_encrypt.add_argument('-i', '--input', dest="input_file", default=None,
                        help='Read the value from the specified file instead of the commandline')
    parser_encrypt.add_argument('-w', '--write-salt-state', default=None,
                        help='Write the final salt state string to the given YAML file, in property "encryptionsalt')
    parser_encrypt.add_argument('--nonce', default=None,
                        help='A Base-64 encoded binary nonce value, typically 12 bytes long, to be used for '
                        'encrypting this value. By default, a random 12-byte nonce will be used.')

    parser_encrypt.add_argument('value',
                        nargs='?',
                        default=None,
                        help="""The value to be encrypted. By default, interpreted as a string value to be
                                JSON-serialized before encryption. Omit this parameter if --input or --stdin is provided.
                                See options for interpretaton.""")
    parser_encrypt.set_defaults(func=self.cmd_encrypt)

    # ======================= decrypt

    parser_decrypt = subparsers.add_parser('decrypt', description="Get the plaintext value associated with an encrypted value")
    parser_decrypt.add_argument(
        '-t', '--type',
        dest='value_type',
        default=None,
        choices= [ 'raw-str', 'str', 'int', 'float', 'bool', 'json', 'base64', 'raw-base64'],
        help='''Specify how the decrypted plaintext is interpreted. All types
                except "raw-str" and "raw-base64" will be deserialized from JSON before rendering.
                "base64" and "raw-base64" will decode arbitrary binary data from a base64 string before rendering.
                Default is "raw-str".''')
    parser_decrypt.add_argument('--json', '-j', dest="vtype_json", action='store_true', default=False,
                        help='short for --type=json. The plaintext is interpreted as JSON which will be reformatted for readability.')
    parser_decrypt.add_argument('--str', dest="vtype_str", action='store_true', default=False,
                        help='short for --type=str. The plaintext is interpreted as a JSON representation of a string.')
    parser_decrypt.add_argument('--int', dest="vtype_int", action='store_true', default=False,
                        help='short for --type=int. The plaintext is interpreted as a JSON representation of an integer.')
    parser_decrypt.add_argument('--float', dest="vtype_float", action='store_true', default=False,
                        help='short for --type=float. The plaintext is interpreted as a JSON representation of a float.')
    parser_decrypt.add_argument('--bool', dest="vtype_bool", action='store_true', default=False,
                        help='short for --type=bool. The plaintext is interpreted as a JSON representation of a bool.')
    parser_decrypt.add_argument('--base64', dest="vtype_base64", action='store_true', default=False,
                        help='short for --type=base64. The plaintext is interpreted as a JSON representation of a base64 '
                             'string, which is decoded to binary.')
    parser_decrypt.add_argument('--raw-str', dest="vtype_raw_str", action='store_true', default=False,
                        help='short for --type=raw-str. The plaintext is used as the result without transformation.')
    parser_decrypt.add_argument('--raw-base64', dest="vtype_raw_base64", action='store_true', default=False,
                        help='short for --type=raw-base64. The plaintext is interpreted as base64, which is decoded to binary.')
    parser_decrypt.add_argument('--stdin', dest="use_stdin", action='store_true', default=False,
                        help='Read the ciphertext from stdin instead of the commandline')
    parser_decrypt.add_argument('-i', '--input', dest="input_file", default=None,
                        help='Read the ciphertext from the specified file instead of the commandline')
    parser_decrypt.add_argument('-w', '--write-salt-state', default=None,
                        help='Write the final salt state string to a YAML file, in property "encryptionsalt')

    parser_decrypt.add_argument('ciphertext',
                        nargs='?',
                        default=None,
                        help="""The ciphertext to be decrypted. Omit this parameter if --input or --stdin is provided.
                                See options for interpretaton.""")
    parser_decrypt.set_defaults(func=self.cmd_decrypt)

    # =========================================================

    try:
      args = parser.parse_args(self._argv)
    except ArgparseExitError as ex:
      return ex.exit_code
    traceback: bool = args.traceback
    try:
      self._args = args
      self._raw_stdout = sys.stdout
      self._raw_stderr = sys.stderr
      self._raw = args.raw
      self._compact = args.compact
      self._output_file = args.output_file
      self._encoding = args.text_encoding
      monochrome: bool = args.monochrome
      if not monochrome:
        self._colorize_stdout = is_colorizable(sys.stdout)
        self._colorize_stderr = is_colorizable(sys.stderr)
        if self._colorize_stdout or self._colorize_stderr:
          colorama.init(wrap=False)
          if self._colorize_stdout:
            new_stream = colorama.AnsiToWin32(sys.stdout)
            if new_stream.should_wrap():
              sys.stdout = new_stream
          if self._colorize_stderr:
            new_stream = colorama.AnsiToWin32(sys.stderr)
            if new_stream.should_wrap():
              sys.stderr = new_stream

        if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
          self._colorize_stdout = True
        if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
          self._colorize_stderr = True
      rc = args.func()
    except Exception as ex:
      if isinstance(ex, CmdExitError):
        rc = ex.exit_code
      else:
        rc = 1
      if rc != 0:
        if traceback:
          raise

        print(f"{self.ecolor(Fore.RED)}pulumi-crypto: error: {ex}{self.ecolor(Style.RESET_ALL)}", file=sys.stderr)
    return rc

def run(argv: Optional[Sequence[str]]=None) -> int:
  try:
    rc = CommandHandler(argv).run()
  except CmdExitError as ex:
    rc = ex.exit_code
  return rc

# allow running with "python3 -m", or as a standalone script
if __name__ == "__main__":
  sys.exit(run())
