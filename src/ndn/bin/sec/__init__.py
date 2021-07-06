# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import argparse
from . import cmd_init, cmd_list


CMD_LIST = '''
Available commands:
  init           Initialize a PIB
  list           List all known identities/keys/certificates
  get-default    Show the default identity/key/certificate
  set-default    Change the default identity/key/certificate
  delete         Delete an identity/key/certificate
  key-gen        Generate a key for an identity
  sign-req       Generate a certificate signing request
  cert-gen       Create a certificate for an identity
  cert-dump      Export a certificate
  cert-install   Import a certificate from a file
  
Try '%(prog)s COMMAND -h' for more information on each command
'''


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=CMD_LIST)
    subparsers = parser.add_subparsers(metavar='COMMAND', help='sub-command to execute')

    cmd_init.add_parser(subparsers)
    cmd_list.add_parser(subparsers)

    parser.add_argument('--pib', metavar='PIB_SCHEMA', choices=['pib-sqlite3'], default='pib-sqlite3',
                        help='the schema of PIB. Only pib-sqlite3 is available currently.')
    parser.add_argument('--path', metavar='PIB_PATH', help='the path to the base folder of PIB. '
                                                           'By default it is "~/.ndn" or "%%LOCALAPPDATA%%\\ndn".')
    parser.add_argument('--tpm', metavar='TPM_SCHEMA', choices=['tpm-file', 'tpm-osxkeychain', 'tpm-cng'],
                        help='the TPM schema. Must be tpm-file, tpm-osxkeychain or tpm-cng.')
    parser.add_argument('--tpm-path', help='the path of TPM when the schema is tpm-file')

    args = parser.parse_args()
    if 'executor' not in args:
        parser.print_help()
        exit(-1)

    return args.executor(args)
