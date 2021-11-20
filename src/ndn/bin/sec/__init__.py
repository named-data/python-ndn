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
from . import cmd_init_pib, cmd_get_childitem, cmd_get_default, cmd_set_default, \
    cmd_new_item, cmd_sign_cert, cmd_remove_item, cmd_export_cert, cmd_import_cert, \
    cmd_get_signreq


CMD_LIST = '''
Available commands:
  Init-Pib (init)             Initialize a new PIB
  Get-ChildItem (list,ls,gci) List all known identities/keys/certificates
  Get-Default (gd)            Show the default identity/key/certificate
  Set-Default (sd)            Change the default identity/key/certificate
  New-Item (key-gen,ni)       Create a new identity or a new key
  Sign-Cert (cert-gen,sc)     Issue a new certificate for an external sign request
  Remove-Item (del,ri,rm)     Delete an identity/key/certificate
  Export-Cert (export,ec)     Export the default certificate
  Import-Cert (import,ic)     Import a certificate from a file
  Get-SignReq (sign-req,gsr)  Generate a certificate signing request

Try '%(prog)s COMMAND -h' for more information on each command
'''


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=CMD_LIST)
    subparsers = parser.add_subparsers(metavar='COMMAND', help='sub-command to execute')

    cmd_init_pib.add_parser(subparsers)
    cmd_get_childitem.add_parser(subparsers)
    cmd_get_default.add_parser(subparsers)
    cmd_set_default.add_parser(subparsers)
    cmd_new_item.add_parser(subparsers)
    cmd_sign_cert.add_parser(subparsers)
    cmd_remove_item.add_parser(subparsers)
    cmd_export_cert.add_parser(subparsers)
    cmd_import_cert.add_parser(subparsers)
    cmd_get_signreq.add_parser(subparsers)

    parser.add_argument('--pib', metavar='PIB_SCHEME', choices=['pib-sqlite3'], default='pib-sqlite3',
                        help='the scheme of PIB. Only pib-sqlite3 is available currently.')
    parser.add_argument('--path', metavar='PIB_PATH', help='the path to the base folder of PIB. '
                                                           'By default it is "~/.ndn" or "%%LOCALAPPDATA%%\\ndn".')
    parser.add_argument('--tpm', metavar='TPM_SCHEME', choices=['tpm-file', 'tpm-osxkeychain', 'tpm-cng'],
                        help='the TPM scheme. Must be tpm-file, tpm-osxkeychain or tpm-cng.')
    parser.add_argument('--tpm-path', help='the path of TPM when the scheme is tpm-file')

    args = parser.parse_args()
    if 'executor' not in args:
        parser.print_help()
        exit(-1)

    return args.executor(args)
