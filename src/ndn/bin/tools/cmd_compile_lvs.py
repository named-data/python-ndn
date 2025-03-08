# -----------------------------------------------------------------------------
# Copyright (C) 2025-2025 The python-ndn authors
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
import os
import sys

import lark
from ndn.app_support.light_versec import compile_lvs, SemanticError
from ndn.app_support.light_versec.binary import *


def add_parser(subparsers):
    parser = subparsers.add_parser("Compile-Lvs", aliases=["compile-lvs"])
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default="-",
        help="Write compiled result into a file",
    )
    parser.add_argument(
        "input_file",
        metavar="FILE",
        nargs="?",
        default="-",
        help="file containing the content of the LVS text, '-' for stdin (default)",
    )
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    try:
        if args.input_file == "-":
            text = sys.stdin.read()
        else:
            with open(os.path.expandvars(args.input_file), "r") as f:
                text = f.read()
    except (ValueError, OSError, IndexError):
        print("Unable to read the input file")
        return -1

    try:
        lvs_model = compile_lvs(text)
    except (SemanticError, lark.UnexpectedInput) as e:
        print("Unable to compile the LVS text input:", e)
        return -2

    encoded_output = bytes(lvs_model.encode())

    if args.output:
        if args.output == "-":
            sys.stdout.buffer.write(encoded_output)
        else:
            with open(os.path.expandvars(args.output), "wb") as f:
                f.write(encoded_output)
