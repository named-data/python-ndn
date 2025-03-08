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

from . import (
    cmd_compile_lvs,
    cmd_fetch_data,
    cmd_fetch_rdrcontent,
    cmd_serve_data,
    cmd_serve_rdrcontent,
)


CMD_LIST = """
Available commands:
  Serve-Data (poke,sd)
  Fetch-Data (peek,fd)
  Serve-RdrContent (putchunks,src)
  Fetch-RdrContent (catchunks,frc)
  Compile-Lvs (compile-lvs)

Try '%(prog)s COMMAND -h' for more information on each command
"""


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=CMD_LIST
    )
    subparsers = parser.add_subparsers(metavar="COMMAND", help="sub-command to execute")

    cmd_fetch_data.add_parser(subparsers)
    cmd_serve_data.add_parser(subparsers)
    cmd_fetch_rdrcontent.add_parser(subparsers)
    cmd_serve_rdrcontent.add_parser(subparsers)
    cmd_compile_lvs.add_parser(subparsers)

    args = parser.parse_args()
    if "executor" not in args:
        parser.print_help()
        exit(-1)

    return args.executor(args)
