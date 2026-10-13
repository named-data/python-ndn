# -----------------------------------------------------------------------------
# Copyright (C) 2019-2026 The python-ndn authors
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
import logging

from ndn import app, encoding as enc, utils


SEGMENT_SIZE = 4400


def main():
    parser = argparse.ArgumentParser(
        description='Serve a file as segmented Data.',
    )
    parser.add_argument('name', help='base NDN name')
    parser.add_argument('file', help='file to serve')
    args = parser.parse_args()

    logging.basicConfig(
        format='[{asctime}]{levelname}:{message}',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO,
        style='{',
    )

    base_name = enc.Name.normalize(args.name)
    versioned_name = base_name + [
        enc.Component.from_version(utils.timestamp()),
    ]
    with open(args.file, 'rb') as input_file:
        contents = input_file.read()
    segment_count = max(1, (len(contents) + SEGMENT_SIZE - 1) // SEGMENT_SIZE)
    final_block_id = enc.Component.from_segment(segment_count - 1)

    ndn_app = app.NDNApp()
    keychain = ndn_app.default_keychain()
    signer = keychain.get_signer({})
    packets = [
        ndn_app.make_data(
            versioned_name + [enc.Component.from_segment(segment_no)],
            content=contents[
                segment_no * SEGMENT_SIZE:(segment_no + 1) * SEGMENT_SIZE
            ],
            signer=signer,
            freshness_period=10000,
            final_block_id=final_block_id,
        )
        for segment_no in range(segment_count)
    ]

    print(
        f'Created {segment_count} segments under '
        f'{enc.Name.to_str(versioned_name)}'
    )

    @ndn_app.route(base_name)
    def on_interest(
        name: enc.FormalName,
        _app_param: enc.BinaryStr | None,
        reply: app.ReplyFunc,
        _context: app.PktContext,
    ):
        if name == base_name or name == versioned_name:
            segment_no = 0
        elif (
            enc.Name.is_prefix(versioned_name, name)
            and len(name) == len(versioned_name) + 1
            and enc.Component.get_type(name[-1]) == enc.Component.TYPE_SEGMENT
        ):
            segment_no = enc.Component.to_number(name[-1])
        else:
            return

        if segment_no < segment_count:
            reply(packets[segment_no])

    try:
        ndn_app.run_forever()
    finally:
        keychain.shutdown()


if __name__ == '__main__':
    main()
