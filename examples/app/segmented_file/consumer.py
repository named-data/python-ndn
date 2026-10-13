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
import sys

from ndn import app, encoding as enc, types


async def fetch_file(
    ndn_app: app.NDNApp,
    name: enc.NonStrictName,
    timeout: int = 4000,
    retry_times: int = 3,
) -> bytes:
    if retry_times <= 0:
        raise ValueError('retry_times must be positive')

    async def retry(interest_name, can_be_prefix):
        for attempt in range(retry_times):
            try:
                return await ndn_app.express(
                    interest_name,
                    validator=app.pass_all,
                    must_be_fresh=True,
                    can_be_prefix=can_be_prefix,
                    lifetime=timeout,
                )
            except types.InterestTimeout:
                if attempt + 1 == retry_times:
                    raise

    data_name, content, context = await retry(name, True)
    if content is None:
        raise ValueError('Data packet has no Content')
    if (
        not data_name
        or enc.Component.get_type(data_name[-1]) != enc.Component.TYPE_SEGMENT
    ):
        return bytes(content)

    final_block_id = context['meta_info'].final_block_id
    if (
        final_block_id is None
        or enc.Component.get_type(final_block_id)
        != enc.Component.TYPE_SEGMENT
    ):
        raise ValueError('Data packet does not contain a segment FinalBlockId')
    final_segment = enc.Component.to_number(final_block_id)
    versioned_name = data_name[:-1]
    first_segment = enc.Component.to_number(data_name[-1])
    if first_segment > final_segment:
        raise ValueError('First segment is beyond FinalBlockId')
    if first_segment == 0:
        chunks = [bytes(content)]
        next_segment = 1
    else:
        chunks = []
        next_segment = 0

    for segment_no in range(next_segment, final_segment + 1):
        expected_name = versioned_name + [
            enc.Component.from_segment(segment_no),
        ]
        fetched_name, content, fetched_context = await retry(
            expected_name,
            False,
        )
        if fetched_name != expected_name:
            raise ValueError(
                f'Expected {enc.Name.to_str(expected_name)}, '
                f'got {enc.Name.to_str(fetched_name)}'
            )
        if content is None:
            raise ValueError(f'Segment {segment_no} has no Content')
        if fetched_context['meta_info'].final_block_id != final_block_id:
            raise ValueError(
                f'Segment {segment_no} has an inconsistent FinalBlockId'
            )
        chunks.append(bytes(content))

    print(
        f'Fetched {final_segment + 1} segments from '
        f'{enc.Name.to_str(versioned_name)}',
        file=sys.stderr,
    )
    return b''.join(chunks)


def main():
    parser = argparse.ArgumentParser(description='Fetch a segmented file.')
    parser.add_argument('name', help='base NDN name')
    parser.add_argument(
        'output',
        nargs='?',
        help='output file; writes to standard output when omitted',
    )
    args = parser.parse_args()

    logging.basicConfig(
        format='[{asctime}]{levelname}:{message}',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO,
        style='{',
    )

    ndn_app = app.NDNApp()

    async def after_start():
        try:
            contents = await fetch_file(ndn_app, args.name)
            if args.output is None:
                sys.stdout.buffer.write(contents)
                sys.stdout.buffer.flush()
            else:
                with open(args.output, 'wb') as output_file:
                    output_file.write(contents)
        except types.InterestNack as exc:
            print(f'Nacked with reason={exc.reason}', file=sys.stderr)
        except types.InterestTimeout:
            print('Timeout', file=sys.stderr)
        except types.InterestCanceled:
            print('Canceled', file=sys.stderr)
        except types.ValidationFailure:
            print('Data failed to validate', file=sys.stderr)
        finally:
            ndn_app.shutdown()

    ndn_app.run_forever(after_start=after_start())


if __name__ == '__main__':
    main()
