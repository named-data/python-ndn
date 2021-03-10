# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
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
import sys
import asyncio as aio
import logging
from ndn.app import NDNApp
from ndn.encoding import Name
from ndn.schema import policy
from ndn.schema.schema_tree import Node
from ndn.schema.simple_node import RDRNode
from ndn.schema.simple_cache import MemoryCache, MemoryCachePolicy
from ndn.schema.simple_trust import SignedBy


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')
app = NDNApp()


async def main():
    if len(sys.argv) <= 1:
        print(f'Usage: {sys.argv[0]} <name> [<file-path>]')
        exit(0)

    # Make schema tree
    root = Node()
    root['/<IDName>/KEY/<KeyID>/self/<CertID>'] = Node()
    root['/file/<FileName>'] = RDRNode()

    # Set policies
    id_name = Name.Component.get_value(app.keychain.default_identity().name[0])
    cache = MemoryCache()
    root.set_policy(policy.Cache, MemoryCachePolicy(cache))
    root['/file/<FileName>'].set_policy(
        policy.DataValidator,
        SignedBy(root['/<IDName>/KEY/<KeyID>'],
                 subject_to=lambda _, vars: vars['IDName'] == id_name))

    # Store the certificate
    cert = app.keychain.default_identity().default_key().default_cert()
    await cache.save(Name.normalize(cert.name), cert.data)

    # Attach the tree to the face
    await root.attach(app, '/')

    filename = sys.argv[1]
    if len(sys.argv) > 2:
        # If it's the producer
        filepath = sys.argv[2]
        print(f'Read {filename} from file {filepath}...')
        # Provider with file
        with open(filepath, 'rb') as f:
            data = f.read()
            await root.match('/file/' + filename).provide(data, freshness_period=60000)
        # Wait for it to be cached
        await aio.sleep(0.1)
    else:
        # If it's the producer
        print(f'Try to fetch {filename}...')

    # The file is ready!
    data, metadata = await root.match('/file/' + filename).need()
    print(f'Content size: {len(data)}')
    print(f'Content: {data[:70]} ...')
    print(f'Number of segments: {metadata["block_count"]}')
    print(f'Serving {filename}')

if __name__ == '__main__':
    app.run_forever(after_start=main())
