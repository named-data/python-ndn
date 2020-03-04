import sys
import asyncio as aio
import logging
from ndn.app import NDNApp
from ndn.encoding import Name
from ndn.app_support.security_v2 import parse_certificate
from ndn.schema import policy
from ndn.schema.schema_tree import Node
from ndn.schema.simple_node import RDRNode
from ndn.schema.simple_cache import MemoryCache, MemoryCachePolicy
from ndn.schema.simple_trust import SignedBy


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')
app = NDNApp()


async def main():
    if len(sys.argv) <= 1:
        print(f'Usage: {sys.argv[0]} <name> [<file>]')
        exit(0)

    # Setup root node and cache
    prefix = sys.argv[1]
    root = Node()
    cache = MemoryCache()
    root.set_policy(policy.Cache, MemoryCachePolicy(cache))

    # Store default public key
    kc = app.keychain
    id_name = Name.to_str(kc.default_identity().name)
    root[id_name + '/KEY/<KeyID>/self/<CertID>'] = Node()
    cert = kc.default_identity().default_key().default_cert().data
    cert_val = parse_certificate(cert)
    await cache.save(cert_val.name, cert)

    # Setup RDR node
    root[prefix] = RDRNode()
    root[prefix].set_policy(policy.DataValidator, SignedBy(root['/ndncc/KEY/<KeyID>']))

    # Attach node
    # Automatically registered prefix: /${prefix}, /${id_name}/KEY
    await root.attach(app, '/')

    if len(sys.argv) > 2:
        filename = sys.argv[2]
        print(f'Read {prefix} from file {filename}...')
        # Provider with file
        with open(filename, 'rb') as f:
            data = f.read()
            await root.match(prefix).provide(data, freshness_period=60000)
        # Wait for it to be cached
        await aio.sleep(0.1)
    else:
        # Consumer => Provider
        print(f'Try to fetch {prefix}...')

    data, metadata = await root.match(prefix).need()
    print(f'Content size: {len(data)}')
    print(f'Number of segments: {metadata["block_count"]}')
    print(f'Serving {prefix}')

if __name__ == '__main__':
    app.run_forever(after_start=main())
