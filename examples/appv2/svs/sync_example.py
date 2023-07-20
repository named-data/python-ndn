import typing
import logging
import asyncio as aio
from ndn import appv2
from ndn import encoding as enc
from ndn import types
from ndn import security as sec
from ndn.app_support import svs as svs
import random


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


fetched_dict = {}
fetch_signal = aio.Event()
running = False
group_prefix = enc.Name.from_str('/example/testSvs')


def on_missing_data(_svs_inst: svs.SvsInst):
    # This function must be non-blocking
    fetch_signal.set()


app = appv2.NDNApp()
keychain = app.default_keychain()
text_node_id = f'node-{random.randbytes(4).hex()}'
name_node_id = enc.Name.from_str(text_node_id)
node_name = name_node_id + group_prefix
svs_inst = svs.SvsInst(
    group_prefix, name_node_id,
    on_missing_data,
    sec.DigestSha256Signer(),
    appv2.pass_all,
    sync_interval=10,
)
packet_cache = {}


@app.route(node_name)
def data_pkt_handler(name, _app_param, reply, _context):
    name_bytes = enc.Name.to_bytes(name)
    ret = packet_cache.get(name_bytes, None)
    if ret:
        reply(ret)


async def fetch_missing_data():
    while running:
        await fetch_signal.wait()
        if not running:
            return
        local_sv = svs_inst.local_sv.copy()
        fetch_signal.clear()
        del local_sv[enc.Name.to_bytes(name_node_id)]
        for node_id, seq in local_sv.items():
            fetched_seq = fetched_dict.get(node_id, -1)
            node_name = enc.Name.from_bytes(node_id) + group_prefix
            if fetched_seq < seq:
                fetched_dict[node_id] = seq
                for i in range(fetched_seq+1, seq+1):
                    pkt_name = node_name + [enc.Component.from_sequence_num(i)]
                    try:
                        _, data, _ = await app.express(pkt_name, appv2.pass_all)
                        logging.info(f'Fetched {enc.Name.to_str(pkt_name)}: {bytes(data).decode()}')
                    except types.InterestNack as e:
                        logging.info(f'[{enc.Name.to_str(pkt_name)}] Nacked with reason={e.reason}')
                    except types.InterestTimeout:
                        logging.info(f'[{enc.Name.to_str(pkt_name)}] Timeout')
                    except types.InterestCanceled:
                        logging.info(f'[{enc.Name.to_str(pkt_name)}] Canceled')
                    except types.ValidationFailure:
                        logging.info(f'[[{enc.Name.to_str(pkt_name)}] Data failed to validate')


async def generate_data():
    seq = 0
    while running:
        data = f'[{text_node_id}] DATA {seq}'.encode()
        name = node_name + [enc.Component.from_sequence_num(seq)]
        data_pkt = app.make_data(name, data, sec.DigestSha256Signer(), freshness_period=5000)
        packet_cache[enc.Name.to_bytes(name)] = data_pkt
        svs_seq = svs_inst.new_data()
        assert svs_seq == seq
        seq += 1
        logging.info(f'Produced data: {data.decode()}')
        await aio.sleep(random.random()*4 + 1.0)


async def main():
    global running
    running = True
    gen_data_task = aio.create_task(generate_data())
    fetch_missing_task = aio.create_task(fetch_missing_data())
    logging.info(f'Run as {text_node_id} ...')

    async def after_start():
        svs_inst.start(app)
        await app.register(group_prefix)

    try:
        await app.main_loop(after_start())
    except KeyboardInterrupt:
        logging.info('Receiving Ctrl+C, exit')

    # await app.unregister(group_prefix)
    svs_inst.stop()
    running = False
    fetch_signal.set()
    await aio.gather(gen_data_task, fetch_missing_task)
    # await app.shutdown()


if __name__ == '__main__':
    aio.run(main())
