# -----------------------------------------------------------------------------
# Copyright (C) 2023-2023 The python-ndn authors
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
import logging
import typing
import secrets
import time
import asyncio as aio
from enum import Enum
from ... import encoding as enc
from ... import appv2 as app
from .tlv import StateVec, StateVecWrapper, StateVecEntry


__all__ = ['OnMissingDataFunc', 'SvsState', 'SvsInst']


OnMissingDataFunc = typing.Callable[["SvsInst"], None]
r"""
Called when there is a missing event.
MUST BE NON-BLOCKING. Therefore, it is not allowed to fetch the missing data in this callback.
It can start a task or trigger a signal to fetch missing data.
"""


class SvsState(Enum):
    SyncSteady = 0
    SyncSuppression = 1


class SvsInst:
    on_missing: OnMissingDataFunc
    sync_interval: float
    suppression_interval: float
    base_prefix: enc.FormalName
    on_missing_data: OnMissingDataFunc

    local_sv: dict[bytes, int]
    agg_sv: dict[bytes, int]
    state: SvsState
    self_seq: int
    self_node_id: bytes
    running: bool
    ndn_app: app.NDNApp | None

    next_sync_timing: float = 0.0
    timer_rst_event: aio.Event | None
    int_signer: enc.Signer
    int_validator: app.Validator
    timer_task: aio.Task | None

    def __init__(self, base_prefix: enc.NonStrictName, self_node_id: enc.NonStrictName,
                 on_missing_data: OnMissingDataFunc, sync_int_signer: enc.Signer,
                 sync_int_validator: app.Validator,
                 sync_interval: float = 30, suppression_interval: float = 0.2,
                 last_used_seq_num: int = 0):
        self.base_prefix = enc.Name.normalize(base_prefix)
        self.self_node_id = enc.Name.to_bytes(self_node_id)
        self.sync_interval = sync_interval
        self.suppression_interval = suppression_interval
        self.on_missing_data = on_missing_data
        self.local_sv = {}
        self.agg_sv = {}
        self.state = SvsState.SyncSteady
        self.self_seq = last_used_seq_num
        self.running = False
        self.timer_rst_event = None
        self.ndn_app = None
        self.int_signer = sync_int_signer
        self.int_validator = sync_int_validator
        self.timer_task = None
        self.logger = logging.getLogger(__name__)

    def sample_sync_timer(self):
        dev = secrets.randbits(16) / 327680 * self.sync_interval
        return self.sync_interval + dev - self.sync_interval * 0.1

    def sample_sup_timer(self):
        dev = secrets.randbits(16) / 65536 * self.suppression_interval
        return self.suppression_interval + dev - self.suppression_interval * 0.5

    def sync_handler(self, name: enc.FormalName, _app_param: enc.BinaryStr | None,
                     _reply: app.ReplyFunc, _context: app.PktContext) -> None:
        if len(name) != len(self.base_prefix) + 2:
            self.logger.error(f'Received invalid Sync Interest: {enc.Name.to_str(name)}')
            return
        try:
            remote_sv_pkt = StateVecWrapper.parse(name[-2]).val
        except (enc.DecodeError, IndexError) as e:
            self.logger.error(f'Unable to decode state vector [{enc.Name.to_str(name)}]: {e}')
            return

        if remote_sv_pkt is None or not remote_sv_pkt.entries:
            return
        remote_sv = remote_sv_pkt.entries

        # No lock is needed since we do not await
        # Compare state vectors
        rsv_dict = {}
        for rsv in remote_sv:
            if not rsv.node_id:
                continue
            rsv_id = enc.Name.to_bytes(rsv.node_id)
            rsv_seq = rsv.seq_no
            if rsv_id == self.self_node_id and rsv_seq > self.self_seq:
                self.logger.error('Remote side has more local data for local node.')
                return
            rsv_dict[rsv_id] = rsv_seq

        need_notif = len(rsv_dict.keys() - self.local_sv.keys()) > 0
        need_fetch = False
        for rsv_id, rsv_seq in rsv_dict.items():
            lsv_seq = self.local_sv.get(rsv_id, 0)
            if lsv_seq < rsv_seq:
                # Remote is latest
                need_fetch = True
                self.local_sv[rsv_id] = rsv_seq
                self.logger.debug(f'Missing data for: [{enc.Name.to_str(rsv_id)}]: {lsv_seq} < {rsv_seq}')
            elif lsv_seq > rsv_seq:
                # Local is latest
                need_notif = True
                self.logger.debug(f'Outdated remote on: [{enc.Name.to_str(rsv_id)}]: {rsv_seq} < {lsv_seq}')

        if need_notif or self.state == SvsState.SyncSuppression:
            # Set the aggregation timer
            if self.state == SvsState.SyncSteady:
                self.state = SvsState.SyncSuppression
                self.agg_sv = rsv_dict.copy()
                # Reset sync timer
                self.next_sync_timing = time.time() + self.sample_sup_timer()
                self.timer_rst_event.set()
            else:
                self.aggregate(rsv_dict)
        else:
            # Reset sync timer
            self.next_sync_timing = time.time() + self.sample_sync_timer()
            self.timer_rst_event.set()

        if need_fetch:
            self.on_missing_data(self)

    def aggregate(self, rsv_dict: dict[bytes, int]):
        for rsv_id, rsv_seq in rsv_dict.items():
            asv_seq = self.local_sv.get(rsv_id, 0)
            self.agg_sv[rsv_id] = max(asv_seq, rsv_seq)

    async def on_timer(self):
        while self.running:
            try:
                # Timer reset event
                await aio.wait_for(self.timer_rst_event.wait(), timeout=max(self.next_sync_timing - time.time(), 0))
                self.timer_rst_event.clear()
            except aio.CancelledError:
                break
            except aio.TimeoutError:
                # The real timer triggered
                # Note: this part is non-blocking
                if not self.running:
                    return
                necessary = True
                if self.state == SvsState.SyncSuppression:
                    self.state = SvsState.SyncSteady
                    necessary = False
                    for lsv_id, lsv_seq in self.local_sv.items():
                        if self.agg_sv.get(lsv_id, 0) < lsv_seq:
                            necessary = True
                            break
                if necessary:
                    self.express_sync_interest()
                self.timer_rst_event.clear()
                self.next_sync_timing = time.time() + self.sample_sync_timer()

    def express_sync_interest(self):
        # Append sv to name does not make any sense, but the spec says so
        sv_pkt = StateVecWrapper()
        sv_pkt.val = StateVec()
        sv_pkt.val.entries = []
        for lsv_id, lsv_seq in self.local_sv.items():
            cur = StateVecEntry()
            cur.node_id = enc.Name.from_bytes(lsv_id)
            cur.seq_no = lsv_seq
            sv_pkt.val.entries.append(cur)
        sync_name = self.base_prefix + [sv_pkt.encode()]
        self.ndn_app.express(sync_name, app.pass_all, signer=self.int_signer, no_response=True)

    def new_data(self):
        self.self_seq += 1
        self.local_sv[self.self_node_id] = self.self_seq
        # Emit a sync Interest immediately
        self.state = SvsState.SyncSteady
        self.next_sync_timing = 0
        if self.running:
            self.timer_rst_event.set()
        return self.self_seq

    def start(self, ndn_app: app.NDNApp):
        if self.running:
            raise RuntimeError(f'Sync is already running @[{enc.Name.to_str(self.base_prefix)}]')
        self.running = True
        self.timer_rst_event = aio.Event()
        if self.self_seq >= 0:
            self.local_sv[self.self_node_id] = self.self_seq
        self.ndn_app = ndn_app
        self.ndn_app.attach_handler(self.base_prefix, self.sync_handler, self.int_validator)
        self.timer_task = aio.create_task(self.on_timer())

    def stop(self):
        if not self.running:
            return
        self.running = False
        self.timer_rst_event.set()
        self.ndn_app.detach_handler(self.base_prefix)
        self.timer_task = None
