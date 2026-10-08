import dataclasses as dc

from ndn.app_support.svs.tlv import (
    MappingData,
    MappingDataWrapper,
    MappingEntry,
    StateVecEntry,
    StateVec,
    StateVecWrapper,
)
from ndn.encoding import Name, tlv_encode, tlv_parse


def test_state_vector_dataclass_wire_format():
    state = StateVecWrapper(
        StateVec(entries=[StateVecEntry(node_id='/node', seq_no=7)])
    )
    assert dc.is_dataclass(state)

    wire = bytes(tlv_encode(state))
    assert wire == bytes.fromhex('c90dca0b070608046e6f6465cc0107')

    parsed = tlv_parse(StateVecWrapper, wire)
    assert Name.to_str(parsed.val.entries[0].node_id) == '/node'
    assert parsed.val.entries[0].seq_no == 7


def test_mapping_models_wire_format():
    mapping = MappingData(
        node_id='/node',
        entries=MappingEntry(seq_no=7, app_name='/app'),
    )
    wire = bytes(tlv_encode(mapping))
    assert wire == bytes.fromhex('070608046e6f6465ce0acc010707050803617070')

    parsed = tlv_parse(MappingData, wire)
    assert Name.to_str(parsed.node_id) == '/node'
    assert Name.to_str(parsed.entries.app_name) == '/app'
    assert parsed.entries.seq_no == 7

    wrapper_wire = bytes(tlv_encode(
        MappingDataWrapper(MappingEntry(seq_no=7, app_name='/app'))
    ))
    assert wrapper_wire == bytes.fromhex('cd0acc010707050803617070')
