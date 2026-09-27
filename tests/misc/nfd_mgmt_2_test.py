from ndn.app_support import nfd_mgmt as v1
from ndn.app_support import nfd_mgmt_2 as v2
from ndn.encoding import Name
from ndn.encoding.tlv_model_v2 import tlv_encode, tlv_parse


def test_make_command_v2_matches_v1():
    kwargs = dict(name='/example/prefix', face_id=300, origin=65, cost=10,
                  flags=1, expiration_period=3600000,
                  face_persistency=v1.FacePersistency.PERMANENT)
    assert v2.make_command_v2('rib', 'register', **kwargs) == \
        v1.make_command_v2('rib', 'register', **kwargs)
    assert v2.make_command_v2('strategy-choice', 'set', name='/a', strategy='/localhost/nfd/strategy/multicast') == \
        v1.make_command_v2('strategy-choice', 'set', name='/a', strategy='/localhost/nfd/strategy/multicast')


def test_make_command_matches_v1(monkeypatch):
    for mod in (v1, v2):
        monkeypatch.setattr(mod, 'timestamp', lambda: 1234567)
        monkeypatch.setattr(mod, 'gen_nonce_64', lambda: 0xdeadbeef)
    assert v2.make_command('faces', 'create', uri='udp4://127.0.0.1:6363') == \
        v1.make_command('faces', 'create', uri='udp4://127.0.0.1:6363')


def test_parse_response_matches_v1():
    cr = v1.ControlResponse()
    cr.status_code = 200
    cr.status_text = 'OK'
    cr.body = v1.ControlParametersValue()
    cr.body.name = '/example'
    cr.body.face_id = 5
    cr.body.uri = 'udp4://1.2.3.4:6363'
    cr.body.face_persistency = v1.FacePersistency.ON_DEMAND
    body = bytes(cr.encode())
    wire = bytes([0x65, len(body)]) + body

    ret = v2.parse_response(wire)
    assert ret == v1.parse_response(wire)
    assert ret['face_persistency'] is v2.FacePersistency.ON_DEMAND
    assert Name.to_str(ret['name']) == '/example'


def test_parse_response_without_body():
    body = tlv_encode(v2.ControlResponse(status_code=404, status_text='Not found'))
    ret = v2.parse_response(bytes([0x65, len(body)]) + body)
    assert ret['status_code'] == 404
    assert ret['status_text'] == 'Not found'
    assert ret['face_id'] is None


def test_face_status_interop():
    status = v1.FaceStatus()
    status.face_id = 1
    status.uri = 'internal://'
    status.face_scope = v1.FaceScope.LOCAL
    status.link_type = v1.FaceLinkType.POINT_TO_POINT
    status.flags = v1.FaceFlags.LOCAL_FIELDS_ENABLED | v1.FaceFlags.LP_RELIABILITY_ENABLED
    status.n_in_bytes = 2 ** 40
    msg = v1.FaceStatusMsg()
    msg.face_status = [status]
    wire = bytes(msg.encode())

    parsed = tlv_parse(v2.FaceStatusMsg, wire)
    assert len(parsed.face_status) == 1
    fs = parsed.face_status[0]
    assert fs.uri == 'internal://'
    assert fs.face_scope is v2.FaceScope.LOCAL
    assert fs.flags == v2.FaceFlags.LOCAL_FIELDS_ENABLED | v2.FaceFlags.LP_RELIABILITY_ENABLED
    assert fs.n_in_bytes == 2 ** 40
    assert bytes(tlv_encode(parsed)) == wire


def test_rib_status_interop():
    rib = v2.RibStatus(entries=[
        v2.RibEntry(name='/a', routes=[v2.Route(face_id=1, origin=0, cost=0,
                                                flags=v2.RouteFlags.CHILD_INHERIT)]),
        v2.RibEntry(name='/b', routes=[]),
    ])
    wire = bytes(tlv_encode(rib))
    parsed = v1.RibStatus.parse(wire)
    assert [Name.to_str(e.name) for e in parsed.entries] == ['/a', '/b']
    assert parsed.entries[0].routes[0].flags == v1.RouteFlags.CHILD_INHERIT
    assert bytes(parsed.encode()) == wire
