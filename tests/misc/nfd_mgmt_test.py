from ndn.app_support import nfd_mgmt
from ndn.encoding import Name, tlv_encode, tlv_parse
from ndn.security.signer import sha256_digest_signer


def test_make_command_wire_format(monkeypatch):
    monkeypatch.setattr(nfd_mgmt, 'timestamp', lambda: 1234567)
    monkeypatch.setattr(nfd_mgmt, 'gen_nonce_64', lambda: 0xdeadbeef)
    monkeypatch.setattr(sha256_digest_signer, 'timestamp', lambda: 1234567)

    command = nfd_mgmt.make_command(
        'faces',
        'create',
        uri='udp4://127.0.0.1:6363',
    )
    assert Name.to_bytes(command) == bytes.fromhex(
        '077f08096c6f63616c686f737408036e6664080566616365730806637265617465'
        '081968177215756470343a2f2f3132372e302e302e313a36333633080800000000'
        '0012d687080800000000deadbeef080b16091b010028040012d68708221720'
        '4744ed7fd39b467ad7adccb05929ff3da1d2b7d003895224c3fa8ff77f0c2770'
    )


def test_make_command_v2_wire_format():
    command = nfd_mgmt.make_command_v2(
        'rib',
        'register',
        name='/example/prefix',
        face_id=300,
        origin=65,
        cost=10,
        flags=1,
        expiration_period=3600000,
        face_persistency=nfd_mgmt.FacePersistency.PERMANENT,
    )
    assert Name.to_bytes(command) == bytes.fromhex(
        '074c08096c6f63616c686f737408036e6664080372696208087265676973746572'
        '082b6829071108076578616d706c6508067072656669786902012c6f01416a010a'
        '6c01016d040036ee80850102'
    )


def test_parse_response_round_trip():
    response = nfd_mgmt.ControlResponse(
        status_code=200,
        status_text='OK',
        body=nfd_mgmt.ControlParametersValue(
            name='/example',
            face_id=5,
            uri='udp4://1.2.3.4:6363',
            face_persistency=nfd_mgmt.FacePersistency.ON_DEMAND,
        ),
    )
    body = bytes(tlv_encode(response))
    parsed = nfd_mgmt.parse_response(bytes([0x65, len(body)]) + body)

    assert parsed['status_code'] == 200
    assert parsed['status_text'] == 'OK'
    assert Name.to_str(parsed['name']) == '/example'
    assert parsed['face_id'] == 5
    assert parsed['face_persistency'] is nfd_mgmt.FacePersistency.ON_DEMAND


def test_face_status_wire_format_and_round_trip():
    status = nfd_mgmt.FaceStatus(
        face_id=1,
        uri='internal://',
        face_scope=nfd_mgmt.FaceScope.LOCAL,
        link_type=nfd_mgmt.FaceLinkType.POINT_TO_POINT,
        flags=(
            nfd_mgmt.FaceFlags.LOCAL_FIELDS_ENABLED
            | nfd_mgmt.FaceFlags.LP_RELIABILITY_ENABLED
        ),
        n_in_bytes=2 ** 40,
    )
    wire = bytes(tlv_encode(nfd_mgmt.FaceStatusMsg(face_status=[status])))
    assert wire == bytes.fromhex(
        '8023690101720b696e7465726e616c3a2f2f840101860100'
        '940800000100000000006c0103'
    )

    parsed = tlv_parse(nfd_mgmt.FaceStatusMsg, wire)
    assert parsed.face_status[0].face_scope is nfd_mgmt.FaceScope.LOCAL
    assert parsed.face_status[0].n_in_bytes == 2 ** 40


def test_parse_response_without_body():
    body = tlv_encode(
        nfd_mgmt.ControlResponse(status_code=404, status_text='Not found')
    )
    parsed = nfd_mgmt.parse_response(bytes([0x65, len(body)]) + body)
    assert parsed['status_code'] == 404
    assert parsed['status_text'] == 'Not found'
    assert parsed['face_id'] is None
