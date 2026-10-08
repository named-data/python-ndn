from ndn.encoding import Name
from ndn.encoding import ndn_format_0_3_2017 as fmt


def test_forwarding_hint_round_trip():
    wire = fmt.make_interest(
        '/test',
        fmt.InterestParam(forwarding_hint=[(1, '/hint')]),
    )
    assert wire == bytes.fromhex(
        '051b07060804746573741e0d1f0b1e01010706080468696e740c020fa0'
    )

    name, params, app_params, _ = fmt.parse_interest(wire)
    assert name == Name.from_str('/test')
    assert params.forwarding_hint == [(1, Name.from_str('/hint'))]
    assert app_params is None


def test_missing_meta_info_is_preserved():
    name, meta_info, content, _ = fmt.parse_data(bytes.fromhex('06020700'))
    assert name == []
    assert meta_info is None
    assert content is None
