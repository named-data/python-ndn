from typing import Union, List, Tuple
from ..encoding import Name, Component, BinaryStr, get_tl_num_size, TypeNumber, write_tl_num

NamePattern = List[Union[BinaryStr, Tuple[int, int, str]]]


def norm_pattern(name: str) -> NamePattern:
    ret = Name.normalize(name)[:]
    for i, comp in enumerate(ret):
        comp_type = Component.get_type(comp)
        comp_value = Component.get_value(comp)
        if comp_type == Component.TYPE_GENERIC and comp_value[0] == b'<'[0] and comp_value[-1] == b'>'[0]:
            content = bytes(comp_value[1:-1]).decode()
            eq_sgn = content.find(':')
            if eq_sgn >= 0:
                type_str = content[:eq_sgn]
                if type_str == 'sha256digest':
                    type_val = Component.TYPE_IMPLICIT_SHA256
                elif type_str == 'params-sha256':
                    type_val = Component.TYPE_PARAMETERS_SHA256
                elif type_str in Component.ALTERNATE_URI_STR:
                    type_val = Component.ALTERNATE_URI_STR[type_str]
                else:
                    type_val = int(type_str)
                content = content[eq_sgn+1:]
            else:
                type_val = Component.TYPE_GENERIC
            if not content:
                raise ValueError('Pattern variable name cannot be empty')
            ret[i] = (0, type_val, content)
    return ret

