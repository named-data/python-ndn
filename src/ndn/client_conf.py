import os
from configparser import ConfigParser


def read_client_conf():
    def get_path():
        path = os.path.expanduser('~/.ndn/client.conf')
        if os.path.exists(path):
            return path
        path = '/usr/local/etc/ndn/client.conf'
        if os.path.exists(path):
            return path
        path = '/opt/local/etc/ndn/client.conf'
        if os.path.exists(path):
            return path
        path = '/etc/ndn/client.conf'
        if os.path.exists(path):
            return path

    def resolve_loaction(value):
        nonlocal path
        sp = value.split(':')
        if len(sp) == 1:
            schema = value
            loc = ''
        else:
            schema, loc = sp
        if not loc or not os.path.exists(loc):
            if loc:
                loc = os.path.join(os.path.dirname(path), loc)
            if not loc or not os.path.exists(loc):
                loc = '~/.ndn/ndnsec-key-file' if schema == 'tpm-file' else '~/.ndn'
                loc = os.path.expanduser(loc)
        return ':'.join((schema, loc))

    path = get_path()
    ret = {
        'transport': 'unix:///var/run/nfd.sock',
        'pib': 'pib-sqlite3',
        'tpm': 'tpm-file'
    }
    if path:
        parser = ConfigParser()
        text = '[DEFAULT]\n'
        with open(path) as f:
            text += f.read()
        parser.read_string(text)
        for key in ['transport', 'pib', 'tpm']:
            try:
                ret[key] = parser['DEFAULT'][key]
            except KeyError:
                pass
    for key in ['pib', 'tpm']:
        ret[key] = resolve_loaction(ret[key])
    return ret
