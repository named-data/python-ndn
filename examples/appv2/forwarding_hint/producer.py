import typing
import logging
from ndn import appv2
from ndn import encoding as enc


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = appv2.NDNApp()
keychain = app.default_keychain()


@app.route('/repo/command')
def on_cmd(name: enc.FormalName, _app_param: typing.Optional[enc.BinaryStr],
           reply: appv2.ReplyFunc, context: appv2.PktContext):
    print(f'>> I: {enc.Name.to_str(name)}, {context["int_param"]}')
    content = "Hello, world!".encode()
    reply(app.make_data(name, content=content, signer=keychain.get_signer({}),
                        freshness_period=10000))
    print(f'<< D: {enc.Name.to_str(name)}')
    print(enc.MetaInfo(freshness_period=10000))
    print(f'Content: (size: {len(content)})')
    print('')


# The following function catches all Interests that are not handled.
# So we can dispatch by forwarding hints.
@app.route('/')
def on_fwd_hint(name: enc.FormalName, app_param: typing.Optional[enc.BinaryStr],
                reply: appv2.ReplyFunc, context: appv2.PktContext):
    fwd_hints = context["int_param"].forwarding_hint
    if fwd_hints:
        fh_name = fwd_hints[0]
        if enc.Name.is_prefix('/repo', fh_name):
            print(f'>> Received forwarding hinted Interest: {enc.Name.to_str(fh_name)}')
            on_cmd(name, app_param, reply, context)
            return
    print(f'>> Received wrong Interest')


if __name__ == '__main__':
    app.run_forever()
