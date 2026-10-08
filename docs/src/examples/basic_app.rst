Basic Applications
==================

Connect to NFD
--------------

.. code-block:: python3

    from ndn.app import NDNApp

    app = NDNApp()

    async def main():
        # Application startup work goes here.
        app.shutdown()

    app.run_forever(after_start=main())

Consumer
--------

A consumer calls :meth:`NDNApp.express` with a validator. The returned context
contains ``meta_info``, ``sig_ptrs``, and ``raw_packet``.

.. code-block:: python3

    from ndn.app import NDNApp, pass_all
    from ndn.encoding import Name
    from ndn.types import InterestNack, InterestTimeout, ValidationFailure

    app = NDNApp()

    async def main():
        try:
            data_name, content, context = await app.express(
                '/example/testApp/randomData',
                validator=pass_all,
                must_be_fresh=True,
                lifetime=6000,
            )
            print(Name.to_str(data_name))
            print(context['meta_info'])
            print(bytes(content) if content else None)
        except InterestNack as exc:
            print(f'Nacked with reason={exc.reason}')
        except InterestTimeout:
            print('Timeout')
        except ValidationFailure:
            print('Data failed to validate')
        finally:
            app.shutdown()

Producer
--------

Interest handlers are synchronous callbacks. Use the supplied ``reply``
function to preserve the incoming PIT token.

.. code-block:: python3

    from ndn.app import NDNApp
    from ndn.security import DigestSha256Signer

    app = NDNApp()

    @app.route('/example/testApp')
    def on_interest(name, app_param, reply, context):
        packet = app.make_data(
            name,
            content=b'content',
            signer=DigestSha256Signer(),
            freshness_period=10000,
        )
        reply(packet)
