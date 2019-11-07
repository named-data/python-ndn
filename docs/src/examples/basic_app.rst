Basic Applications
==================

Connect to NFD
~~~~~~~~~~~~~~

NDNApp connects to an NFD node and provides interface to express and process Interests.
The following code initializes an NDNApp instance with default configuration.

.. code-block::

    from ndn.app import NDNApp
    app = NDNApp()
    app.run_forever()

If there is a main function for the application, use the ``after_start`` argument.

.. code-block::

    from ndn.app import NDNApp
    app = NDNApp()

    async def main():
        # Do something
        app.shutdown()  # Close the connection and shutdown

    app.run_forever(after_start=main())

Consumer
~~~~~~~~

A consumer can use ``express_interest`` to express an Interest.
If a Data is received and validated, it returns the Name, MetaInfo and Content of Data.
Otherwise, an exception is thrown.

.. code-block::

    from ndn.encoding import Name

    async def main():
        try:
            data_name, meta_info, content = await app.express_interest(
                # Interest Name
                '/example/testApp/randomData',
                must_be_fresh=True,
                can_be_prefix=False,
                # Interest lifetime in ms
                lifetime=6000)
            # Print out Data Name, MetaInfo and its conetnt.
            print(f'Received Data Name: {Name.to_str(data_name)}')
            print(meta_info)
            print(bytes(content) if content else None)
        except InterestNack as e:
            # A NACK is received
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            # Interest times out
            print(f'Timeout')
        except InterestCanceled:
            # Connection to NFD is broken
            print(f'Canceled')
        except ValidationFailure:
            # Validation failure
            print(f'Data failed to validate')
        finally:
            app.shutdown()

Producer
~~~~~~~~

A producer can call ``route`` to register a permanent route.
Route registration can be done before application is started.
NDNApp will automatically announce that route to the NFD node.

.. code-block::

    @app.route('/example/testApp')
    def on_interest(name, interest_param, application_param):
        app.put_data(name, content=b'content', freshness_period=10000)

