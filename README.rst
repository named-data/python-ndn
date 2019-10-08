ndn-python
==========

A Named Data Networking client library with AsyncIO support in Python 3.

Instructions for developer
--------------------------

To setup python3.6 virtual environment:

.. code-block:: bash

  python3.6 -m venv venv
  . venv/bin/activate
  pip3 install -e .
  pip3 install pytest pytest-cov

To do unit tests:

.. code-block:: bash

  make test

TODO List
---------

- Documentation
- Correct usage of license
- Correct the order: name, content, metainfo
- Figure out exceptions during encode & decode
- Test InterestCancelled
- Unit tests
- Integration tests
- Security Part
- prepareData
- UnregisterRoute
- SegmentFetcher
- Sync and other fantastic things
