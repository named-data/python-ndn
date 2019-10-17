python-ndn
==========

|Test Badge|
|Code Size|
|Release Badge|
|Doc Badge|

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
- Security Part
- Sync and other fantastic things


.. |Test Badge| image:: https://github.com/zjkmxy/python-ndn/workflows/test/badge.svg
    :target: https://github.com/zjkmxy/python-ndn
    :alt: Test Status

.. |Code Size| image:: https://img.shields.io/github/languages/code-size/zjkmxy/python-ndn
    :target: https://github.com/zjkmxy/python-ndn
    :alt: Code Size

.. |Release Badge| image:: https://img.shields.io/pypi/v/python-ndn?label=release
    :target: https://pypi.org/project/python-ndn/
    :alt: Release Ver

.. |Doc Badge| image:: https://readthedocs.org/projects/python-ndn/badge/?version=latest
    :target: https://python-ndn.readthedocs.io/en/latest/?badge=latest
    :alt: Doc Status
