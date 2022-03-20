============
Installation
============

Install the latest release with pip::

    $ pip install python-ndn

Install the latest development version::

    $ pip install -U git+https://github.com/named-data/python-ndn.git

Instructions for developer
--------------------------

For development, pipenv is recommended::

    $ pipenv install --dev

To setup a traditional python3 virtual environment with editable installation:

.. code-block:: bash

    python3 -m venv venv
    . venv/bin/activate
    pip3 install -e ".[dev]"

Run all tests:

.. code-block:: bash

    pipenv run test

Run static analysis:

.. code-block:: bash

    pipenv run make lint

Please use python 3.9+ to generate the documentation.

.. code-block:: bash

    pip3 install Sphinx sphinx-autodoc-typehints readthedocs-sphinx-ext \
        sphinx-rtd-theme pycryptodomex pygtrie

    cd docs && make html
    open _build/html/index.html

VSCode users can also use the development container obtained from the `.devcontainer` folder.
