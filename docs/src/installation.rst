============
Installation
============

Install the latest release with pip::

    $ pip install python-ndn

Install the latest development version::

    $ pip install -U git+https://github.com/named-data/python-ndn.git

Instructions for developer
--------------------------

For development, `poetry <https://python-poetry.org/>`_ is recommended. You need poetry-dynamic-versioning plugin::

    $ poetry self add "poetry-dynamic-versioning[plugin]"

And to install the development environment::

    $ poetry install --all-extras

To setup a traditional python3 virtual environment with editable installation:

.. code-block:: bash

    python3 -m venv venv
    . venv/bin/activate
    pip3 install -e ".[dev,docs]"

Run all tests:

.. code-block:: bash

    poetry run make test

Run static analysis:

.. code-block:: bash

    poetry run make lint

Generate the documentation:

.. code-block:: bash

    poetry run make -C docs html
    open docs/_build/html/index.html

VSCode users can also use the development container obtained from the `.devcontainer` folder.
