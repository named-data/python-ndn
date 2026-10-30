Light VerSec Application Example
================================

Create a fresh example keychain before running the applications:

.. code-block:: console

    python setup.py

Then run ``producer.py`` and ``consumer.py`` in separate terminals connected
to the same NFD. The setup command creates ``pib.db`` and ``privKeys`` in this
directory. Use ``python setup.py --force`` to replace them before their
one-year certificate validity period expires.

``ls-certificates.sh`` prints the generated certificate hierarchy.
