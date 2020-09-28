1 - File Sharing
================

Assume that Alice has several devices and wants to share some files among them.
To simplify the case, we assume that all devices have Alice's key, which can be used as the trust anchor.
A file may be large, so segmentation is needed.

Design
~~~~~~

First, let's start with the namespace design.
There are two kinds of object in the system, one is the key, the other is the file.

For the file, an option is `RDR protocol <http://www.python.org/>`_.
RDR protocol handles the version discovery and segmentation.
There is no need to know the implementation details,
since NTScheme allows we use an existing protocols as a black box.
In short, RDR has:

- A metadata packet that contains a version number of the content.
- A series of data packets containing segmented data content.

For the key, we can use a single Data packet to contain the certificate.

.. note::

    This example is only used for demo, which is different from the real-world scenario.

    - RDR is not necessary in this scenario, since there is only one version for each file.
    - In real world, Alice may want to have a trust anchor instead of sharing a single key.

The whole namespace design is shown as follows:

.. image:: /_static/schema-example1-schema.svg
    :align: center
    :width: 40%

In the figure, ``/file/<FileName>`` is the file object
and ``/<IDName>/KEY/<KeyID>/self/<CertID>`` represents the certificate.
Here, ``<variable>`` is a pattern variable that matches exactly one name cpmponent.
The real names may be ``/file/foo.txt`` and ``/Alice/KEY/%29/self/%F6``.
Also, note that ``/file/<FileName>`` is an object composed of multiple data packets,
which are managed by :any:`RDRNode` and not exposed to the programmer.

Then, let's move to the policies part.
We want to ensure the following requirements:

- All data packets are stored in memory, so if another node requests this file,
  the current node can serve it. This applies to both the producer -- which loads
  the file from the disk and create packets, and the consumer -- which receives
  the file from another node.
- Data packets of the file must be signed by Alice's key.
  The certificate can be preloaded into memory when the program starts.

Let's attach these two policies onto the namespace schema tree we have:

.. image:: /_static/schema-example1-policy.svg
    :align: center
    :width: 50%

The :any:`MemoryCachePolicy` indicates all data packets are stored in memory.
And :any:`SignedBy` requires data packets with prefix ``/file/<FileName>``
to be signed by key ``/<IDName>/KEY/<KeyID>``.
We can add restrictions, such as ``IDName == 'Alice'``, to limit the identity.

Coding
~~~~~~

With NTSchema, we can translate our design into code directly:

.. code-block:: python3

    # Make schema tree
    root = Node()
    root['/<IDName>/KEY/<KeyID>/self/<CertID>'] = Node()
    root['/file/<FileName>'] = RDRNode()

    # Set policies
    id_name = Name.Component.get_value(app.keychain.default_identity().name[0])
    cache = MemoryCache()
    root.set_policy(policy.Cache, MemoryCachePolicy(cache))
    root['/file/<FileName>'].set_policy(
        policy.DataValidator,
        SignedBy(root['/<IDName>/KEY/<KeyID>'],
                 subject_to=lambda _, vars: vars['IDName'] == id_name))

The full source code can be found in
`examples/rdrnode.py <https://github.com/named-data/python-ndn/blob/master/examples/rdrnode.py>`_.
