Changelog
=========

Master -- (latest)
++++++++++++++++++
* Fix RuntimeWarning for hanging coroutine when main_loop raises an exception.
* Fix the issue when after_start throws an exception, the application gets stuck.
* Set raw_packet of express_interest and on_interest to be the whole packet with TL fields.

0.2b2 (2020-02-18)
++++++++++++++++++

* Switch to Apache License 2.0.
* Add NDNApp.get_original_packet_value.
* Improve NDNApp.route and NDNApp.express_interest to give access the
  original packet and signature pointers of packets.
* Fix typos in the documentation.
* Support more alternate URI format of Name Component (``seg``, ``off``, ``v``, ``t`` and ``seq``)
* Update Python version to 3.8 and add PyPy 7.2.0 in GitHub Action.
* Fix Name.to_str so its output for ``[b'\x08\x00']`` is correct.

0.2b1 (2019-11-20)
++++++++++++++++++

The initial release.
