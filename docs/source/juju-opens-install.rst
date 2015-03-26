Juju Install
============

If you're in a position to use Ubuntu's `Juju Charms`_ deployment tool, you can
quickly get a Calico-based OpenStack deployment up and running. All you need
to do is download `this bundle file`_, and then deploy it to your Juju
environment using `any of the standard methods`_. This will get you a simple
OpenStack deployment with two compute nodes, which you can then easily scale
out by adding more instances of the ``nova-compute`` charm.

For more detailed information, please see `this blog post`_ on the Calico blog.

.. _Juju Charms: https://jujucharms.com/
.. _this bundle file: https://raw.githubusercontent.com/Metaswitch/calico/master/docs/source/_static/juju/bundle.yaml
.. _any of the standard methods: https://jujucharms.com/docs/1.20/charms-bundles
.. _this blog post: http://www.projectcalico.org/exploring-juju/
