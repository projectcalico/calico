This repo contains code for integrating Project Calico's networking into
OpenStack/Neutron.

Calico is an open source solution for virtual networking in cloud data centers,
developed principally by Tigera and released under the Apache 2.0 License.

For general documentation about Calico, including how to get started with a
Calico/OpenStack installation, and how to use various OpenStack/Neutron
features with Calico, please see http://docs.projectcalico.org/master.

* Free software: Apache license
* Documentation: http://docs.projectcalico.org/master
* Source: https://github.com/projectcalico/networking-calico
* Bugs: https://github.com/projectcalico/networking-calico/issues and
  (legacy) http://bugs.launchpad.net/networking-calico

# Version skew

Calico for OpenStack is tested against one or two recent LTS OpenStack versions, as [defined by
Canonical](https://canonical-openstack.readthedocs-hosted.com/en/latest/reference/release-cycle-and-supported-versions/).
For recent Calico versions the corresponding versions of OpenStack are as follows.

| Calico version | OpenStack versions |
| -------------- | ------------------ |
| master         | Caracal            |
| v3.30          | Yoga, Caracal      |
