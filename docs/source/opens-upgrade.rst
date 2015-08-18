Upgrade Procedure (OpenStack)
=============================

This document details the procedure for upgrading a Calico-based OpenStack
system. It contains the full steps for upgrading all components and the order
in which that upgrade should be performed. Most releases do not concurrently
upgrade all of these components: if a release does not upgrade a given
component, you may skip those steps.

.. warning:: While the upgrade procedure is very safe, you will be unable to
             issue API requests to your OpenStack system during the procedure.
             Please plan your upgrade window accordingly, and see the
             :ref:`service_impact` section for more details.


.. _service_impact:

Service Impact
--------------

During the upgrade, **all VMs will continue to function normally**: there
should be no impact on the data plane. However, control plane traffic may fail
at different points throughout the upgrade.

Generally, users should be prevented from creating or updating virtual machines
during this procedure, as these actions will fail. VM deletion *may* succeed,
but will likely be delayed until the end of the upgrade.

For this reason, we highly recommend planning a maintenance window for the
upgrade. During this window, you should disable all user API access to your
OpenStack deployment.

Upgrade Procedure
-----------------

Upgrade is performed in the following stages, which must be performed in the
order shown.

1: Upgrade etcd
~~~~~~~~~~~~~~~

This step should be run on every machine in your deployment that runs any
Calico code, and also on the machine running the etcd cluster.

Ubuntu 14.04
^^^^^^^^^^^^

Use apt-get to obtain the more recent version::

    apt-get update
    apt-get install etcd

Red Hat 7
^^^^^^^^^

Stop the etcd process::

    systemctl stop etcd

Then, download the tested binary (currently 2.0.11) and install it::

    curl -L  https://github.com/coreos/etcd/releases/download/v2.0.11/etcd-v2.0.11-linux-amd64.tar.gz -o etcd-v2.0.11-linux-amd64.tar.gz
    tar xvf etcd-v2.0.11-linux-amd64.tar.gz
    cd etcd-v2.0.11-linux-amd64
    mv etcd* /usr/local/bin/

Now, restart etcd::

    systemctl start etcd

2: Upgrade compute software
~~~~~~~~~~~~~~~~~~~~~~~~~~~

On each machine running the Calico compute software (the component called
Felix), run the following upgrade steps.

Ubuntu 14.04
^^^^^^^^^^^^

First, upgrade packaged components::

    apt-get update
    apt-get install dnsmasq-base nova-api-metadata neutron-dhcp-agent python-etcd calico-compute nova-compute

Then, restart Felix to ensure that it picks up any changes::

    service calico-felix restart

Finally, if dnsmasq was upgraded, kill it and restart the DHCP
agent.  This is required due to an upstream problem: oslo-rootwrap can't kill a
process when the binary has been updated since it started running::

    pkill dnsmasq
    service neutron-dhcp-agent restart

Red Hat 7
^^^^^^^^^

First, upgrade python-etcd::

    curl -L https://github.com/projectcalico/python-etcd/archive/master.tar.gz -o python-etcd.tar.gz
    tar xvf python-etcd.tar.gz
    cd python-etcd-master
    python setup.py install

Then, update the relevant components::

    yum update dnsmasq openstack-nova-api openstack-neutron calico-compute openstack-nova-compute

Finally, if dnsmasq was upgraded, kill it and restart the DHCP agent.  This is
required due to an upstream problem: oslo-rootwrap can't kill a process when
the binary has been updated since it started running::

    pkill dnsmasq
    service neutron-dhcp-agent-restart

3: Upgrade control software
~~~~~~~~~~~~~~~~~~~~~~~~~~~

On each machine running the Calico control software (every machine running
neutron-server), run the following upgrade steps.

Ubuntu 14.04
^^^^^^^^^^^^

First, update packaged components::

    apt-get update
    apt-get install python-etcd etcd calico-control neutron-server

Then, restart Neutron to ensure that it picks up any changes::

    service neutron-server restart

Red Hat 7
^^^^^^^^^

First, upgrade python-etcd::

    curl -L https://github.com/projectcalico/python-etcd/archive/master.tar.gz -o python-etcd.tar.gz
    tar xvf python-etcd.tar.gz
    cd python-etcd-master
    python setup.py install

Then, update the relevant components::

    yum update calico-control openstack-neutron
