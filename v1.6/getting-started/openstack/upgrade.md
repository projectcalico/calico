---
title: 'Upgrade Procedure (OpenStack)'
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/openstack/upgrade/'
---

This document details the procedure for upgrading a Calico-based
OpenStack system. It contains the full steps for upgrading all
components and the order in which that upgrade should be performed. Most
releases do not concurrently upgrade all of these components: if a
release does not upgrade a given component, you may skip those steps.

> **WARNING**
>
> While the upgrade procedure is very safe, you will be unable to
> issue API requests to your OpenStack system during the procedure.
> Please plan your upgrade window accordingly, and see the
> [Service Impact](#service-impact) section for more details.
>

## Service Impact

During the upgrade, **all VMs will continue to function normally**:
there should be no impact on the data plane. However, control plane
traffic may fail at different points throughout the upgrade.

Generally, users should be prevented from creating or updating virtual
machines during this procedure, as these actions will fail. VM deletion
*may* succeed, but will likely be delayed until the end of the upgrade.

For this reason, we highly recommend planning a maintenance window for
the upgrade. During this window, you should disable all user API access
to your OpenStack deployment.

## Upgrade Procedure

Upgrade is performed in the following stages, which must be performed in
the order shown.

### 1: Upgrade etcd

This step should be run on every machine in your deployment that runs
any Calico code, and also on the machine running the etcd cluster.

#### Ubuntu

Use apt-get to obtain the more recent version:

    apt-get update
    apt-get install etcd

#### Red Hat 7

Stop the etcd process:

    systemctl stop etcd

Then, download the tested binary (currently 2.0.11) and install it:

    curl -L  https://github.com/coreos/etcd/releases/download/v2.0.11/etcd-v2.0.11-linux-amd64.tar.gz -o etcd-v2.0.11-linux-amd64.tar.gz
    tar xvf etcd-v2.0.11-linux-amd64.tar.gz
    cd etcd-v2.0.11-linux-amd64
    mv etcd* /usr/local/bin/

Now, restart etcd:

    systemctl start etcd

2: Upgrade compute software
---------------------------

On each machine running the Calico compute software (the component
called Felix), run the following upgrade steps.

#### Uninstall pip-installed networking-calico

If present, uninstall any pip-installed networking-calico package:

    pip uninstall networking-calico

(networking-calico function is now installed as a Debian or RPM package
instead.)

#### Ubuntu

First, use `apt-get` to install the updated packages. On each compute
host upgrade the Calico packages, as follows:

    apt-get update
    apt-get install calico-compute calico-felix calico-common python-etcd \
                    networking-calico

> **WARNING**
>
> Running `apt-get upgrade` is not sufficient to upgrade Calico
> due to new dependent packages added in version 1.3. If you want to
> upgrade Calico as part of a system-wide update, you must use
> `apt-get dist-upgrade`.
>

Then, restart Felix to ensure that it picks up any changes:

    service calico-felix restart

Finally, if dnsmasq was upgraded, kill it and restart the DHCP agent.
This is required due to an upstream problem: oslo-rootwrap can't kill a
process when the binary has been updated since it started running:

    pkill dnsmasq

For OpenStack Liberty or later, install the new Calico DHCP agent and
disable the Neutron-provided one. The Calico DHCP agent is backed by
etcd, allowing it to scale to higher numbers of hosts:

    service neutron-dhcp-agent stop
    echo manual > /etc/init/neutron-dhcp-agent.override
    apt-get install calico-dhcp-agent

Check that only the Calico DHCP agent is now running:

    # status calico-dhcp-agent
    calico-dhcp-agent start/running, process <PID>
    # status neutron-dhcp-agent
    neutron-dhcp-agent stop/waiting

Or if you are using an earlier OpenStack release, restart the
Neutron-provided DHCP agent:

    service neutron-dhcp-agent restart

#### Red Hat 7

First, upgrade python-etcd:

    curl -L https://github.com/projectcalico/python-etcd/archive/master.tar.gz -o python-etcd.tar.gz
    tar xvf python-etcd.tar.gz
    cd python-etcd-master
    python setup.py install

Then, update packaged components:

    yum update

We recommend upgrading the whole distribution as shown here. In case you
prefer to upgrade particular packages only, those needed for a Calico
compute node are the following.

    calico-common
    calico-compute
    calico-dhcp-agent
    calico-felix
    dnsmasq
    networking-calico
    openstack-neutron
    openstack-nova-api
    openstack-nova-compute

Finally, if dnsmasq was upgraded, kill it and restart the DHCP agent.
This is required due to an upstream problem: oslo-rootwrap can't kill a
process when the binary has been updated since it started running:

    pkill dnsmasq

For OpenStack Liberty or later, modify `/etc/neutron/neutron.conf`. In
the `[oslo_concurrency]` section, ensure that the `lock_path` variable
is uncommented and set as follows:

    # Directory to use for lock files. For security, the specified directory should
    # only be writable by the user running the processes that need locking.
    # Defaults to environment variable OSLO_LOCK_PATH. If external locks are used,
    # a lock path must be set.
    lock_path = $state_path/lock

For OpenStack Liberty or later, install the new Calico DHCP agent and
disable the Neutron-provided one. The Calico DHCP agent is backed by
etcd, allowing it to scale to higher numbers of hosts:

    systemctl stop neutron-dhcp-agent
    systemctl disable neutron-dhcp-agent
    yum install calico-dhcp-agent

Check that (only) the Calico DHCP agent is started:

    # systemctl status calico-dhcp-agent
    ...
    Active: active (running)
    ...
    # systemctl status neutron-dhcp-agent
    ...
    Active: inactive
    ...

Or if you are using an earlier OpenStack release:

    systemctl restart neutron-dhcp-agent

3: Upgrade control software
---------------------------

On each machine running the Calico control software (every machine
running neutron-server), run the following upgrade steps.

#### Ubuntu

First, use `apt-get` to install the updated packages. On each control
host you can upgrade only the Calico packages, as follows:

    apt-get update
    apt-get install calico-control calico-common python-etcd networking-calico

> **WARNING**
>
> Running `apt-get upgrade` is not sufficient to upgrade Calico
> due to new dependent packages added in version 1.3. If you want to
> upgrade Calico as part of a system-wide update, you must use
> `apt-get dist-upgrade`.
>

Then, restart Neutron to ensure that it picks up any changes:

    service neutron-server restart

#### Red Hat 7

First, upgrade python-etcd:

    curl -L https://github.com/projectcalico/python-etcd/archive/master.tar.gz -o python-etcd.tar.gz
    tar xvf python-etcd.tar.gz
    cd python-etcd-master
    python setup.py install

Then, update packaged components:

    yum update

We recommend upgrading the whole distribution as shown here. In case you
prefer to upgrade particular packages only, those needed for a Calico
control node are the following.

    calico-common
    calico-control
    networking-calico
    openstack-neutron

Then, restart Neutron to ensure that it picks up any changes:

    systemctl restart neutron-server
