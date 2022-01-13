---
title: Binary install with package manager
description: Install Calico on non-cluster host using a package manager.
canonical_url: '/getting-started/bare-metal/installation/binary-mgr'
---

### Big picture
Install {{site.prodname}} on non-cluster hosts using a package manager.

### Value
Packaged binaries of {{site.prodname}} are easy to consume and upgrade. This method automatically configures the init system to keep Felix running.

### Before you begin...

1. Ensure the {{site.prodname}} datastore is up and accessible from the host
1. Ensure the host meets the minimum [system requirements](../requirements)
1. If your system is not an Ubuntu- or RedHat-derived system, you will need to choose a different install method.
1. If you want to install {{site.prodname}} with networking (so that you can communicate with cluster workloads), you should choose the [container install method](./container)
1. Install `kubectl` (for Kubernetes datastore) or [Install and configure `calicoctl`]({{site.baseurl}}/maintenance/clis/calicoctl/) for etcd3 datastore.

### How to

This guide covers installing Felix, the {{site.prodname}} daemon that handles network policy.

#### Step 1: Install binaries

{% include ppa_repo_name %}

*PPA requires*: Ubuntu 14.04 or 16.04

    sudo add-apt-repository ppa:project-calico/{{ ppa_repo_name }}
    sudo apt-get update
    sudo apt-get upgrade
    sudo apt-get install calico-felix

*RPM requires*: RedHat 7-derived distribution

    cat > /etc/yum.repos.d/calico.repo <<EOF
    [calico]
    name=Calico Repository
    baseurl=http://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/
    enabled=1
    skip_if_unavailable=0
    gpgcheck=1
    gpgkey=http://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/key
    priority=97
    EOF

    yum install calico-felix

Until you initialize the database, Felix will make a regular log that it
is in state "wait-for-ready". The default location for the log file is
`/var/log/calico/felix.log`.

#### Step 2: Configure the datastore connection

{% include content/environment-file.md target="felix" %}

Modify the included init system unit to include the `EnvironmentFile`.  For example, on systemd, add the following line to the `[Service]` section of the `calico-felix` unit.

```
EnvironmentFile=/etc/calico/calico.env
```

#### Step 3: Initialize the datastore

{% include content/felix-init-datastore.md %}
