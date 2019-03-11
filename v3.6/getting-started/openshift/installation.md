---
title: Installation
redirect_from: latest/getting-started/openshift/installation
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/openshift/installation'
---

Installation of {{site.prodname}} in OpenShift is integrated in openshift-ansible.
The information below explains the variables which must be set during
the standard [Advanced Installation](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables).

## Before you begin

Ensure that your cluster meets the {{site.prodname}} [system requirements](requirements).

## Installation

To install {{site.prodname}} in OpenShift, set the following `OSEv3:vars` in your
inventory file:

  - `os_sdn_network_plugin_name=cni`
  - `openshift_use_calico=true`
  - `openshift_use_openshift_sdn=false`

Also ensure that you have an explicitly defined host in the `[etcd]` group.

**Sample Inventory File:**

```
[OSEv3:children]
masters
nodes
etcd

[OSEv3:vars]
os_sdn_network_plugin_name=cni
openshift_use_calico=true
openshift_use_openshift_sdn=false

[masters]
master1

[nodes]
node1

[etcd]
etcd1
```

You are now ready to execute the ansible provision which will install {{site.prodname}}. Note that by default,
{{site.prodname}} will connect to the same etcd that OpenShift uses, and in order to do so, will distribute etcd's
certs to each node. If you would prefer Calico not connect to the same etcd as OpenShift, you may modify the install
such that Calico connects to an etcd you have already set up by following the [dedicated etcd install guide](dedicated-etcd).
