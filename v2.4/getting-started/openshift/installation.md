---
title: Installing Calico on OpenShift
canonical_url: 'https://docs.projectcalico.org/v3.7/getting-started/openshift/installation'
---

Installation of Calico in OpenShift is integrated in openshift-ansible v3.6.
The information below explains the variables which must be set during
during the standard [Advanced Installation](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables).

## Shared etcd

To enable an installation of Calico that shares the etcd
instance used by the apiserver, set the following `OSEv3:vars` in your
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

## Bring-your-own etcd

Calico's OpenShift-ansible integration supports connection to a custom etcd which
a user has already set up.

**Requirements:**

  - The etcd instance must have SSL authentication enabled.
  - Certs must be present at the specified filepath on all nodes.
  - All cert files must be in the same directory specified by `calico_etcd_cert_dir`.

**Inventory Parameters:**

| Key | Value     |
| :------------- | :------------- |
| `calico_etcd_endpoints` | Address of etcd, e.g. `https://calico-etcd:2379` |
| `calico_etcd_ca_cert_file` | Absolute filepath of the etcd CA file. |
| `calico_etcd_cert_file` | Absolute filepath of the etcd client cert. |
| `calico_etcd_key_file` | Absolute filepath of the etcd key file. |
| `calico_etcd_cert_dir` | Absolute path to the directory containing the etcd certs. |

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
calico_etcd_endpoints=http://calico-etcd:2379
calico_etcd_ca_cert_file=/etc/calico/etcd-ca.crt
calico_etcd_cert_file=/etc/calico/etcd-client.crt
calico_etcd_key_file=/etc/calico/etcd-client.key
calico_etcd_cert_dir=/etc/calico/

[masters]
master1

[nodes]
node1

[etcd]
etcd1
```
