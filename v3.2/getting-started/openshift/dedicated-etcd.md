---
title: Installing Calico on OpenShift with a dedicated etcd cluster
redirect_from: latest/getting-started/openshift/dedicated-etcd
---

{{site.prodname}}'s OpenShift-ansible integration supports connection to a custom etcd which
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

You are now ready to execute the ansible provision which will install {{site.prodname}}.
