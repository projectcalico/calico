---
title: Installing Calico on OpenShift
redirect_from: latest/getting-started/openshift/installation
---

Calico has been integrated with both OpenShift Origin and Red Hat OpenShift Container Platform, and is deployed using the standard OpenShift-ansible installation process (which includes roles to deploy and configure Calico).

Calico replaces openshift-sdn and the network policy implementation for openshift-sdn, but functions with other standard OpenShift artifacts including kube-proxy, OpenShift router (HAProxy), Registry, and DNS. 

Deployment of Calico with OpenShift is done using the standard openshift-ansible deployment process, but with the appropriate Calico variables set in the host inventory file for openshift-ansible as described below. Please ensure that all OpenShift prerequisites are met and host preparation steps are performed prior to starting the OpenShift install, as described in [OpenShift Container Platform documentation](https://access.redhat.com/documentation/en-us/openshift_container_platform/3.6/html-single/installation_and_configuration/#install-config-install-prerequisites) or [OpenShift Origin documentation](https://docs.openshift.org/latest/install_config/install/prerequisites.html).

Calico deployment roles have been integrated with openshift-ansible since v3.6.
The information below explains the variables which must be set during
during the standard [OpenShift Origin Advanced Installation](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables) or [OpenShift Container Platform Advanced Installation](https://access.redhat.com/documentation/en-us/openshift_container_platform/3.6/html-single/installation_and_configuration/#install-config-install-advanced-install).

## Etcd Backend for Calico
There are two alternative options for the Datastore backend for Calico within OpenShift deployments:

- Shared Etcd with OpenShift
This is suitable for non-production deployments of OpenShift, and involves Calico using the same Etcd server instances as are used by OpenShift (Calico uses a different part of the Etcd namespace than OpenShift). 

- Dedicated Etcd for Calico (Bring-your-own Etcd)
Alternatively, a separate set of Etcd server instances can be dedicated for Calico independent of OpenShift's Etcd instances. This is recommended for production deployments, and enables tuning of the Calico Etcd instances independently from OpenShift Etcd instances. This option requires that the Etcd server instances be deployed and configured prior to commencing the OpenShift install via openshift-ansible. Please reach out to the Calico team via slack for assistance or guidance if required.

OpenShift does not support Kubernetes Custom Resource Definitions (CRD's) so the Kubernetes Datastore Driver (KDD) backend is not enabled for Calico with OpenShift.

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


## Notes

- Upgrades from existing OpenShift deployments (running openshift-sdn, or the OpenShift build of flannel) to Calico have not been tested.

- These instructions outline deployment on standard RHEL7 or CentOS7 hosts. For deployment on other platforms, please reach out to the Calico team via the [Calico-Users slack channel](https://www.projectcalico.org/community#slack).

