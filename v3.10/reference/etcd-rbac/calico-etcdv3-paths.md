---
title: Calico key and path prefixes
canonical_url: 'https://docs.projectcalico.org/v3.9/reference/etcd-rbac/calico-etcdv3-paths'
---

The paths listed here are the key or path prefixes that a particular {{site.prodname}}
component needs access to in etcd to function successfully.

> **Note**: The path prefixes listed here may change in the future and at that point anything
> referencing them (like etcd roles) would need to be updated appropriately.
{: .alert .alert-info}


## {{site.nodecontainer}}

| Path                                                          | Access |
|---------------------------------------------------------------|--------|
| /calico/felix/v1/\*                                           |   RW   |
| /calico/ipam/v2/\*                                            |   RW   |
| /calico/resources/v3/projectcalico.org/felixconfigurations/\* |   RW   |
| /calico/resources/v3/projectcalico.org/nodes/\*               |   RW   |
| /calico/resources/v3/projectcalico.org/workloadendpoints/\*   |   RW   |
| /calico/resources/v3/projectcalico.org/clusterinformations/\* |   RW   |
| /calico/resources/v3/projectcalico.org/ippools/\*             |   RW   |
| /calico/resources/v3/projectcalico.org/\*                     |   R    |

## Felix as a stand alone process

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/felix/v1/\*                       |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   R    |

## CNI-plugin

| Path                                                          | Access |
|---------------------------------------------------------------|--------|
| /calico/ipam/v2/\*                                            |   RW   |
| /calico/resources/v3/projectcalico.org/workloadendpoints/\*   |   RW   |
| /calico/resources/v3/projectcalico.org/ippools/\*             |   R    |
| /calico/resources/v3/projectcalico.org/clusterinformations/\* |   R    |

## calico/kube-controllers

| Path                                                          | Access |
|---------------------------------------------------------------|--------|
| /calico/ipam/v2/\*                                            |   RW   |
| /calico/resources/v3/projectcalico.org/profiles/\*            |   RW   |
| /calico/resources/v3/projectcalico.org/networkpolicies/\*     |   RW   |
| /calico/resources/v3/projectcalico.org/nodes/\*               |   RW   |
| /calico/resources/v3/projectcalico.org/clusterinformations/\* |   RW   |
| /calico/resources/v3/projectcalico.org/\*                     |   R    |

> **Note**: By default, `calico/kube-controllers` performs periodic 
> compaction of the etcd data store. If you limit it to just these
> paths it will be unauthorized to perform this compaction, as that
> operation requires root privileges on the etcd cluster. You should
> [configure auto-compaction](https://etcd.io/docs/v3.3.12/op-guide/maintenance/)
> on your etcd cluster and 
> [disable `calico/kube-controllers` periodic compaction](/{{page.version}}/reference/kube-controllers/configuration).
{: .alert .alert-info}


## OpenStack Calico driver for Neutron

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/ipam/v2/\*                        |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   RW   |

## OpenStack Calico DHCP agent

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/resources/v3/projectcalico.org/\* |   R    |
| /calico/dhcp/v1/subnet/\*                 |   R    |

## calicoctl (read only access)

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/ipam/v2/\*                        |   R    |
| /calico/resources/v3/projectcalico.org/\* |   R    |

## calicoctl (policy editor access)

| Path                                                            | Access |
|-----------------------------------------------------------------|--------|
| /calico/ipam/v2/\*                                              |   R    |
| /calico/resources/v3/projectcalico.org/\*                       |   R    |
| /calico/resources/v3/projectcalico.org/globalnetworkpolicies/\* |   RW   |
| /calico/resources/v3/projectcalico.org/globalnetworksets/\*     |   RW   |
| /calico/resources/v3/projectcalico.org/networkpolicies/\*       |   RW   |
| /calico/resources/v3/projectcalico.org/networksets/\*           |   RW   |
| /calico/resources/v3/projectcalico.org/profiles/\*              |   RW   |

## calicoctl (full read/write access)

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/ipam/v2/\*                        |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   RW   |
