---
title: Calico key and path prefixes
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/advanced/etcd-rbac/calico-etcdv3-paths'
---

The paths listed here are the key or path prefixes that a particular {{site.prodname}}
component needs access to in etcd to function successfully.

> **Note**: The path prefixes listed here may change in the future and at that point anything
> referencing them (like etcd roles) would need to be updated appropriately.
{: .alert .alert-info}


## {{site.nodecontainer}}

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/felix/v1/\*                       |   RW   |
| /calico/ipam/v2/\*                        |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   RW   |

## Felix as a stand alone process

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/felix/v1/\*                       |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   R    |

## CNI-plugin

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/ipam/v2/\*                        |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   RW   |

## calico/kube-controllers

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/ipam/v2/\*                        |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   RW   |

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
| /calico/resources/v3/projectcalico.org/profiles/\*              |   RW   |

## calicoctl (full read/write access)

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/ipam/v2/\*                        |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   RW   |
