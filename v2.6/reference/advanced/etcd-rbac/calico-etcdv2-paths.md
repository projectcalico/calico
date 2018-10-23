---
title: Calico key and path prefixes in etcd v2
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/advanced/etcd-rbac/calico-etcdv3-paths'
---

The Paths listed here are the key or path prefixes that a particular calico
component needs access to in etcd to function successfully.

> **Note**: The paths listed here may change in the future and at that point anything
> referencing them (like etcd roles) would need to be updated appropriately.
{: .alert .alert-info}


## calico/node

| Path                       | Access |
|----------------------------|--------|
| /calico/\*                 |   R    |
| /calico                    |   RW   |
| /calico/v1\*               |   RW   |
| /calico/felix/v1\*         |   RW   |
| /calico/ipam/v2\*          |   RW   |
| /calico/bgp/v1\*           |   RW   |

## felix as a stand alone process

| Path                       | Access |
|----------------------------|--------|
| /calico/v1\*               |   R    |
| /calico/felix/v1\*         |   RW   |

## CNI-plugin

| Path                       | Access |
|----------------------------|--------|
| /calico/v1/host\*          |   RW   |
| /calico/v1/policy\*        |   RW   |
| /calico/v1/ipam\*          |   R    |
| /calico/ipam/v2\*          |   RW   |

## calico/kube-controllers

| Path                       | Access |
|----------------------------|--------|
| /calico/v1/host\*          |   RW   |
| /calico/v1/policy\*        |   RW   |

## OpenStack Calico driver for Neutron

| Path                       | Access |
|----------------------------|--------|
| /calico/v1/host\*          |   RW   |
| /calico/v1/policy\*        |   RW   |
| /calico/v1/ipam\*          |   R    |
| /calico/ipam/v2\*          |   RW   |
| /calico/dhcp/v1/subnet\*   |   RW   |
| /calico/v1/config\*        |   RW   |
| /calico/v1/Ready           |   RW   |

## OpenStack Calico DHCP agent

| Path                       | Access |
|----------------------------|--------|
| /calico/v1/host\*          |   R    |
| /calico/dhcp/v1/subnet\*   |   R    |


## calicoctl (read only access)

| Path                       | Access |
|----------------------------|--------|
| /calico/v1\*               |   R    |
| /calico/v1/ipam\*          |   R    |
| /calico/ipam/v2\*          |   R    |
| /calico/bgp/v1\*           |   R    |

## calicoctl (policy editor access)

| Path                       | Access |
|----------------------------|--------|
| /calico/v1\*               |   R    |
| /calico/v1/policy\*        |   RW   |
| /calico/v1/ipam\*          |   R    |
| /calico/ipam/v2\*          |   R    |
| /calico/bgp/v1\*           |   R    |

## calicoctl (full read/write access)

| Path                       | Access |
|----------------------------|--------|
| /calico/v1\*               |   RW   |
| /calico/v1/ipam\*          |   RW   |
| /calico/ipam/v2\*          |   RW   |
| /calico/bgp/v1\*           |   RW   |
