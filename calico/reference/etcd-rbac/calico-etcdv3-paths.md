---
title: Calico key and path prefixes
description: Prefixes to configure Calico components to access the etcd datastore. 
canonical_url: '/reference/etcd-rbac/calico-etcdv3-paths'
---

{% tabs %}
  <label:Operator,active:true>
<%

This document does not apply to operator installations of Calico.

%>

  <label:Manifest>
<%


The paths listed here are the key or path prefixes that a particular {{site.prodname}}
component needs access to in etcd to function successfully.

> **Note**: The path prefixes listed here may change in the future and at that point anything
> referencing them (like etcd roles) would need to be updated appropriately.
{: .alert .alert-info}


## {{site.nodecontainer}}

| Path                                                          | Access |
|---------------------------------------------------------------|--------|
| /calico/felix/v1/\*                                           |   RW   |
| /calico/felix/v2/\*                                           |   RW   |
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
| /calico/felix/v2/\*                       |   RW   |
| /calico/resources/v3/projectcalico.org/\* |   R    |

## CNI-plugin

| Path                                                          | Access |
|---------------------------------------------------------------|--------|
| /calico/ipam/v2/\*                                            |   RW   |
| /calico/resources/v3/projectcalico.org/workloadendpoints/\*   |   RW   |
| /calico/resources/v3/projectcalico.org/ippools/\*             |   R    |
| /calico/resources/v3/projectcalico.org/clusterinformations/\* |   R    |
| /calico/resources/v3/projectcalico.org/nodes/\*               |   R    |

## calico/kube-controllers

| Path                                                                    | Access |
|-------------------------------------------------------------------------|--------|
| /calico/ipam/v2/\*                                                      |   RW   |
| /calico/resources/v3/projectcalico.org/profiles/\*                      |   RW   |
| /calico/resources/v3/projectcalico.org/networkpolicies/\*               |   RW   |
| /calico/resources/v3/projectcalico.org/nodes/\*                         |   RW   |
| /calico/resources/v3/projectcalico.org/clusterinformations/\*           |   RW   |
| /calico/resources/v3/projectcalico.org/hostendpoints/\*                 |   RW   |
| /calico/resources/v3/projectcalico.org/kubecontrollersconfigurations/\* |   RW   |
| /calico/resources/v3/projectcalico.org/\*                               |   R    |
 
> **Note**: By default, `calico/kube-controllers` performs periodic
> compaction of the etcd data store. If you limit it to just these
> paths it will be unauthorized to perform this compaction, as that
> operation requires root privileges on the etcd cluster. You should
> [configure auto-compaction](https://etcd.io/docs/v3.3.12/op-guide/maintenance/){:target="_blank"}
> on your etcd cluster and
> [disable `calico/kube-controllers` periodic compaction](/reference/kube-controllers/configuration).
{: .alert .alert-info}


## OpenStack Calico driver for Neutron

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/resources/v3/projectcalico.org/\* |   RW   |
| /calico/dhcp/v1/\*                        |   RW   |
| /calico/dhcp/v2/\*                        |   RW   |
| /calico/compaction/v1/\*                  |   RW   |
| /calico/openstack/v1/\*                   |   RW   |
| /calico/openstack/v2/\*                   |   RW   |
| /calico/felix/v1/\*                       |   R    |
| /calico/felix/v2/\*                       |   R    |

## OpenStack Calico DHCP agent

| Path                                      | Access |
|-------------------------------------------|--------|
| /calico/resources/v3/projectcalico.org/\* |   R    |
| /calico/dhcp/v1/\*                        |   R    |
| /calico/dhcp/v2/\*                        |   R    |

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

%>

{% endtabs %}
