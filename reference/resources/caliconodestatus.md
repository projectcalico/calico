---
title: Calico node status
description: API for this Calico resource.
canonical_url: '/reference/resources/caliconodestatus'
---

An Calico node status resource (`CalicoNodeStatus`) represents a collection of status information for a node that {{site.prodname}} should 
reports back to the user.

As of today, BGP status information including status of BGP agents, BGP sessions and routes exposed to BGP agents are collected. 
Calico node status resource is only valid when {{site.prodname}} BGP networking is in use.

### Sample YAML

Yaml that user created to collect information for node "my-kadm-node-0" with an update interval of 10 seconds.
```yaml
apiVersion: projectcalico.org/v3
kind: CalicoNodeStatus
metadata:
  name: my-caliconodestatus-1
spec:
  classes:
    - Agent
    - BGP
    - Routes
  node: my-kadm-node-0
  updatePeriodSeconds: 10
```

Yaml that user read back from the same resource after all the status is populated by {{site.prodname}}.
```yaml
- apiVersion: projectcalico.org/v3
  kind: CalicoNodeStatus
  metadata:
    annotations:
      kubectl.kubernetes.io/last-applied-configuration: |
        {"apiVersion":"crd.projectcalico.org/v1","kind":"CalicoNodeStatus","metadata":{"annotations":{},"name":"my-caliconodestatus-1"},"spec":{"classes":["Agent","BGP","Routes"],"node":"my-kadm-node-0","updatePeriodSeconds":10}}
      projectcalico.org/metadata: '{"uid":"6e3b676b-546a-41db-aeda-ad44f25ff73f","generation":2,"creationTimestamp":"2021-10-18T10:30:43Z","managedFields":[{"manager":"kubectl-client-side-apply","operation":"Update","apiVersion":"projectcalico.org/v3","time":"2021-10-18T10:30:43Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}}},"f:spec":{".":{},"f:node":{},"f:updatePeriodSeconds":{}}}},{"manager":"kubectl-edit","operation":"Update","apiVersion":"crd.projectcalico.org/v1","time":"2021-10-18T12:59:25Z","fieldsType":"FieldsV1","fieldsV1":{"f:spec":{"f:classes":{}}}}]}'
    creationTimestamp: "2021-10-18T10:30:43Z"
    generation: 139
    name: my-caliconodestatus-1
    resourceVersion: "203255"
    uid: 6e3b676b-546a-41db-aeda-ad44f25ff73f
  spec:
    classes:
    - Agent
    - BGP
    - Routes
    node: my-kadm-node-0
    updatePeriodSeconds: 10
  status:
    agent:
      birdV4:
        lastBootTime: "2021-10-18 09:23:19"
        lastReconfigurationTime: "2021-10-18 09:23:19"
        routerID: 10.128.0.240
        state: Ready
        version: v0.3.3+birdv1.6.8
      birdV6:
        lastBootTime: "2021-10-18 09:23:19"
        lastReconfigurationTime: "2021-10-18 09:23:19"
        routerID: 10.128.0.240
        state: Ready
        version: v0.3.3+birdv1.6.8
    bgp:
      numberEstablishedV4: 2
      numberEstablishedV6: 0
      numberNotEstablishedV4: 1
      numberNotEstablishedV6: 0
      peersV4:
      - peerIP: 10.128.0.242
        since: "09:23:22"
        state: Established
        type: NodeMesh
      - peerIP: 10.128.0.200
        since: "09:23:21"
        state: Established
        type: NodeMesh
      - peerIP: 10.128.0.241
        since: "09:23:22"
        state: OpenSent
        type: NodeMesh
    lastUpdated: "2021-10-18T13:22:03Z"
    routes:
      routesV4:
      - destination: 0.0.0.0/0
        gateway: 172.18.0.1
        interface: eth0
        learnedFrom:
          sourceType: Kernel
        type: FIB
      - destination: 192.168.82.0/26
        gateway: 10.128.0.200
        interface: eth0
        learnedFrom:
          peerIP: 10.128.0.200
          sourceType: NodeMesh
        type: FIB
      - destination: 192.168.36.0/26
        gateway: 10.128.0.242
        interface: eth0
        learnedFrom:
          peerIP: 10.128.0.242
          sourceType: NodeMesh
        type: FIB
      - destination: 10.128.0.5/16
        gateway: N/A
        interface: eth0
        learnedFrom:
          sourceType: Direct
        type: FIB


```

### Calico node status definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     |  The name of this CalicoNodeStatus resource. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field          | Description                 | Accepted Values   | Schema | 
|----------------|-----------------------------|-------------------|--------|
| classes  | List of classes that declare the types of information to monitor for this node and allows for selective status reporting about certain subsets of information. Required. | List of [Classes](#classes) | list |
| node  | The node name identifies the Calico node instance for node status. Required. | valid Kubernetes node name | string |
| updatePeriodSeconds  | Period in seconds at which CalicoNodeStatus should be updated. Set to 0 to disable CalicoNodeStatus refresh. Maximum update period is one day. Required. | 0 - 86400 | int |

#### Status

| Field          | Description                 | Values   |
|----------------|-----------------------------|----------|
| lastUpdated  | Timestamp representing the server time when CalicoNodeStatus object last updated. It is represented in RFC3339 form and is in UTC. |
| agent  | List of [BGP daemon status](#bgpagentdaemonstatus) on the node. | 'birdV4' holds status of IPv4 bird daemon, 'birdV6' holds status of IPv6 bird daemon |
| bpg  | List of [BGP status](#bgptatus) on the node. | 'peersV4' holds status of IPv4 BGP peers, 'peersV6' holds status of IPv6 BGP peers |
| routes  | List of [Route status](#routestatus) learned by BGP daemon on the node. | 'routesV4' holds status of IPv4 routes , 'routesV6' holds status of IPv6 routes |

#### Classes

| Accepted Values    | Description                            | Schema |
|--------------------|----------------------------------------|--------|
| Agent              | Status of BGP daemon agent | string |
| BGP                | Status of BGP sessions | string |
| Routes             | Status of routes exposed to BGP daemon | string |

#### BgpDaemonStatus

| Field   | Description                            | Schema |
|--------------------|----------------------------------------|--------|
| Agent              | Status of BGP daemon agent | string |
| BGP                | Status of BGP sessions | string |
| Routes             | Status of routes exposed to BGP daemon | string |

#### Notes

The implementation of `IPReservation`s is designed to handle reservation of a small number of IP addresses/CIDRs from
(generally much larger) IP pools.  If a significant portion of an IP pool is reserved (say more than 10%) then 
{{site.prodname}} may become significantly slower when searching for free IPAM blocks.

Since `IPReservations` must be consulted for every IPAM assignment request, it's best to have one or two 
`IPReservation` resources with multiple addresses per `IPReservation` resource (rather than having many IPReservation
resources), each with one address inside.

If an `IPReservation` is created after an IP from its range is already in use then the IP is not automatically 
released back to the pool.  The reservation check is only done at auto allocation time.

{{site.prodname}} supports Kubernetes [annotations that force the use of specific IP addresses](../cni-plugin/configuration#requesting-a-specific-ip-address). These annotations override any `IPReservation`s that 
are in place.

When Windows nodes claim blocks of IPs they automatically assign the first three IPs
in each block and the final IP for internal purposes.  These assignments cannot be blocked by an `IPReservation`.
However, if a whole IPAM block is reserved with an `IPReservation`, Windows nodes will not claim such a block.
