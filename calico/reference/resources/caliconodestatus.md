---
title: Calico node status
description: API for this Calico resource.
canonical_url: '/reference/resources/caliconodestatus'
---

A Calico node status resource (`CalicoNodeStatus`) represents a collection of status information for a node that {{site.prodname}} reports back to the user for use during troubleshooting.

As of today, status of BGP agents, BGP sessions and routes exposed to BGP agents are collected from Linux nodes only. **Windows nodes are not supported at this time.**
Calico node status resource is only valid when {{site.prodname}} BGP networking is in use.

#### Notes

The updating of `CalicoNodeStatus` will have a small performance impact on CPU/Memory usage of the node as well as adding load to kubernetes apiserver.

In our testing on a ten node, full mesh cluster, a `CalicoNodeStatus` resource was created for each node where the update interval was set to ten seconds. On each node, this resulted in an increase in CPU use of 5% of a vCPU and an increase of 4MB of memory.  The control plane node recorded an increase in CPU usage of 5% of a vCPU for these 10 nodes.

> **Warning**: The implementation of `CalicoNodeStatus` is designed to handle a small number of nodes (less than 10 is recommended) reporting back status in the same time. If `CalicoNodeStatus` are created for a large number of nodes, and with short update interval,
the kubernetes apiserver may become slower and less responsive.
{: .alert .alert-warning}

You should create `CalicoNodeStatus` for the node you are interested in and for debugging purpose only. `CalicoNodeStatus` resource should be deleted upon the completion of the debugging process.

### Sample YAML
To use this function, the user creates a CalicoNodeStatus object for the node, specifying the information to collect and the interval it should be collected at.  This example collects information for node "my-kadm-node-0" with an update interval of 10 seconds.

```yaml
kubectl apply -f -<<EOF
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
EOF
```
The user then reads back the same resource using the command `kubectl get caliconodestatus my-caliconodestatus-1 -o yaml`, and the information collected can be found in the `status` field.  For example:
```yaml
apiVersion: projectcalico.org/v3
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
| classes  | List of classes that declare the types of information to monitor for this node and allows for selective status reporting about certain subsets of information. Required. | List of [Classes](#classes) | list of string |
| node  | The node name identifies the Calico node instance to collect node status for. Required. | valid Kubernetes node name | string |
| updatePeriodSeconds  | Period in seconds at which CalicoNodeStatus should be updated. Set to 0 to disable CalicoNodeStatus refresh. Maximum update period is one day. Required. | 0 - 86400 | int |

#### Status

| Field          | Description                 | Values   |
|----------------|-----------------------------|----------|
| lastUpdated  | Timestamp representing the server time when the CalicoNodeStatus object last updated. It is represented in RFC3339 form and is in UTC. |
| agent  | List of [BGP daemon status](#bgpdaemonstatus) on the node. | 'birdV4' holds status of IPv4 bird daemon, 'birdV6' holds status of IPv6 bird daemon |
| bgp  | List of [BGP status](#bgpstatus) on the node. | 'peersV4' holds status of IPv4 BGP peers, 'peersV6' holds status of IPv6 BGP peers |
| routes  | List of [Route status](#routestatus) learned by BGP daemon on the node. | 'routesV4' holds status of IPv4 routes , 'routesV6' holds status of IPv6 routes |

#### Classes

| Accepted Values    | Description                            |
|--------------------|----------------------------------------|
| Agent              | Status of BGP daemon agent |
| BGP                | Status of BGP sessions |
| Routes             | Status of routes exposed to BGP daemon |

#### BGPDaemonStatus

| Field              | Description                            | Schema | Possible Values |
|--------------------|----------------------------------------|--------|-----------------|
| state              | State of BGP daemon.                   | string | Ready, NotReady |
| version            | Version of BGP daemon                  | string |                 |
| routerID           | Router ID used by BGP daemon           | string |                 |
| lastBootTime       | Last boot time of BGP daemon           | string |                 |
| lastReconfigurationTime| Last reconfiguration time of BGP daemon | string |            |

#### BGPStatus

| Field              | Description                            | Schema |
|--------------------|----------------------------------------|--------|
| numberEstablishedV4      | The total number of IPv4 established bgp sessions. | int |
| numberNotEstablishedV4   | The total number of IPv4 non-established bgp sessions. | int |
| numberEstablishedV6      | The total number of IPv6 established bgp sessions. | int |
| numberNotEstablishedV6   | The total number of IPv6 non-established bgp sessions. | int |
| peersV4  | IPv4 BGP peers status on the node. | List of [BGP peer](#bgppeer) |
| peersV6  | IPv6 BGP peers status on the node. | List of [BGP peer](#bgppeer) |

#### RouteStatus

| Field              | Description                            | Schema |
|--------------------|----------------------------------------|--------|
| routesV4  | IPv4 routes learned by BGP daemon on the node.  | List of [route](#route) |
| routesV6  | IPv6 routes learned by BGP daemon on the node.  | List of [route](#route) |

#### BGPPeer

| Field              | Description                            | Schema | Possible Values |
|--------------------|----------------------------------------|--------|-----------------|
| peerIP              | IP address of the peer whose condition we are reporting.  | `ip` | |
| type            | Type indicates whether this peer is configured via the node-to-node mesh, or via en explicit global or per-node BGPPeer object. | string |  NodeMesh, NodePeer, GlobalPeer |
| state          | BGP session state. Value of an empty string means BGP session state is unknown. | string |  Idle, Connect, Active, OpenSent, OpenConfirm, Established, Close |
| since       | Timestamp of last BGP session state change.  | `time` |      |

#### Route

| Field              | Description                            | Schema | Possible Values |
|--------------------|----------------------------------------|--------|-----------------|
| type             | Type indicates if the route is being used for forwarding or not.  | string | FIB, RIB |
| destination      | Destination IP of the route. | `ip` |  |
| gateway          | Gateway IP of the route. If the route does not involve a gateway, for example a direct route, the value is `N/A`.  | `ip` or `N/A` |  |
| interface      | Network interface for the destination. For a blackhole route, the value is `blackhole`. For a unreachable route, the value is `unreachable`.  | string |      |
| learnedFrom      | Information regarding where this route originated. | [learned from](#learnedfrom) |  |

#### LearnedFrom

| Field              | Description                            | Schema | Possible Values |
|--------------------|----------------------------------------|--------|-----------------|
| sourceType         | Type of the source where a route is learned from. | string | Kernel, Static, Direct, NodeMesh, BGPPeer |
| peerIP             | If sourceType is NodeMesh or BGPPeer, IP address of the router that sent us this route. | `ip` |  |

