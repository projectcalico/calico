---
title: Calico on Google Cloud
---

Calico is designed to provide high performance massively scalable virtual
networking for containers in public cloud environments such as
Google Cloud.

## Why Use Calico in Google Cloud

#### Network Policy for Containers

While Google Cloud Firewall Rules control network traffic sent to VM instances,
it does not cover containers running on them. Calico automatically implements
fine-grain, dynamic network policy for containers.

#### No Overlays

Calico minimizes the need for overlays by assigning each container
its own IP and allowing containers to talk to one another in a pure IP network.

## How to Run Calico in Google Cloud

To deploy Calico in Google Cloud, ensure that the proper firewall rules
have been created and that traffic between containers on different hosts is not
dropped. There are a few different options for doing this depending
on your deployment.

#### Configure Firewall Rules

Calico requires the following firewall exceptions to enable the necessary
network connectivity for Calico Google Cloud.

| Description    | Allowed Protocol and Ports |
|:---------------|:---------------------------|
| BGP            | tcp:79                     |
| \*IPIP         | 4                          |

>\*IPIP: Only required if using Calico with IPIP encapsulation.
Keep reading for information on when IPIP is required in Google Cloud.

You can check if your hosts have successfully established BGP sessions with
one another using `calicoctl node status`.

#### Allow Workload-to-Workload Traffic

Inc Google Cloud, all workload traffic will pass through the network's routing table.
If this routing table does not know how to route container/pod IPs, it will
drop the traffic. There are two ways two prevent this from happening:

1. Encapsulate Container Traffic

   Container traffic can be encapsulated with its host IP so that the
   never sees the container IPs, allowing standard Google Cloud routing to take over.

   Turn on traffic encapsulation in pool settings by enabling:

   - `ipip` for container-to-container traffic.
   - `nat-outgoing` for container-to-ec2-instance traffic.

   See [pool configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool) for information on how to enable this for IP pools.

2. Configure the Routing Table

   Alternatively, the routing table can be programmed with container/pod IP
   routes so that it can route container traffic natively.
   This can be accomplished in two ways:

   1. Deploy [canal][canal] and select the [Google Cloud backend][Google Cloud-backend],
      which interacts with Google Cloud APIs to automatically program the routing table.

   2. Manually program the routing table (not recommended).

[canal]: https://github.com/tigera/canal
[Google Cloud-backend]: https://github.com/coreos/flannel#backends
