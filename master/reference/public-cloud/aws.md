---
title: AWS
---

Calico is designed to provide high performance massively scalable virtual
networking for containers in public cloud environments such as
Amazon Web Services (AWS).

## Why Use Calico in AWS

#### Network Policy for Containers

While AWS Security Groups control network traffic sent to ec2 instances, it
does not cover containers running on hosts. Calico automatically implements
fine-grain, dynamic network policy for containers.

#### No Overlays

Calico minimizes the need for overlays by assigning each container
its own IP and allowing containers to talk to one another in a pure IP network.

#### No 50 Node Limit

[AWS VPC Routing tables are limited to 50 programmable routes](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-route-tables).
While this might limit other networking plugins, Calico supports
ip-over-ip encapsulation to circumvent manually programming container routes in
the VPC routing table altogether.

## How to Run Calico in AWS

To deploy Calico in AWS, you must ensure that the proper security group rules
have been made and that traffic between containers on different hosts is not
dropped by the VPC. There are a few different options for doing this depending
on your deployment.

#### Configure Security Groups

Calico requires the following security group exceptions to function properly
in AWS.

| Description    | Type            | Protocol | Port Range |
|:---------------|:----------------|:---------|:-----------|
| BGP            | Custom TCP Rule | TCP      | 179        |
| \*IPIP           | Custom Protocol | IPIP     | all        |

>\*IPIP: Only required if using Calico with IPIP encapsulation.
Keep reading for information on when IPIP is required in AWS.

You can check if your hosts have successfully established BGP sessions with
one another using `calicoctl node status`.

#### Allow Traffic Within a Single VPC Subnet

By default, each EC2 instance performs source/destination checks on inbound
and outbound traffic. This ensures that the instance is the source or
destination of any traffic it sends or receives.

Since Calico allocates a unique IP address to each container that isn't the IP
of its host, and since Calico doesn't encapsulate container traffic by default,
traffic to/from containers will be dropped by the AWS src/dst checks

This reverse-path filtering is enabled by default, but can be disabled on each
host, allowing Calico traffic to pass through unaffected **between hosts within
the same VPC subnet.**
Ensure you follow
[AWS documentation on disabling source/destination checks](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck).

#### Allow Traffic Across Different VPC Subnets

Container traffic that traverses different VPC subnets will pass through
a VPC routing table. If this VPC routing table does not know how to route
container/pod IPs, it will drop the traffic. There are two ways two prevent this from
happening:

1. Encapsulate Container Traffic

   Container traffic can be encapsulated with its host IP so that the VPC
   never sees the container IPs, allowing standard ec2 routing to take over.

   Turn on traffic encapsulation in pool settings by enabling:

   - `ipip` for container-to-container traffic.
   - `nat-outgoing` for container-to-ec2-instance traffic.

   See [pool configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool) for information on how to enable this for IP pools.

2. Configure the VPC Routing Table

   Alternatively, the VPC routing table can be programmed with container/pod IP
   routes so that it can route container traffic natively.
   This can be accomplished in two ways:

   1. Deploy [canal][canal] and select the [aws-vpc backend][aws-vpc-backend],
      which interacts with AWS APIs to automatically program the routing table.

   2. Manually program the routing table (not recommended).

   >Note: [AWS VPC Routing tables are limited to 50 programmable routes](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-route-tables).

#### Allow Traffic Across Peered VPCs

AWS drops container traffic when it passes through
[peered VPCs](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-peering.html).
This behavior can not be turned off.

To circumvent this issue, enable `ipip` and `nat-outgoing` on your IP pools ([as discussed above](#allow-traffic-across-different-vpc-subnets)

#### Allow Workload-to-WAN Traffic

In a private cloud where operators maintain full control of the networking
fabric, NAT typically takes place at the edge router.

AWS performs outbound NAT on traffic that has the source address of known
EC2 instances, but does not support NAT on traffic from container/pod IP
addresses.

Calico can perform NAT on outbound container traffic on each compute node
by enabling `nat-outgoing` on each
[Calico IP pool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).

[canal]: https://github.com/tigera/canal
[aws-vpc-backend]: https://github.com/coreos/flannel#backends
