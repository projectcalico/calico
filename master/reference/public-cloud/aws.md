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
its own IP and allowing containers to talk to one another in a pure IP network
in most configurations.

#### No 50 Node Limit

[AWS VPC Routing tables are limited to 50 programmable routes](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-route-tables).
While this might limit other networking plugins, Calico architecture
circumvents this issue altogether.

## How to Run Calico in AWS

To deploy Calico in AWS, you must ensure that the proper security group rules
have been made and that traffic between containers on different hosts is not
dropped by the VPC. There are a few different options for doing this depending
on your deployment.

#### Configure Security Groups

Calico requires the following security group exceptions to function properly
in AWS.

| Description      | Type            | Protocol | Port Range |
|:-----------------|:----------------|:---------|:-----------|
| BGP              | Custom TCP Rule | TCP      | 179        |
| \*IPIP           | Custom Protocol | IPIP     | all        |

>\*IPIP: Only required if using Calico with IPIP encapsulation.
Keep reading for information on when IPIP is required in AWS.

You can check if your hosts have successfully established BGP sessions with
one another using `calicoctl node status`.

#### Allow Container Traffic

By default, AWS drops container traffic with an unrecognized IP.

This reverse-path filtering is enabled by default, but can be disabled on each
host, allowing Calico traffic to pass unaffected
**between hosts within the same VPC subnet.** See
[AWS documentation on disabling source/destination checks](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck).

#### Allow Traffic Across Different VPC Subnets

By default, AWS drops container traffic which traverses different VPC subnets,
and additionally does not perform NAT for any source besides EC2 instances.

This behavior can be circumvented by turning on traffic encapsulation in Calico's
ippool settings:

- `ipip` for container-to-container traffic.
- `nat-outgoing` for container-to-ec2-instance traffic and Workload-to-WAN traffic.

See [pool configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
for information on how to enable both for your IP pools.

[canal]: https://github.com/tigera/canal
[aws-vpc-backend]: https://github.com/coreos/flannel#backends
