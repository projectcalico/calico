---
title: AWS
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/public-cloud/aws'
---

Calico provides the following advantages when running in AWS:

- **Network Policy for Containers**: Calico provides fine-grained network security policy for individual containers.
- **No Overlays**: Within each VPC subnet Calico doesn't need an overlay, which means high performance networking for your containers.
- **No 50 Node Limit**: Calico allows you to surpass the 50 node limit, which exists as a consequence of the [AWS 50 route limit](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-route-tables) when using the VPC routing table.

## Requirements

To deploy Calico in AWS, you must ensure that the proper security group rules
have been made and that traffic between containers on different hosts is not
dropped by the VPC. There are a few different options for doing this depending
on your deployment.

#### Configure Security Groups

Calico requires the following security group exceptions to function properly
in AWS.

| Description   | Type            | Protocol | Port Range |
|:--------------|:----------------|:---------|:-----------|
| BGP           | Custom TCP Rule | TCP      | 179        |
| IPIP*         | Custom Protocol | 4        | all        |

\* The IPIP exception is required only when using Calico with IPIP encapsulation. Keep reading 
for information on when IPIP is required in AWS.

#### Routing Traffic Within a Single VPC Subnet

Since Calico assigns IP addresses outside the range used by AWS for EC2 instances, you must disable AWS src/dst
checks on each EC2 instance in your cluster
[as described in the AWS documentation](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck).  This
allows Calico to route traffic natively within a single VPC subnet without using an overlay or any of the limited VPC routing table entries.

#### Routing Traffic Across Different VPC Subnets / VPCs

If you need to split your deployment across multiple AZs for high availability then each AZ will have its own VPC subnet.  To
use Calico across multiple different VPC subnets or [peered VPCs](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-peering.html),
in addition to disabling src/dst checks as described above you must also enable IPIP encapsulation and outgoing NAT
on your Calico IP pools.

See the [IP pool configuration reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
for information on how to configure Calico IP pools.

By default, Calico's IPIP encapsulation applies to all container-to-container traffic.  However,
encapsulation is only required for container traffic that crosses a VPC subnet boundary.  For better
performance, you can configure Calico to perform IPIP encapsulation only across VPC subnet boundaries.

To enable the "cross-subnet" IPIP feature, configure your Calico IP pool resources
to enable IPIP and set the mode to "cross-subnet".

> **Note**: This feature was introduced in Calico v2.1, if your deployment was created with 
> an older version of Calico, or if you if you are unsure whether your deployment 
> is configured correctly, follow the [Configuring IP-in-IP guide]({{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip)
> which discusses this in more detail.
>
{: .alert .alert-info}

The following `calicoctl` command will create or modify an IPv4 pool with
CIDR 192.168.0.0/16 using IPIP mode `cross-subnet`. Adjust the pool CIDR for your deployment.

```
$ calicoctl apply -f - << EOF
apiVersion: v1
kind: ipPool
metadata:
  cidr: 192.168.0.0/16
spec:
  ipip:
    enabled: true
    mode: cross-subnet
EOF
```

#### Enabling Workload-to-WAN Traffic

To allow Calico networked containers to reach resources outside of AWS,
you must configure outgoing NAT on your [Calico IP pool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).

AWS will perform outbound NAT on any traffic which has the source address of an EC2 virtual
machine instance.  By enabling outgoing NAT on your Calico IP pool, Calico will
NAT any outbound traffic from the containers hosted on the EC2 virtual machine instances.

The following `calicoctl` command will create or modify an IPv4 pool with
CIDR 192.168.0.0/16 using IPIP mode `cross-subnet` and enables outgoing NAT.
Adjust the pool CIDR for your deployment.

```
$ calicoctl apply -f - << EOF
apiVersion: v1
kind: ipPool
metadata:
  cidr: 192.168.0.0/16
spec:
  ipip:
    enabled: true
    mode: cross-subnet
  nat-outgoing: true
EOF
```
