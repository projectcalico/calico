---
title: Amazon Web Services
description: Advantages of using Calico in AWS.
canonical_url: '/reference/public-cloud/aws'
---

{{site.prodname}} provides the following advantages when running in Amazon Web Services (AWS):

- **Network Policy for Containers**: {{site.prodname}} provides fine-grained network security policy for individual containers.
- **No Overlays**: Within each VPC subnet {{site.prodname}} doesn't need an overlay, which means high performance networking for your containers.
- **No 50 Node Limit**: {{site.prodname}} allows you to surpass the 50 node limit, which exists as a consequence of the [AWS 50 route limit](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-route-tables){:target="_blank"} when using the VPC routing table.

## Routing traffic within a single VPC subnet

Since {{site.prodname}} assigns IP addresses outside the range used by AWS for EC2 instances, you must disable AWS src/dst
checks on each EC2 instance in your cluster
[as described in the AWS documentation](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck){:target="_blank"}.  This
allows {{site.prodname}} to route traffic natively within a single VPC subnet without using an overlay or any of the limited VPC routing table entries.

## Routing traffic across different VPC subnets / VPCs

If you need to split your deployment across multiple AZs for high availability then each AZ will have its own VPC subnet.  To
use {{site.prodname}} across multiple different VPC subnets or [peered VPCs](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-peering.html){:target="_blank"},
in addition to disabling src/dst checks as described above you must also enable IPIP encapsulation and outgoing NAT
on your {{site.prodname}} IP pools.

See the [IP pool configuration reference]({{ site.baseurl }}/reference/resources/ippool)
for information on how to configure {{site.prodname}} IP pools.

By default, {{site.prodname}}'s IPIP encapsulation applies to all container-to-container traffic.  However,
encapsulation is only required for container traffic that crosses a VPC subnet boundary.  For better
performance, you can configure {{site.prodname}} to perform IPIP encapsulation only across VPC subnet boundaries.

To enable the "CrossSubnet" IPIP feature, configure your {{site.prodname}} IP pool resources
to enable IPIP and set the mode to "CrossSubnet".

> **Note**: This feature was introduced in {{site.prodname}} v2.1, if your deployment was created with
> an older version of {{site.prodname}}, or if you if you are unsure whether your deployment
> is configured correctly, follow the [Configuring IP-in-IP guide]({{ site.baseurl }}/networking/vxlan-ipip)
> which discusses this in more detail.
>
{: .alert .alert-info}

The following `calicoctl` command will create or modify an IPv4 pool with
CIDR 192.168.0.0/16 using IPIP mode `CrossSubnet`. Adjust the pool CIDR for your deployment.

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-cs-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: CrossSubnet
EOF
```

## Enabling workload-to-WAN traffic

To allow {{site.prodname}} networked containers to reach resources outside of AWS,
you must configure outgoing NAT on your [{{site.prodname}} IP pool]({{ site.baseurl }}/reference/resources/ippool).

AWS will perform outbound NAT on any traffic which has the source address of an EC2 virtual
machine instance.  By enabling outgoing NAT on your {{site.prodname}} IP pool, {{site.prodname}} will
NAT any outbound traffic from the containers hosted on the EC2 virtual machine instances.

The following `calicoctl` command will create or modify an IPv4 pool with
CIDR 192.168.0.0/16 using IPIP mode `CrossSubnet` and enables outgoing NAT.
Adjust the pool CIDR for your deployment.

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: CrossSubnet
  natOutgoing: true
EOF
```
