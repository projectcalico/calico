---
title: Configure workload access outside the cluster
description: Enable and disable internet access for your workloads.
canonical_url: '/networking/workloads-outside-cluster'
---

### Big picture

With all {{site.prodname}} networking options, you can enable and disable internet access for your workloads.

### Value

You control which {{site.prodname}} IP pools are subject to outbound NAT to enable public and private network connections and allow single IP address communication.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource with natOutgoing field

### Concepts

#### Outgoing NAT on each node

For all networking options, you can allow your workloads to access the internet (subject to network policy, of course!) by enabling outbound NAT on the IP pool.  When enabled, traffic from pods in that pool going to a destination outside all {{site.prodname}} pools will be NATed.  The source address is masqueraded to an IP of the node on which each workload is hosted, allowing the network to understand the traffic. By default, the NAT outgoing option is automatically enabled for the pool that is created when you install {{site.prodname}}.

#### BGP peering with out-of-cluster NAT

When {{site.prodname}} is [BGP peered with your physical network infrastructure]({{ site.baseurl }}/networking/bgp), you can use the infrastructure to NAT traffic from pods to the internet.  In this case, you should disable the {{site.prodname}} NAT outgoing option.

#### Expose pods directly on the internet

If you want your pods to have public internet IPs:

- Configure {{site.prodname}} to peer with your physical network infrastructure
- Create an IP pool for those pods that contain public IP addresses that are routed to your network with `natOutgoing: false`
- Verify that other network equipment does not NAT the pod traffic

### How to

- [Allow workloads access to internet, private IP addresses](#allow-workloads-access-to-internet-private-ip-addresses)
- [NAT traffic only to specific IP address ranges](#nat-traffic-only-to-specific-ip-address-ranges)

#### Allow workloads access to internet, private IP addresses

To allow workloads with a private IP address access to the internet, you can use your existing NAT capabilities, or you can enable natOutgoing on the {{site.prodname}} IPPool.

In the following example, we create a {{site.prodname}} IPPool with natOutgoing enabled. Outbound NAT is performed locally on the node where each workload in the pool is hosted.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: default-ipv4-ippool
spec:
  cidr: 192.168.0.0/16
  natOutgoing: true
```

#### NAT traffic only to specific IP address ranges

You can create additional IPPools that are not used for IP address management that prevent NAT to certain CIDR blocks. This is useful if you want nodes to NAT traffic to the internet, but not to IPs in certain internal ranges.  For example, if you did not want to NAT traffic from pods to 10.0.0.0/8, you could create the following pool.  You must ensure that the network between the cluster and 10.0.0.0/8 can route pod IPs.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: no-nat-10.0.0.0-8
spec:
  cidr: 10.0.0.0/8
  disabled: true
```
