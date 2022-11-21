---
title: Configure outgoing NAT
description: Configure networking to perform outbound NAT for connections from pods to outside of the cluster.
canonical_url: '/networking/workloads-outside-cluster'
---

### Big picture

Configure {{site.prodname}} networking to perform outbound NAT for connections from pods to outside of the cluster. {{site.prodname}} optionally source NATs the pod IP to the node IP.

### Value

The {{site.prodname}} NAT outbound connection option is flexible; it can be enabled, disabled, and applied to {{site.prodname}} IP pools with public IPs, private IPs, or a specific range of IP addresses. This article describes some use cases for enabling and disabling outgoing NAT.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource with `natOutgoing` field

### Concepts

#### {{site.prodname}} IP pools and NAT

When a pod with an IP address in the pool initiates a network connection to an IP address to outside of {{site.prodname}}’s IP pools, the outgoing packets will have their source IP address changed from the pod IP address to the node IP address using SNAT (Source Network Address Translation). Any return packets on the connection automatically get this change reversed before being passed back to the pod.

#### Enable NAT: for pods with IP addresses that are not routable beyond the cluster

A common use case for enabling NAT outgoing, is to allow pods in an overlay network to connect to IP addresses outside of the overlay, or pods with private IP addresses to connect to public IP addresses outside the cluster/the internet (subject to network policy allowing the connection, of course). When NAT is enabled, traffic is NATed from pods in that pool to any destination outside of all other {{site.prodname}} IP pools.

#### Disable NAT: For on-premises deployments using physical infrastructure 

If you choose to implement {{site.prodname}} networking with [BGP peered with your physical network infrastructure]({{site.baseurl}}/networking/bgp), you can use your own infrastructure to NAT traffic from pods to the internet. In this case, you should disable the {{site.prodname}} `natOutgoing` option. For example, if you want your pods to have public internet IPs, you should:

- Configure {{site.prodname}} to peer with your physical network infrastructure
- Create an IP pool with public IP addresses for those pods that are routed to your network with NAT disabled (`natOutgoing: false`)
- Verify that other network equipment does not NAT the pod traffic

### How to

- [Create an IP pool with NAT outgoing enabled](#create-an-ip-pool-with-nat-outgoing-enabled)
- [Use additional IP pools to specify addresses that can be reached without NAT](#use-additional-ip-pools-to-specify-addresses-that-can-be-reached-without-nat)

#### Create an IP pool with NAT outgoing enabled

In the following example, we create a {{site.prodname}} IPPool with natOutgoing enabled. Outbound NAT is performed locally on the node where each workload in the pool is hosted.

```yaml
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: default-ipv4-ippool
spec:
  cidr: 192.168.0.0/16
  natOutgoing: true
```

#### Use additional IP pools to specify addresses that can be reached without NAT

Because {{site.prodname}} performs outgoing NAT only when connecting to an IP address that is not in a {{site.prodname}} IPPool, you can create additional IPPools that are not used for pod IP addresses, but prevent NAT to certain CIDR blocks. This is useful if you want nodes to NAT traffic to the internet, but not to IPs in certain internal ranges. For example, if you did not want to NAT traffic from pods to 10.0.0.0/8, you could create the following pool. You must ensure that the network between the cluster and 10.0.0.0/8 can route pod IPs.

```yaml
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: no-nat-10.0.0.0-8
spec:
  cidr: 10.0.0.0/8
  disabled: true
```