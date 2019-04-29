---
title: Connecting workloads that you do not control
---

### Big Picture

Enable inter workload communication across networks that are not workload aware.

### Value

Calico supports encapsulation so you can send traffic between workloads, without requiring the underlying network to be aware of pod IP addresses.

### Features

This how-to guide uses the following features: 

- IP in IP encapsulation
- VXLAN encapsulation

### Concepts

#### Routing workload IP addresses
When a network is **aware of workload IP addresses** (either through static routes, BGP route distribution, or another mechanism), it can directly route traffic between workloads. However, not all networks are able to route workload IP addresses. For example, public cloud environments where you don’t own the hardware, AWS across VPC subnet boundaries, and other scenarios where you cannot peer Calico over BGP to the underlay or easily configure static routes. This is why Calico supports encapsulation, so you can send traffic between workloads without requiring the underlying network to be aware of workload IP addresses.

#### Encapsulation types
Calico supports two types of encapsulations: VXLAN and IP in IP.  VXLAN is supported in some environments where IP in IP is not (for example, Azure). However, VXLAN has a slightly higher per-packet overhead because the header is larger.

####
Cross subnet
Encapsulation of workload traffic is typically required only when traffic crosses a router (crossing an IP subnet boundary). For IP in IP, Calico can perform encapsulation on: all traffic, no traffic, or only on traffic that crosses a subnet boundary.

### How to

You can configure each IP pool with different encapsulation configurations. However, you cannot mix encapsulation types within an IP pool.

- [Configure IP in IP encapsulation for only cross subnet traffic](#configure-ip-in-ip-encapsulation-for-only-cross-subnet-traffic)
- [Configure IP in IP encapsulation for all inter workload traffic](#configure-ip-in-ip-encapsulation-for-all-inter-workload-traffic)
- [Configure VXLAN encapsulation for all inter workload traffic](#configure-vxlan-encapsulation-for-all-inter-workload-traffic)

#### Best practice

For IP in IP encapsulation, use the **cross subnet** option to minimize the overhead associated with encapsulation. Cross subnet mode provides better performance in AWS multi-AZ deployments, and on networks where routers are used to connect pools of nodes with L2 connectivity.

Be aware that switching encapsulation modes can cause disruption to in-progress connections. Plan accordingly. 

#### Configure IP in IP encapsulation for only cross subnet traffic
IP in IP encapsulation can be performed selectively, and only for traffic crossing subnet boundaries. 

To enable this feature, set `ipipMode` to `CrossSubnet`.

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-cross-subnet-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: CrossSubnet
  natOutgoing: true
</pre> 

#### Configure IP in IP encapsulation for all inter workload traffic

With `ipipMode` set to `Always`, Calico routes traffic using IP in IP for all traffic originating from a Calico enabled-host, to all Calico networked containers and VMs within the IP pool.

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-ipip-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: Always
  natOutgoing: true
</pre>

#### Configure VXLAN encapsulation for all inter workload traffic

With `vxlanMode` set to `Always`, Calico routes traffic using VXLAN for all traffic originating from a Calico enabled host, to all Calico networked containers and VMs within the IP pool.

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-vxlan-1
spec:
  cidr: 192.168.0.0/16
  vxlanMode: Always
  natOutgoing: true
</pre>

If you use only VXLAN pools, BGP networking is not required. You can disable BGP to reduce the moving parts in your cluster by [Customizing the manifests](https://docs.projectcalico.org/master/getting-started/kubernetes/installation/config-options). Set the `calico_backend` setting to `vxlan`, and disable the BGP readiness check.

### Above and Beyond
For details on the IP in IP option, see [IP pools]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).
