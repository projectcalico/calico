---
title: Configure overlay networking
Description: Configure Calico to use IP in IP or VXLAN overlay networking so the underlying network doesn’t need to understand pod addresses.
---

### Big picture

Configure {{site.prodname}} to encapsulate workload traffic using IP in IP or VXLAN so that the underlying network doesn’t need to be configured to understand pod addresses.

### Value

Overlay networks allow you to get guest workloads networked without injecting routing information into the underlying network. In general, we recommend running {{site.prodname}} without network overlay/encapsulation for the highest performance and simplest network; the packet that leaves your workload is the packet that goes on the wire.  However, overlay networks are useful in the following scenarios.

#### AWS across multiple VPCs/subnets

Public clouds often do not support injecting routing information into the underlying network, or have a limited number of routes available. For example, AWS has a limited number of routes available effectively limiting the size of your cluster.  {{site.prodname}} can selectively encapsulate only the traffic that is routed **between** the VPCs/subnets, and run without encapsulation **within** each VPC/subnet, removing the dependency on AWS cloud routes.

#### Networking team restrictions

Network security teams may keep the underlying routing control plane isolated from {{site.prodname}}. They may also need to schedule time to set up {{site.prodname}} BGP peering and other routing information in your underlying network. In the meantime, you could get started using {{site.prodname}} using encapsulation for pod traffic.

### Features

This how-to guide uses the following {{site.prodname}} features:

**IPPool** resource with:
  - ipipMode field
  - vxlanMode field
  - natOutgoing field

### Concepts

#### Overlays

An **overlay network** is a network that runs on top of another network. The underlying network usually treats the overlay as opaque data, and doesn’t need to be aware of the addresses or endpoints in the overlay. Typically, this is accomplished by **encapsulation**, where the packets from the overlay are inserted inside packets from the underlay.

In **IP in IP overlays**, IP packets from the overlay are inserted into IP packets in the underlying network. Specifically, the packets between guest workload endpoints are inserted into IP packets sent between the hosts. They are de-encapsulated at the destination and delivered as normal to the guest workloads.

#### Encapsulation types

{{site.prodname}} supports two types of encapsulation:

- IP in IP is a good choice because the overhead is smaller overhead than VXLAN, and Linux kernel support is mature and performant.
- VXLAN is supported in some environments where IP in IP is not (for example, Azure). However, VXLAN has a slightly higher per-packet overhead because the header is larger.

#### Cross subnet encapsulation

A **subnet** is a group of endpoints that can communicate with one another over layer 2 (for example ethernet). When the hosts are in the same subnet, traffic typically does not need to be encapsulated because no intermediate routers (layer 3) process the packets. However, when workload traffic crosses a router (crossing an IP subnet boundary), you can use {{site.prodname}} cross subnet mode for encapsulation.

{{site.prodname}} can perform encapsulation on: all traffic, no traffic, or only on traffic that crosses a subnet boundary. Cross subnet mode provides better performance in AWS multi-AZ deployments, and for networks where routers are used to connect pools of nodes with L2 connectivity.

#### Communication outside the overlay

To configure access to destinations outside the pool, you can enable outgoing SNAT on the IP pool. Without this setting, endpoints in the IP pool are usually not able to communicate with addresses outside of the pool.

### Before you begin...

**Supported**

- IP in IP and VXLAN with IPv4 addresses

>**Note**: Switching encapsulation modes after initial configuration can cause disruption to in-progress connections. Plan accordingly.
{: .alert .alert-info}

### How to

You can configure each IP pool with different encapsulation configurations. However, you cannot mix encapsulation types within an IP pool.

- [Configure IP in IP encapsulation only for cross subnet traffic](#configure-ip-in-ip-encapsulation-only-for-cross-subnet-traffic)
- [Configure IP in IP encapsulation for all inter-workload traffic](#configure-ip-in-ip-encapsulation-for-all-inter-workload-traffic)
- [Configure VXLAN encapsulation only for cross subnet traffic](#configure-vxlan-encapsulation-only-for-cross-subnet-traffic)
- [Configure VXLAN encapsulation for all inter-workload traffic](#configure-vxlan-encapsulation-for-all-inter-workload-traffic)
- [Configure network address translation (NAT)](#configure-network-address-translation-nat)

#### Configure IP in IP encapsulation only for cross subnet traffic

To enable IP in IP encapsulation only for traffic that cross subnet boundaries, set `ipipMode` to `CrossSubnet`.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-cross-subnet-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: CrossSubnet
  natOutgoing: true
```

#### Configure IP in IP encapsulation for all inter-workload traffic

With `ipipMode` set to `Always`, Calico routes traffic using IP in IP for all traffic originating from a Calico enabled host, to all Calico networked containers and VMs within the IP pool.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-ipip-1
spec:
  cidr: 192.168.0.0/16
  ipipMode: Always
  natOutgoing: true
```

#### Configure VXLAN encapsulation only for cross subnet traffic

To enable VXLAN encapsulation only for traffic that cross subnet boundaries, set `vxlanMode` to `CrossSubnet`.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-cross-subnet-1
spec:
  cidr: 192.168.0.0/16
  vxlanMode: CrossSubnet
  natOutgoing: true
```

#### Configure VXLAN encapsulation for all inter-workload traffic

With `vxlanMode` set to `Always`, {{site.prodname}} routes traffic using VXLAN for all traffic originating from a {{site.prodname}} enabled host, to all {{site.prodname}} networked containers and VMs within the IP pool.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ippool-vxlan-1
spec:
  cidr: 192.168.0.0/16
  vxlanMode: Always
  natOutgoing: true
```

If you use only VXLAN pools, BGP networking is not required. To reduce the moving parts in your cluster, you can disable BGP using the steps in [Customizing the manifests]({{site.baseurl}}/getting-started/kubernetes/installation/config-options#about-customizing-manifests). (Set the `calico_backend` setting to `vxlan`, and disable the BGP readiness check).

#### Configure network address translation (NAT)

To configure hosts to source-NAT packets from IPs in the pool sent to destinations outside the pool, add the setting, **natOutgoing: true**. Without this setting, endpoints in the pool are usually not able to communicate with addresses outside the cluster.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: ipip-nat-outgoing
spec:
  cidr: 10.1.0.0/16
  ipipMode: CrossSubnet
  natOutgoing: true
  disabled: false
  nodeSelector: all()
```

### Above and beyond

[Configure MTU to maximize network performance]({{site.baseurl}}/{{page.version}}/networking/mtu)
