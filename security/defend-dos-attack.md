---
title: Defend against DoS attacks
description: Define DoS mitigation rules in Calico policy to quickly drop connections when under attack. Learn how rules use eBPF and XDP, including hardware offload when available.
---

### Big picture 

Calico automatically enforces specific types of deny-list policies at the earliest possible point in the packet processing pipeline, including offloading to NIC hardware whenever possible.

### Value

During a DoS attack, a cluster can receive massive numbers of connection requests from attackers. The faster these connection requests are dropped, the less flooding and overloading to your hosts. When you define DoS mitigation rules in Calico network policy, Calico enforces the rules as efficiently as possible to minimize the impact.

### Features

This how-to guide uses the following Calico features:
- **HostEndpoint**(s) as the policy enforcement point
- **GlobalNetworkSet** to manage deny-listed CIDRs
- **GlobalNetworkPolicy** to deny ingress traffic from IPs in the global network set

### Concepts

#### Earliest packet processing

The earliest point in the packet processing pipeline that packets can be dropped, depends on the Linux kernel version and the capabilities of the NIC driver and NIC hardware. Calico automatically uses the fastest available option.

| Processed by... | Used by Calico if...                                         | Performance |
| --------------- | ------------------------------------------------------------ | ----------- |
| NIC hardware    | The NIC supports **XDP offload** mode.                       | Fastest     |
| NIC driver      | The NIC driver supports **XDP native** mode.                 | Faster      |
| Kernel          | The kernel supports **XDP generic mode** and Calico is configured to explicitly use it. This mode is rarely used and has no performance benefits over iptables raw mode below. To enable, see [Felix Configuration]({{ site.baseurl }}/reference/resources/felixconfig).   | Fast        |
| Kernel          | If none of the modes above are available, **iptables raw** mode is used. | Fast        |

>**Note**: XDP modes require Linux kernel v4.16 or later.
{: .alert .alert-info}

### How to

The high-level steps to defend against a DoS attack are:

- [Step 1: Create host endpoints](#step-1-create-host-endpoints)
- [Step 2: Add CIDRs to deny-list in a global network set](#step-2-add-cidrs-to-deny-list-in-a-global-network-set)
- [Step 3: Create deny incoming traffic global network policy](#step-3-create-deny-incoming-traffic-global-network-policy)

#### Best practice

The following steps walk through the above required steps, assuming no prior configuration is in place. A best practice is to proactively do these steps before an attack (create the host endpoints, network policy, and global network set). In the event of a DoS attack, you can quickly respond by just adding the CIDRs that you want to deny-list to the global network set.

#### Step 1: Create host endpoints

First, you create the HostEndtpoints corresponding to the network interfaces where you want to enforce DoS mitigation rules. In the following example, the HostEndpoint secures the interface named **eth0** with IP **10.0.0.1** on node **jasper**.

```yaml
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: production-host
  labels:
    apply-dos-mitigation: "true"
spec:
  interfaceName: eth0
  node: jasper
  expectedIPs: ["10.0.0.1"]
```

#### Step 2: Add CIDRs to deny-list in a global network set

Next, you create a Calico **GlobalNetworkset**, adding the CIDRs that you want to deny-list. In the following example, the global network set deny-lists the CIDR ranges **1.2.3.4/32** and **5.6.0.0/16**:

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: dos-mitigation
  labels:
    dos-deny-list: 'true'
spec:
  nets:
  - "1.2.3.4/32"
  - "5.6.0.0/16"
```

#### Step 3: Create deny incoming traffic global network policy 

Finally, create a Calico GlobalNetworkPolicy adding the GlobalNetworkSet label (**dos-deny-list** in the previous step) as a selector to deny ingress traffic. To more quickly enforce the denial of forwarded traffic to the host at the packet level, use the **doNotTrack** and **applyOnForward** options.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: dos-mitigation
spec:
  selector: apply-dos-mitigation == 'true'
  doNotTrack: true
  applyOnForward: true
  types:
  - Ingress
  ingress:
  - action: Deny
    source:
      selector: dos-deny-list == 'true'
```

### Above and beyond

- [Global network sets]({{ site.baseurl }}/reference/resources/globalnetworkset)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
- [Create a host endpoint]({{ site.baseurl }}/reference/resources/hostendpoint)
- [Introduction to XDP](https://www.iovisor.org/technology/xdp){:target="_blank"}
- [Advanced XDP documentation](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/index.html){:target="_blank"}
