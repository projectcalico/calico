---
title: Defend against a DoS Attack
---

### Big Picture

Calico automatically enforces certain types of blacklist policies at the earliest possible point in the packet processing pipeline, including offloading to NIC hardware whenever possible.

### Value
When under DoS attack, your cluster can receive massive numbers of connection requests from attackers. The faster these connection requests are dropped, the less flooding and overloading to your hosts. Calico allows you to define DoS mitigation rules in network policy, enforces these as efficiently as possible to minimize the impact in a DoS attack.

### Features
This how-to article uses the following Calico features:
- One or more host endpoints as the policy enforcement point
- A global network set to manage your blacklisted CIDRs
- A global network policy to deny ingress traffic from IPs in the global network set

### Concepts

#### Earliest packet processing
The earliest point in the packet processing pipeline where packets can be dropped, depends on the Linux kernel version and the capabilities of the NIC driver and NIC hardware. Calico automatically uses the fastest available option.

| Processed by... | Used by Calico if...                                         | Performance |
| --------------- | ------------------------------------------------------------ | ----------- |
| NIC hardware    | The NIC supports **XDP offload** mode.                       | Fastest     |
| NIC driver      | The NIC driver supports **XDP native** mode.                 | Faster      |
| Kernel          | The kernel is configured with **XDP generic** mode enabled.  (This mode is rarely enabled, and typically used only by Linux networking developers.) | Fast        |
| Kernel          | If none of the modes above are available, **iptables raw** mode is used. | Fast        |

**Note**: XDP modes require Linux kernel v4.16 or later.

### How to

The high-level steps to defend against a DoS attack are:
- [Step 1: Create a host endpoint with allowed IPs](#step-1-create-host-endpoints)
- [Step 2: Blacklist CIDRs in a global network set](#step-2-set-up-blacklist-cidrs-in-a-global-network-set)
- [Step 3: Create deny incoming traffic global network policy](#step-3-create-deny-incoming-traffic-global-network-policy) 

#### Best practice
The following example walks through the above required steps, and assumes no configuration is in place. A best practice is to proactively create the host endpoints, network policy, and global network set. In the event of a DoS attack, you can quickly respond by just adding the blacklist CIDRs to the global network set.

#### Step 1: Create host endpoints
First, you need to create the host endpoints corresponding to the network interfaces where you want to enforce any DoS mitigation rules. In the following example, the host endpoint secures the interface named eth0 with IP 10.0.0.1 for a specific host:

```
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: <name of endpoint>
  labels:
    apply-dos-mitigation: true
spec:
  interfaceName: eth0
  node: <node name or hostname>
  expectedIPs: ["10.0.0.1"]
```

#### Step 2: Set up blacklist CIDRs in a global network set
Next, you need to create a Calico global network set, adding the CIDRs that you want to blacklist. In the following example, the global network set blacklists the CIDR ranges `1.2.3.4/32` and `5.6.0.0/16`:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: dos-mitigation
  labels:
    dos-blacklist: 'true'
spec:
  nets:
  - "1.2.3.4/32"
  - "5.6.0.0/16"
```
#### Step 3: Create deny incoming traffic global network policy 
Finally, create a Calico global network policy with the `doNotTrack` option. Use the global network set as a selector to deny ingress traffic.

```
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
      selector: dos-blacklist == 'true'
```
### Above and beyond

- [Global Network Sets](http://reference/calicoctl/resources/globalnetworkset)
- [Global Network Policy](http://reference/calicoctl/resources/globalnetworkpolicy)
- [Create a Host Endpoint](http://reference/calicoctl/resources/hostendpoint/hostendpointdefinition)
- [Introduction to XDP](https://www.iovisor.org/technology/xdp)
- [Advanced XDP Documentation](https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/index.html)
