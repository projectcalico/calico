---
title: Defend against DoS attacks
---

### Big Picture

Calico automatically enforces specific types of blacklist policies at the earliest possible point in the packet processing pipeline, including offloading to NIC hardware whenever possible.

### Value
During a DoS attack, a cluster can receive massive numbers of connection requests from attackers. The faster these connection requests are dropped, the less flooding and overloading to your hosts. When you define DoS mitigation rules in Calico network policy, Calico enforces the rules as efficiently as possible to minimize the impact.

### Features
This how-to article uses the following Calico features:
- One or more host endpoints as the policy enforcement point
- A global network set to manage blacklisted CIDRs
- A global network policy to deny ingress traffic from IPs in the global network set

### Concepts

### How to

The high-level steps to defend against a DoS attack are:

- [Step 1: Create host endpoints](#step-1-create-host-endpoints)
- [Step 2: Add CIDRs to blacklist in a global network set](#step-2-add-cidrs-to-blacklist-in-a-global-network-set)
- [Step 3: Create deny incoming traffic global network policy](#step-3-create-deny-incoming-traffic-global-network-policy)

#### Best practice
The following steps walk through the above required steps, assuming no prior configuration is in place. A best practice is to proactively do these steps before an attack (create the host endpoints, network policy, and global network set). In the event of a DoS attack, you can quickly respond by just adding the CIDRs that you want to blacklist to the global network set.

#### Step 1: Create host endpoints
First, you create the host endpoints corresponding to the network interfaces where you want to enforce any DoS mitigation rules. In the following example, the host endpoint secures the interface named **eth0** with IP **10.0.0.1** on node **jasper**.

<pre>
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: production-host
  labels:
    apply-dos-mitigation: true
spec:
  interfaceName: <b>eth0</b>
  <b>node: jasper</b>
  expectedIPs: ["10.0.0.1"]
</pre>
{: .no-select-button}

#### Step 2: Add CIDRs to blacklist in a global network set
Next, you create a Calico **global network set**, adding the CIDRs that you want to blacklist. In the following example, the global network set blacklists the CIDR ranges `1.2.3.4/32` and `5.6.0.0/16`:

<pre>
apiVersion: projectcalico.org/v3
<b>kind: GlobalNetworkSet</b>
metadata:
  name: dos-mitigation
  labels:
    dos-blacklist == 'true'
spec:
  <b>nets:
  - "1.2.3.4/32"
  - "5.6.0.0/16"</b>
</pre>
{: .no-select-button}

#### Step 3: Create deny incoming traffic global network policy
Finally, create a Calico global network policy adding the global network set label (**dos-blacklist** in the previous step) as a selector to deny ingress traffic. To more quickly enforce the denial of forwarded traffic to the host at the packet level, use the **doNotTrack** and **applyOnForward** options.

<pre>
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: dos-mitigation
spec:
  selector: apply-dos-mitigation == 'true'
  <b>doNotTrack: true
  applyOnForward: true</b>
  types:
  - Ingress
  ingress:
  - action: Deny
    source:
      <b>selector: dos-blacklist == 'true'</b>
</pre>
{: .no-select-button}

### Above and beyond

- [Global Network Sets]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkset)
- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkpolicy)
- [Create a Host Endpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint)
