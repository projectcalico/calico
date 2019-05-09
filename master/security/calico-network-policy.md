---
title: Get started with calico network policy
---

### Big Picture
Enforce which network traffic that is allowed or denied using rules in Calico network policy. 

### Value

#### Extends Kubernetes network policy
Calico network policy provides a richer set of policy capabilities than Kubernetes including: policy ordering/priority, deny rules, and more flexible match rules. While Kubernetes network policy applies only to pods, Calico network policy can be applied to multiple types of endpoints including pods, VMs, and host interfaces. Finally, when used with Istio service mesh, Calico network policy supports securing applications layers 5-7 match criteria, and cryptographic identity.

#### Write once, works everywhere
No matter which cloud provider you use now, adopting Calico network policy means you write the policy once and it is portable. If you move to a different cloud provider, you don’t need to rewrite your Calico network policy. Calico network policy is a key feature to avoid cloud provider lock-in. 

#### Works seamlessly with Kubernetes network policies
You can use Calico network policy in addition to Kubernetes network policy, or exclusively. For example, you could allow developers to define Kubernetes network policy for their microservices. For broader and higher-level access controls that developers cannot override, you could allow only security or Ops teams to define Calico network policies.

### Features

The **Calico network policy API** supports the following features:
- Policies can be applied to any kind of endpoint: pods/containers, VMs, and/or to host interfaces
- Policies can define rules that apply to ingress, egress, or both
- Policy rules support:
  - **Actions**: allow, deny, log, pass 
  - **Source and destination match criteria**:
    - Ports: numbered, ports in a range, and Kubernetes named ports
    - Protocols: TCP, UDP, ICMP, SCTP, UDPlite, ICMPv6, protocol numbers (1-255)
    - HTTP attributes (if using Istio service mesh)
    - ICMP attributes
    - IP version (IPv4, IPv6)
    - IP or CIDR
    - Endpoint selectors (using label expression to select pods, VMs, host interfaces, and/or network sets)
    - Namespace selectors
    - Service account selectors
- **Optional packet handling controls**: disable connection tracking, apply before DNAT, apply to forwarded traffic and/or locally terminated traffic

### Concepts

#### Endpoints
Calico policies apply to **endpoints**. In Kubernetes, each pod is a Calico endpoint. However, Calico can support other kinds of endpoints. There are two types of Calico endpoints: **workload endpoints** (such as a Kubernetes pod or OpenStack VM) and **host endpoints** (an interface or group of interfaces on a host). 

#### Namespaced and global network policies
**Calico network policy** is a namespaced resource that applies to pods/containers/VMs in that namespace. 

<pre>
apiVersion: projectcalico.org/v3
kind: <b>NetworkPolicy</b>
metadata:
  <b>name</b>: allow-tcp-6379
  <b>namespace</b>: production
</pre>
{: .no-select-button}

**Calico global network policy** is a non-namespaced resource and can be applied to any kind of endpoint (pods, VMs, host interfaces) independent of namespace. 

<pre>
apiVersion: projectcalico.org/v3
kind: <b>GlobalNetworkPolicy</b>
metadata:
  <b>name</b>: allow-tcp-port-6379
</pre>
{: .no-select-button}

**Calico network policies and Calico global network policies** are applied using calicoctl. Syntax is similar to Kubernetes, but there a few differences. For help, see [calicoctl user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/).

#### Ingress and egress
Each network policy rule applies to either **ingress** or **egress** traffic. From the point of view of an endpoint (pod, VM, host interface), **ingress** is incoming traffic to the endpoint, and **egress** is outgoing traffic from the endpoint. In a Calico network policy, you create ingress and egress rules independently (egress, ingress, or both). 

You can specify whether policy applies to ingress, egress, or both using the **types** field. If you do not use the types field, Calico defaults to the following values.


| Ingress rule present? | Engress rule present? |      Value      |
| :-------------------: | :-------------------: | :-------------: |
|          No           |          No           |     Ingress     |
|          Yes          |          No           |     Ingress     |
|          No           |          Yes          |     Egress      |
|          Yes          |          Yes          | Ingress, Egress |


#### Network traffic behaviors: deny and allow

The Kubernetes network policy specification defines the following behavior:
- If no network policies apply to a pod, then all traffic to/from that pod is allowed.
- If one or more network policies apply to a pod containing ingress rules, then only the ingress traffic specifically allowed by those policies is allowed, and all other traffic to/from the pod is denied.
- If one or more network policies apply to a pod containing egress rules, then only the egress traffic specifically allowed by those policies is allowed, and all other traffic to/from the pod is denied.

For compatibility with Kubernetes, **Calico network policy** follows the same behavior for Kubernetes pods.  For other endpoint types (VMs, host interfaces), Calico network policy is default deny. That is, only traffic specifically allowed by network policy is allowed, even if no network policies apply to the endpoint.

### Before you begin...
None

### How to

- [Control traffic to/from endpoints in a namespace](#control-traffic-tofrom-endpoints-in-a-namespace)
- [Control traffic to/from endpoints independent of namespace](#control-traffic-tofrom-endpoints-independent-of-namespace)
- [Control traffic to/from endpoints using IP addresses or CIDR ranges](#control-traffic-tofrom-endpoints-using-ip-addresses-or-cidr-ranges)
- [Apply network policies in specific order](#apply-network-policies-in-specific-order)
- [Generate logs for specific traffic](#generate-logs-for-specific-traffic)


#### Control traffic to/from endpoints in a namespace
In the following example, incoming traffic to endpoints in the **namespace: production** with label **color: red** is allowed, only if it comes from a pod in the same namespace with **color: blue**, on port **6379**.

<pre>
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-tcp-6379
  <b>namespace: production</b>
spec:
  selector: <b>color == 'red'</b>
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: <b>color == 'blue'</b>
    destination:
      ports:
        - <b>6379</b>
</pre>
{: .no-select-button}

To allow ingress traffic from endpoints in other namespaces, use a **namespaceSelector** in the policy rule. A namespaceSelector matches namespaces based on the labels that are applied in the namespace. In the following example, ingress traffic is also allowed from endpoints in namespaces that match **shape == circle**.

<pre>
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-tcp-6379
  namespace: production
spec:
  selector: color == 'red'
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: color == 'blue'
      <b>namespaceSelector: shape == 'circle'</b>
    destination:
      ports:
      - 6379
</pre>
{: .no-select-button}

#### Control traffic to/from endpoints independent of namespace
The following Calico network policy is similar to the previous example, but uses **kind: GlobalNetwork Policy** so it applies to all endpoints, regardless of namespace. 

In the following example, incoming TCP traffic to any pods with label **color: red** is denied if it comes from a pod with **color: blue**. 

<pre>
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-blue
spec:
  selector: <b>color == 'red'</b>
  ingress:
  - action: <b>Deny</b>
    protocol: <b>TCP</b>
    source:
      selector: <b>color == 'blue'</b>
</pre>
{: .no-select-button}

As with **kind: NetworkPolicy**, you can allow or deny ingress traffic from endpoints in specific namespaces using a namespaceSelector in the policy rule:

<pre>
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-circle-blue
spec:
  selector: color == 'red'
  ingress:
  - action: Deny
    protocol: TCP
    source:
      selector: color == 'blue'
      <b>namespaceSelector: shape == 'circle'</b>
</pre>
{: .no-select-button}

#### Control traffic to/from endpoints using IP addresses or CIDR ranges

Instead of using a selector to define which traffic is allowed to/from the endpoints in a network policy, you can also specify an IP block in CIDR notation. 

In the following example, outgoing traffic is allowed from pods with the label **color: red** if it goes to an IP address in the **1.2.3.4/24** CIDR block. 

<pre>
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-egress-external
  namespace: production
spec:
  selector:
    <b>color == 'red'</b>
  types:
    - Egress
  egress:    
    - action: Deny
      destination:
        nets:
          - <b>1.2.3.4/24</b>
</pre>
{: .no-select-button}

#### Apply network policies in specific order

To control the order/sequence of applying network policies, you can use the **order** field (with precedence from the lowest value to highest). Defining policy **order** is important when you include both **action: allow** and **action: deny** rules that may apply to the same endpoint.

In the following example, the policy **allow-cluster-internal-ingress** (order: 10) will be applied before the **policy drop-other-ingress** (order: 20). 

<pre>
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  <b>name: drop-other-ingress</b>
spec:
  <b>order: 20</b>
  <b>...deny policy rules here...</b> 
</pre>
{: .no-select-button}  
  
<pre>  
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  <b>name: allow-cluster-internal-ingress</b>
spec:
  <b>order: 10</b>
  <b>...allow policy rules here...</b>
</pre>
{: .no-select-button}

#### Generate logs for specific traffic
In the following example, incoming TCP traffic to an application is denied, and each connection attempt is logged to syslog.

<pre>
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
Metadata:
  name: allow-tcp-6379
  namespace: production
Spec:
  selector: role == 'database'
  types:
  - Ingress
  - Egress
  ingress:
  - <b>action: Log</b>
    protocol: TCP
    source:
      selector: role == 'frontend'
  - <b>action: Deny</b>
    protocol: TCP
    source:
      selector: role == 'frontend'
</pre>
{: .no-select-button}

### Tutorial
None

### Above and beyond
- For additional Calico network policy features, see [Calico Network Policy Reference]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy) and [Calico Global Network Policy Reference]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy)
- For an alternative to using IP addresses or CIDRs in policy, see [network sets]({{site.baseurl}}/{{page.version}}/reference/resources/) 
- For details on the calicoctl command line tool, see [calicoctl user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
