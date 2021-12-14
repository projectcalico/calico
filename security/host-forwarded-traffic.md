---
title: Apply policy to forwarded traffic
description: Apply Calico network policy to traffic being forward by hosts acting as routers or NAT gateways.
---

### Big picture

Enforce {{site.prodname}} policy on traffic transiting a host that is used as a router or NAT gateway.

### Value

If your host has multiple network interfaces, and is configured as a router, or NAT gateway between two different networks, you may want to enforce policy on traffic as it moves between the networks. In this configuration, often neither the source or destination is a {{site.prodname}} endpoint, so policy enforcement at the endpoint is not available. You can centrally manage the firewall policy on a fleet of such hosts using the same policy language as the rest of {{site.prodname}}.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Host Endpoint**
- **GlobalNetworkPolicy**
  - applyOnForward setting
  - preDNAT setting

### Concepts

#### Workload endpoints and host endpoints

The following figure shows a host with two network interfaces: eth0 and eth1. We call these **host endpoints (HEPs)**. The host also runs two guest workloads (VMs or containers). We call the virtual interfaces to the guests, **workload endpoints (WEPs)**.  Each has a corresponding configuration object on the {{site.prodname}} API called HostEndpoint and WorkloadEndpoint, respectively. 

The `HostEndpoint API` object is optional, and Calico does not enforce any policy on the HEP if the API object is missing. The `WorkloadEndpoint API` object is required, and is automatically managed by the cluster orchestrator plugin (for example, Kubernetes or OpenStack).

Several connections are shown in the figure, numbered 1 through 4. For example, connection 1 ingresses over HEP eth0, is forwarded, and then ingresses Workload A’s WEP. Calico policies select which WEPs or HEPs they apply to. So, for example an ingress policy that selects Workload A’s WEP will apply to connections as shown in number 1.

![Host-forward-traffic]({{site.baseurl}}/images/host-forward-traffic.png)

#### applyOnForward

By default, {{site.prodname}} global network policies set **applyOnForward to false**. When set to false on policies that select HEPs, the policies are applied only to traffic that originates or terminates on the host, for example: connection 4 (Node process). Connections 1-3 are unaffected by policies that select the HEP, but have applyOnForward set to false.

In contrast, if applyOnForward is set to true for a policy that selects a HEP, that policy can apply to all connections 1-4. For example:

- Ingress policy on HEP eth0 affects connections 1 and 2
- Egress policy on HEP eth1 affects connections 2, 3, and 4

There are also different default action semantics for **applyOnForward: true policy** versus **applyOnForward: false policy**.
An applyOnForward: true policy affects all traffic through the HEP (connections 1-4). If no applyOnForward policy selects the HEP and direction (ingress versus egress), then forwarded traffic is allowed.  If no policy (regardless of applyOnForward) selects the HEP and direction, then local traffic is denied.

| **HEP defined?** | **Traffic Type** | **applyOnForward defined?** | **Any policy defined?** | **Default Action** |
| ---------------- | ---------------- | --------------------------- | ----------------------- | ------------------ |
| No               | Any              | n/a                         | n/a                     | Allow              |
| Yes              | Forwarded        | No                          | Any                     | Allow              |
| Yes              | Forwarded        | Yes                         | Yes                     | Deny               |
| Yes              | Local            | n/a                         | No                      | Deny               |
| Yes              | Local            | n/a                         | Yes                     | Deny               |

**{{site.prodname}} namespaced network policies** do not have an applyOnForward setting. HEPs are always cluster global, not namespaced, so network policies cannot select them.

#### preDNAT policy

Hosts are often configured to perform Destination Network Address Translation before forwarding certain packets. A common example of this in cloud computing is when the host acts as a reverse-proxy to load balance service requests for a set of backend workload instances. To apply policy to a specific example of such a reverse-proxy, see [Kubernetes nodePorts]({{ site.baseurl }}/security/kubernetes-node-ports).

When preDNAT is set to false on a global network policy, the policy rules are evaluated on the connection after DNAT is performed. False is the default.  When preDNAT is set to true, the policy rules are evaluated on the connection before DNAT has been performed. 

If you set preDNAT policy to true, you must set applyOnForward to true, and preDNAT policy must only include Ingress policies.

#### Host Endpoints with interfaceName: `*`

HostEndpoint API objects can be created with the name of the host interface (as reported by ip link or similar), or they can be created with interfaceName set to `*`, which means all host interfaces on the given node, including the interfaces between the host to any WEPs on that host.

With interfaceName set to a particular interface, any policies that select the HEP apply only if the traffic goes through the named interface. With it set to `*`, policies that select the HEP apply regardless of the interface.

This is particularly relevant when you want to enforce policy for a host that also runs guest workloads like VMs or Pods. Traffic from local workloads to reverse-proxy IPs or ports do not traverse any external interfaces, and thus a HEP with interfaceName set to * is required in order for policy to apply to them.

### How to

#### Control forwarded traffic in or out of particular networks

1. Choose a labeling scheme for your Host Endpoints (network interfaces).  
   For example, if you have an application network and management network, you might choose the labels **network = application** and **network = management**.
1. Write GlobalNetworkPolicies expressing your desired rules.    
   - applyOnForward set to true.   
   - Use the **selector:** to choose which Host Endpoints to apply policy.
1. Create the HostEndpoint objects on the `{{site.prodname}} API`.    
   - Label the HostEndpoints according to the label scheme you developed in step 1.    
   - We recommend that you create policies before you create the Host Endpoints. This ensures that all policies exist before {{site.prodname}} starts enforcing.     

### Tutorial

Let’s say I have a host that has two network interfaces:

- eth0 -  connects to the main datacenter network for application traffic
- eth1 -  connects to a special maintenance network

My goal is to allow SSH traffic to be forwarded to the maintenance network, but to drop all other traffic.

I choose the following label scheme:

- network = application for the main datacenter network for application traffic
- network = maintenance for the maintenance network

I create the GlobalNetworkPolicy that allows SSH traffic (default deny is implicit in this case).

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-ssh-maintenance
spec:
  selector: network == 'maintenance'
  applyOnForward: true
  types:
  - Egress
  egress:
  # Allow SSH
  - action: Allow
    protocol: TCP
    destination:
      ports:
      - 22
```

Save this as allow-ssh-maintenace.yaml.

Apply the policy to the cluster:

<pre>
calicoctl create -f allow-ssh-maintenance.yaml
</pre>

Finally, create the host endpoint for the interface that connects to the maintenance network.

```yaml
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: myhost.eth1
  labels:
    network: maintenance
spec:
  interfaceName: eth1
  node: myhost
  expectedIPs:
  - 192.168.0.45
```

Replace myhost with the node name {{site.prodname}} uses, and the expected IPs with the actual interface IP address(es).  Save this file as hep.yaml.

Apply the host endpoint to the cluster:

<pre>
calicoctl create -f hep.yaml
</pre>

For completeness, you could also create a HostEndpoint for eth0, but because we have not written any policies for the application network yet, you can omit this step.

### Above and beyond

- [Host endpoint]({{ site.baseurl }}/reference/resources/hostendpoint)
- [Workload endpoint]({{ site.baseurl }}/reference/resources/workloadendpoint)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
