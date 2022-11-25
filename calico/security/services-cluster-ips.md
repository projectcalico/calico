---
title: Apply Calico policy to services exposed externally as cluster IPs
description: Expose Kubernetes service cluster IPs over BGP using Calico, and restrict who can access them using Calico network policy.
---

### Big picture

Control access to services exposed through clusterIPs that are advertised outside the cluster using BGP.

### Value

{{site.prodname}} network policy uses standard Kubernetes Services that allow you to expose services within clusters to external clients in the following ways:

- [Apply policy to Kubernetes nodeports]({{ site.baseurl }}/security/kubernetes-node-ports)
- Using cluster IPs over BGP (described in this article)

### Features

This how-to guide uses the following {{site.prodname}} features:

- {{site.prodname}} cluster IP advertisement
- **HostEndpoints**
- **GlobalNetworkPolicy**
  - applyOnForward
  - preDNAT
- **NetworkPolicy**

### Concepts

#### Advertise cluster IPs outside the cluster

A **cluster IP** is a virtual IP address that represents a Kubernetes Service. Kube Proxy on each host translates the clusterIP into a pod IP for one of the pods backing the service, acting as a reverse proxy and load balancer.

Cluster IPs were originally designed for use within the Kubernetes cluster. {{site.prodname}} allows you to advertise Cluster IPs externally -- so external clients can use them to access services hosted inside the cluster. This means that {{site.prodname}} ingress policy can be applied at **one or both** of the following locations:

- Host interface, when the traffic destined for the clusterIP first ingresses the cluster
- Pod interface of the backend pod

#### Traffic routing: local versus cluster modes

{{site.prodname}} implements [Kubernetes service external traffic policy](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip){:target="_blank"}, which controls whether external traffic is routed to node-local or cluster-wide endpoints. The following table summarizes key differences between these settings. The default is **cluster mode**.

| **Service setting**                         | **Traffic is load balanced...**                     | **Pros and cons**                                            | **Required service type**                                    |
| ------------------------------------------- | --------------------------------------------------- | :----------------------------------------------------------- | ------------------------------------------------------------ |
| **externalTrafficPolicy: Cluster**(default) | Across all nodes in the cluster                     | Equal distribution of traffic among all pods running a service. <br /><br />Possible unnecessary network hops between nodes for ingress external traffic.When packets are rerouted to pods on another node, traffic is SNAT’d (source network address translation). <br /><br />Destination pod can see the proxying node’s IP address rather than the actual client IP. | **ClusterIP**                                                |
| **externalTrafficPolicy: Local**            | Across the nodes with the endpoints for the service | Avoids extra hops so better for apps that ingress a lot external traffic. <br /><br />Traffic is not SNAT’d so actual client IPs are preserved. <br /><br />Traffic distributed among pods running a service may be imbalanced. | **LoadBalancer** (for cloud providers), or **NodePort** (for node’s static port) |

### Before you begin...

[Configure Calico to advertise cluster IPs over BGP]({{ site.baseurl }}/networking/advertise-service-ips).

### How to

Selecting which mode to use depends on your goals and resources. At an operational level, **local mode** simplifies policy, but load balancing may be uneven in certain scenarios. **Cluster mode** requires more work to manage clusterIPs, SNAT, and create policies that reference specific IP addresses, but you always get even load balancing.

- [Secure externally exposed cluster IPs, local mode](#secure-externally-exposed-cluster-ips-local-mode)
- [Secure externally exposed cluster IPs, cluster mode](#secure-externally-exposed-cluster-ips-cluster-mode)

#### Secure externally exposed cluster IPs, local mode

Using **local mode**, the original source address of external traffic is preserved, and you can define policy directly using standard {{site.prodname}} network policy.

1. Create {{site.prodname}} **NetworkPolicies** or **GlobalNetworkPolicies** that select the same set of pods as your Kubernetes Service.
1. Add rules to allow the external traffic.
1. If desired, add rules to allow in-cluster traffic.

#### Secure externally exposed cluster IPs, cluster mode

In the following steps, we define **GlobalNetworkPolicy** and **HostEndpoints**.

##### Step 1: Verify Kubernetes Service manifest

Ensure that your Kubernetes Service manifest explicitly lists the clusterIP; do not allow Kubernetes to automatically assign the clusterIP because you need it for your policies in the following steps.

##### Step 2: Create global network policy at the host interface

In this step, you create a **GlobalNetworkPolicy** that selects all **host endpoints**. It controls access to the cluster IP, and prevents unauthorized clients from outside the cluster from accessing it. The hosts then forwards only authorized traffic.

**Set policy to allow external traffic for cluster IPs**

Add rules to allow the external traffic for each clusterIP. The following example allows connections to two cluster IPs. Make sure you add **applyOnForward** and **preDNAT** rules.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-cluster-ips
spec:
  selector: k8s-role == 'node'
  types:
  - Ingress
  applyOnForward: true
  preDNAT: true
  ingress:
  # Allow 50.60.0.0/16 to access Cluster IP A
  - action: Allow
    source:
      nets:
      - 50.60.0.0/16
    destination:
      nets:
      - 10.20.30.40/32 # Cluster IP A
  # Allow 70.80.90.0/24 to access Cluster IP B
  - action: Allow
    source:
      nets:
      - 70.80.90.0/24
    destination:
      nets:
      - 10.20.30.41/32 # Cluster IP B
```

**Add a rule to allow traffic destined for the pod CIDR**

Without this rule, normal pod-to-pod traffic is blocked because the policy applies to forwarded traffic.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-to-pods
spec:
  selector: k8s-role == 'node'
  types:
  - Ingress
  applyOnForward: true
  preDNAT: true
  ingress:
  # Allow traffic forwarded to pods
  - action: Allow
    destination:
      nets:
      - 192.168.0.0/16 # Pod CIDR
```

**Add a rule to allow traffic destined for all host endpoints**

Or, you can add rules that allow specific host traffic including Kubernetes and {{site.prodname}}. Without this rule, normal host traffic is blocked.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-traffic-hostendpoints
spec:
  selector: k8s-role == 'node'
  types:
  - Ingress
  # Allow traffic to the node (not nodePorts, TCP)
  - action: Allow
    protocol: TCP
    destination:
      selector: k8s-role == 'node'
      notPorts: ["30000:32767"] # nodePort range
  # Allow traffic to the node (not nodePorts, UDP)
  - action: Allow
    protocol: UDP
    destination:
      selector: k8s-role == 'node'
      notPorts: ["30000:32767"] # nodePort range
```

##### Step 3: Create a global network policy that selects pods

In this step, you create a **GlobalNetworkPolicy** that selects the **same set of pods as your Kubernetes Service**. Add rules that allow host endpoints to access the service ports.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-nodes-svc-a
spec:
  selector: k8s-svc == 'svc-a'
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: k8s-role == 'node'
    destination:
      ports: [80, 443]
  - action: Allow
    protocol: UDP
    source:
      selector: k8s-role == 'node'
    destination:
      ports: [80, 443]
```

##### Step 4: (Optional) Create network polices or global network policies that allow in-cluster traffic to access the service

##### Step 5: Create HostEndpoints

Create HostEndpoints for the interface of each host that will receive traffic for the clusterIPs. Be sure to label them so they are selected by the policy in Step 2 (Add a rule to allow traffic destined for the pod CIDR), and the rules in Step 3.

In the previous example policies, the label **k8s-role: node** is used to identify these HostEndpoints.

### Above and beyond

- [Enable service IP advertisement]({{ site.baseurl }}/networking/advertise-service-ips)
- [Defend against DoS attacks]({{ site.baseurl }}/security/defend-dos-attack)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
