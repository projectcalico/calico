---
title: Apply policy to Kubernetes node ports
---

### Big picture

Apply Calico network policy to Kubernetes node ports

### Value

Exposing services to external clients using node ports is a standard Kubernetes feature. However, if you want to restrict access to node ports to specific external clients, you need to use Calico global network policy.

### Features

This how-to guide uses the following Calico features:
- **GlobalNetwork policy** with a preDNAT field
- **HostEndpoint**

### Concepts

#### Calico global network policy with a preDNAT field 

In a Kubernetes cluster, kube-proxy will DNAT a request to the node's port and IP address, to one of the pods that backs the service. For Calico global network policy to both allow normal ingress cluster traffic, and deny other general ingress traffic, it must take effect before DNAT. To do this, you simply add a preDNAT field to a Calico global network policy. The preDNAT field:

- Applies only to ingress rules
- Enforces all ingress traffic through a host endpoint, regardless of destination.  
  The destination can be a locally hosted pod, a pod on another node, or a process running on the host. 


### Before you begin...

- For services that you want to expose to external clients, configure Kubernetes services with type **NodePort**. 
- Define Calico [host endpoints]({{site.baseurl}}/{{page.version}}/reference/resources/hostendpoint) for the Kubernetes nodes with network policy that is appropriate for your cluster.


### How to

To securely expose a Kubernetes service to external clients, you must implement all of the following steps. 

- [Allow cluster ingress traffic, but deny general ingress traffic](#allow-cluster-ingress-traffic,-but-deny-general-ingress-traffic)
- [Allow local host egress traffic](#allow-local-host-egress-traffic)
- [Create host endpoints with appropriate network policy](#create-host-endpoints-with-appropriate-network-policy)
- [Allow ingress traffic to specific node ports](#allow-ingress-traffic-to-specific-node-ports)

#### Allow cluster ingress traffic, but deny general ingress traffic

In the following example, we create a global network policy to allow cluster ingress traffic (**allow-cluster-internal-ingress**): for the nodes’ IP addresses (**1.2.3.4/16**), and for pod IP addresses assigned by Kubernetes (**100.100.100.0/16**). By adding a preDNAT field, Calico global network policy is applied before regular DNAT on the Kubernetes cluster. 

In this example, we use the **selector: has(host-endpoint)** -- so the policy is applicable to any endpoint with a **host-endpoint** label (but you can easily specify particular nodes). 

Finally, when you specify a preDNAT field, you must also add the **applyOnForward: true** field.

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-cluster-internal-ingress-only
spec:
  order: 20
  preDNAT: true
  applyOnForward: true
  ingress:
    - action: Allow
      source:
        nets: [1.2.3.4/16, 100.100.100.0/16]
        selector: has(host-endpoint)
    - action: Deny
```

#### Allow host local egress traffic   

We also need a global network policy to allow egress traffic through each node's external interface. Otherwise, when we define host endpoints for those interfaces, no egress traffic will be allowed from local processes (except for traffic that is allowed by the [Failsafe rules](({{site.baseurl}}/{{page.version}}/security/hostendpoint/failsaferules).

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-outbound-external
spec:
  order: 10
  egress:
    - action: Allow
  selector: has(host-endpoint)
```

#### Create host endpoints with appropriate policy

In this example, we assume that you have already defined Calico host endpoints with network policy that is appropriate for the cluster. (For example, you wouldn’t want a host endpoint with a “default deny all traffic to/from this host” network policy because that is counter to the goal of allowing/denying specific traffic.)

All of our previously-defined global network policies have a selector that makes them applicable to any endpoint with a **host-endpoint label**; so we will include that label in our definitions. For example, for **eth0** on **node1**.

```
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: node1-eth0
  labels:
    host-endpoint: ingress
spec:
  interfaceName: eth0
  node: node1
```

#### Allow ingress traffic to specific node ports

Now we can allow external access to the node ports by creating a global network policy with the preDNAT field. In this example, **ingress traffic is allowed** for any host endpoint with **port: 31852**.

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-nodeport
spec:
  preDNAT: true
  applyOnForward: true
  order: 10
  ingress:
    - action: Allow
      protocol: TCP
      destination:
        selector: has(host-endpoint)
        ports: [31852]
  selector: has(host-endpoint)
  ```

To make the NodePort accessible only through particular nodes, give the nodes a particular label. For example:

```
nodeport-external-ingress: true
```

Then, use **nodeport-external-ingress == ‘true’** as the selector of the **allow-nodeport** policy, instead of **has(host-endpoint)**.


### Above and beyond

[Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy) 
[Host Endpoints]({{site.baseurl}}/{{page.version}}/security/hostendpoints) 
