---
title: Protect Kubernetes nodes
Description: Protect Kubernetes nodes with host endpoints managed by Calico
---

### Big picture

Secure Kubernetes nodes with host endpoints managed by {{site.prodname}}.

### Value

{{site.prodname}} can automatically create host endpoints for your Kubernetes nodes. This means {{site.prodname}} can manage the lifecycle of host endpoints as your cluster evolves, ensuring nodes are always protected by policy.

### Features

This how-to guide uses the following Calico features:
- **HostEndpoint**
- **KubeControllersConfiguration**
- **GlobalNetworkPolicy**

### Concepts

### Host endpoints

Each host has one or more network interfaces that it uses to communicate externally. You can represent these interfaces in Calico using host endpoints and then use network policy to secure them.

{{site.prodname}} host endpoints can have labels, and they work the same as labels on workload endpoints. The network policy rules can apply to both workload and host endpoints using label selectors.

Automatic host endpoints secure _all_ of the hosts interfaces non-workload interfaces. They are created by setting `interfaceName: "*"`.

### Automatic host endpoints

{{site.prodname}} creates a wildcard host endpoint for each node, with the host endpoint containing the same labels and IP addresses as its corresponding node.
{{site.prodname}} will ensure these managed host endpoints maintain the same labels and IP addresses as its node by periodic syncs.
This means that policy targeting these automatic host endpoints will function correctly with the policy put in place to select those nodes, even if over time the node's IPs or labels change.

Automatic host endpoints are differentiated from other host endpoints by the label `projectcalico.org/created-by: calico-kube-controllers`.
Enable or disable automatic host endpoints by configuring the default KubeControllersConfiguration resource.

### Before you begin...

Have a running {{site.prodname}} cluster with `calicoctl` installed.

### How to

- [Enable automatic host endpoints](#enable-automatic-host-endpoints)
- [Restrict host egress to whitelisted IPs](#restrict-host-egress-to-whitelisted-ips)

#### Enable automatic host endpoints

To enable automatic host endpoints, edit the default KubeControllersConfiguration instance, and set `spec.controllers.node.hostEndpoint.autoCreate` to `true`:

```bash
calicoctl patch kubecontrollersconfiguration default --patch='{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
```

If successful, host endpoints are created for each of your cluster's nodes:

```bash
calicoctl get heps -owide
```

The output may look similar to this:

```
$ calicoctl get heps -owide
NAME                                                    NODE                                           INTERFACE   IPS                              PROFILES
ip-172-16-101-147.us-west-2.compute.internal-auto-hep   ip-172-16-101-147.us-west-2.compute.internal   *           172.16.101.147,192.168.228.128   projectcalico-default-allow
ip-172-16-101-54.us-west-2.compute.internal-auto-hep    ip-172-16-101-54.us-west-2.compute.internal    *           172.16.101.54,192.168.107.128    projectcalico-default-allow
ip-172-16-101-79.us-west-2.compute.internal-auto-hep    ip-172-16-101-79.us-west-2.compute.internal    *           172.16.101.79,192.168.91.64      projectcalico-default-allow
ip-172-16-101-9.us-west-2.compute.internal-auto-hep     ip-172-16-101-9.us-west-2.compute.internal     *           172.16.101.9,192.168.71.192      projectcalico-default-allow
ip-172-16-102-63.us-west-2.compute.internal-auto-hep    ip-172-16-102-63.us-west-2.compute.internal    *           172.16.102.63,192.168.108.192    projectcalico-default-allow
```

#### Apply network policy to automatic host endpoints

Automatic host endpoints share the common label `projectcalico.org/created-by: calico-kube-controllers`.
To write policy that targets all Kubernetes nodes, use that label:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: all-nodes-policy
spec:
  selector: projectcalico.org/created-by == 'calico-kube-controllers'
  <rest of the policy>
```

To select a specific set of host endpoints (and their corresponding Kubernetes nodes), use a policy selector that selects a label unique to that set of host endpoints.
We can take advantage of the syncing of node labels to automatic host endpoints and label that set of nodes with a unique key/value pair.
For example, if we want to add the label `environment=dev` to nodes named `node1` and `node2`:

```bash
kubectl label node node1 environment=dev
kubectl label node node2 environment=dev
```

With the labels in place and automatic host endpoints enabled, hostendpoints for node1 and node2 will be updated with the `environment=dev` label.
We can write policy to select that set of nodes with a combination of selectors:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: all-nodes-policy
spec:
  selector: projectcalico.org/created-by == 'calico-kube-controllers' && environment == 'dev'
  <rest of the policy>
```

#### Restrict host ingress

This tutorial will lock down Kubernetes node ingress to only allow SSH and required ports for Kubernetes to function.

> Note: Do not run this tutorial on a cluster that is important. This tutorial may disrupt traffic in your cluster.
> Only run this tutorial on a sandbox cluster.
{: .alert .alert-danger }

First, let's restrict ingress traffic to the master nodes from outside the cluster only to the Kubernetes API server and Kubelet API ports.
If you have not modified the failsafe ports, we should still have access to SSH to the nodes after applying this policy.

```bash
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-all-to-masters
spec:
  selector: has(node-role.kubernetes.io/master)
  order: 100
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports:
      # kubelet API
      - 10250
      # kube API server
      - 6443
  - action: Allow
    protocol: UDP
    destination:
      ports: [53]
  egress:
  - action: Allow
EOF
```

Note that the above policy selects the standard Kubernetes label *node-role.kubernetes.io/master* attached to master nodes.

Next apply policy that allows ingress traffic between the masters on certain ports.
In addition to allowing the Kubernetes API server and Kubelet API ports, we also allow the 
master nodes to access the etcd server client API and the other Kubernetes control plane processes.

```bash
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-master-to-master
spec:
  selector: has(node-role.kubernetes.io/master)
  order: 200
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: has(node-role.kubernetes.io/master)
    destination:
      ports:
      # kubelet API
      - 10250
      # kube API server
      - 6443
      # etcd server client API
      - "2379:2381"
      # kube-scheduler
      - 10251
      - 10259
      # kube-controller-manager
      - 10252
      - 10257
  egress:
  - action: Allow
EOF
```

Now apply a policy similar to the above that allows traffic coming into the loopback device at 127.0.0.1.
This allows the masters to reach local Kubernetes control plane processes. 

```bash
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-master-to-master-local
spec:
  selector: has(node-role.kubernetes.io/master)
  order: 200
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      nets:
      - 127.0.0.1/32
      ports:
      # kubelet API
      - 10250
      # kube API server
      - 6443
      # etcd server client API
      - "2379:2381"
      # kube-scheduler
      - 10251
      - 10259
      # kube-controller-manager
      - 10252
      - 10257
      # calico/node health check
      - 9099
  egress:
  - action: Allow
EOF
```

Lastly, we need to allow all Kubernetes nodes access to their own Kubelet API.
Before adding the policy we will add a label to all of our nodes, which then gets added to its automatic host endpoint.
For this example we will use *kubernetes-host*:

``bash
kubectl label nodes --all kubernetes-host=
```

Finally we can apply policy that selects all Kubernetes nodes:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-nodes-to-kublet
spec:
  selector: has(kubernetes-host)
  order: 200
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: has(kubernetes-host)
    destination:
      ports:
      # kubelet API
      - 10250
  egress:
  - action: Allow
EOF
```

- [Protect hosts tutorial]({{ site.baseurl }}/security/tutorials/protect-hosts)
- [Apply policy to Kubernetes node ports]({{ site.baseurl }}/security/kubernetes-node-ports)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) 
- [Host [[endpoints]]]({{ site.baseurl }}/reference/resources/hostendpoint)
