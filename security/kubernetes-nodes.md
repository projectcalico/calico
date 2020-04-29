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
- [Apply network policy to automatic host endpoints](#apply-network-policy-to-automatic-host-endpoints)

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

To apply policy that targets all Kubernetes nodes, first add a label to the nodes.
The label will be synced to their automatic host endpoints.

For example, to add the label **kubernetes-host** to all nodes and their host endpoints:

```bash
kubectl label nodes --all kubernetes-host=
```

And an example policy snippet:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: all-nodes-policy
spec:
  selector: has(kubernetes-host)
  <rest of the policy>
```

To select a specific set of host endpoints (and their corresponding Kubernetes nodes), use a policy selector that selects a label unique to that set of host endpoints.
For example, if we want to add the label **environment=dev** to nodes named node1 and node2:

```bash
kubectl label node node1 environment=dev
kubectl label node node2 environment=dev
```

With the labels in place and automatic host endpoints enabled, host endpoints for node1 and node2 will be updated with the **environment=dev** label.
We can write policy to select that set of nodes with a combination of selectors:

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: some-nodes-policy
spec:
  selector: has(kubernetes-host) && environment == 'dev'
  <rest of the policy>
```

### Tutorial

This tutorial will lock down Kubernetes node ingress to only allow SSH and required ports for Kubernetes to function.

> Note: Run this tutorial only on a sandbox cluster; using it on a real cluster can disrupt traffic.
{: .alert .alert-danger }

First, let's restrict ingress traffic to the master nodes. The ingress policy below contains two rules.
The first rule allows access to the API server port from anywhere. The second rule allows access to the Kubernetes
control plane from localhost. These control plane processes includes the etcd server client API, the scheduler, and the controller-manager. This rule
also whitelists localhost access to the kubelet API and calico/node health checks.

If you have not modified the failsafe ports, we should still have access to SSH to the nodes after applying this policy.

```
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: ingress-k8s-masters
spec:
  selector: has(node-role.kubernetes.io/master)
  # This rule allows ingress to the Kubernetes API server.
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports:
      # kube API server
      - 6443
  # This rule allows traffic to Kubernetes control plane ports
  # from localhost. The health check port for calico/node is also whitelisted
  - action: Allow
    protocol: TCP
    destination:
      nets:
      - 127.0.0.1/32
      ports:
      # etcd server client API
      - "2379:2381"
      # kube-scheduler
      - 10251
      - 10259
      # kube-controller-manager
      - 10252
      - 10257
      # kubelet API
      - 10250
      # calico/node health check
      - 9099
EOF
```

Note that the above policy selects the standard Kubernetes label **node-role.kubernetes.io/master** attached to master nodes.

Lastly, we need to allow all Kubernetes nodes access to their own Kubelet API and calico/node health check.
Before adding the policy we will add a label to all of our nodes, which then gets added to its automatic host endpoint.
For this example we will use **kubernetes-host**:

```bash
kubectl label nodes --all kubernetes-host=
```

Finally we can apply policy that selects all Kubernetes nodes:

```
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: ingress-k8s-nodes
spec:
  selector: has(kubernetes-host)
  order: 300
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      nets:
      - 127.0.0.1/32
      ports:
      # kubelet API
      - 10250
      # calico/node health check
      - 9099
EOF
```

### Above and beyond

- [Protect hosts tutorial]({{ site.baseurl }}/security/tutorials/protect-hosts)
- [Apply policy to Kubernetes node ports]({{ site.baseurl }}/security/kubernetes-node-ports)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) 
- [Host [[endpoints]]]({{ site.baseurl }}/reference/resources/hostendpoint)
