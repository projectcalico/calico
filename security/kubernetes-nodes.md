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
We will apply two policies: one for the master nodes. and one for the worker nodes.

> Note: Run this tutorial only on a sandbox cluster; using it on a real cluster can disrupt traffic.
{: .alert .alert-danger }

> Note: This tutorial was tested on a cluster created with kubeadm v1.18.2 on AWS, using a "stacked etcd" [topology](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/ha-topology/). Stacked etcd topology means the etcd pods are running on the masters. kubeadm uses stacked etcd by default.
>
> If your Kubernetes cluster is on a different platform, is running a variant of Kubernetes, or is running a topology with an external etcd cluster,
> please review the required ports for master and worker nodes in your cluster and adjust the policies in this tutorial as needed.
{: .alert .alert-info }

First, let's restrict ingress traffic to the master nodes. The ingress policy below contains three rules.
The first rule allows access to the API server port from anywhere. The second rule allows access to the Kubernetes
control plane from localhost. These control plane processes includes the etcd server client API, the scheduler, and the controller-manager. This rule
also whitelists localhost access to the kubelet API and calico/node health checks. And the final rule allows the etcd pods
to peer with each other.

If you have not modified the failsafe ports, you should still have SSH access to the nodes after applying this policy.
Now apply the ingress policy for the Kubernetes masters:

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
  # This rule is required in multi-master clusters where etcd pods are colocated with the masters.
  # Allow the etcd pods on the masters to communicate with each other. 2380 is the etcd peer port.
  - action: Allow
    protocol: TCP
    source:
      selector: has(node-role.kubernetes.io/master)
    destination:
      ports:
      - 2380
EOF
```

Note that the above policy selects the standard Kubernetes label **node-role.kubernetes.io/master** attached to master nodes.

Next, we need to apply policy to restrict ingress to the Kubernetes workers.
Before adding the policy we will add a label to all of our worker nodes, which then gets added to its automatic host endpoint.
For this tutorial we will use **kubernetes-worker**. An example command to add the label to worker nodes:

```bash
kubectl get node -l '!node-role.kubernetes.io/master' -o custom-columns=NAME:.metadata.name | tail -n +2 | xargs -I{} kubectl label node {} kubernetes-worker=
```

The workers' ingress policy consists of two rules. As with the masters, the worker nodes need to access their kubelet API and calico/node healthcheck.
Now apply the policy:

```
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: workers
spec:
  selector: has(kubernetes-worker)
  # Allow kubelet API access from the docker API and allow calico/node health check.
  # An ephemeral port # is used by kubelet and docker for commands like 'kubectl exec'
  # to a pod on a worker node.
  # Note: This rule's port range will differ based on your system's ephemeral port range.
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      nets:
      - 127.0.0.1/32
      ports:
      # kubelet API
      - 10250
      - "32768:60999"
      # calico/node health check
      - 9099
  # Allow the masters access to the nodes kubelet API.
  - action: Allow
    protocol: TCP
    source:
      selector: has(node-role.kubernetes.io/master)
    destination:
      ports:
      - 10250
EOF
```

Now that the policies are in place, the final task is to update the **FailsafeInboundHostPorts** and remove unnecessary failsafe ports.
Without this step, the control plane is still accessible on ports 2379 and 2380.
First, get the current **FelixConfiguration**:

```bash
calicoctl get felixconfiguration default -oyaml --export > felixconfig.yaml
```

Next, edit the default FelixConfiguration failsafe inbound ports so it only has ports: tcp:22, udp:68, and tcp:179.
This removes the etcd-related ports from the failsafes. For example, the configuration may look as follows:

```
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  creationTimestamp: null
  name: default
spec:
  bpfLogLevel: ""
  ipipEnabled: true
  logSeverityScreen: Info
  reportingInterval: 0s
  failsafeInboundHostPorts:
  - protocol: tcp
    port: 22
  - protocol: udp
    port: 68
  - protocol: tcp
    port: 179
```

Finally, apply the updated configuration:

```
calicoctl apply -f - < felixconfig.yaml
```

### Above and beyond

- [Protect hosts tutorial]({{ site.baseurl }}/security/tutorials/protect-hosts)
- [Apply policy to Kubernetes node ports]({{ site.baseurl }}/security/kubernetes-node-ports)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) 
- [Host endpoints]({{ site.baseurl }}/reference/resources/hostendpoint)
