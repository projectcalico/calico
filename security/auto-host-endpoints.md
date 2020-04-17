---
title: Protect Kubernetes nodes
description: Protect Kubernetes nodes with host endpoints managed by {{site.prodname}}
---

### Big picture

Secure Kubernetes nodes with host endpoints managed by {{site.prodname}}.

### Value

{{site.prodname}} can automatically create host endpoints for your Kubernetes nodes. The lifecycle of these host endpoints are managed by {{site.prodname}} in response to an evolving cluster to ensure policy protecting your nodes is always enforced.

### Features

This how-to guide uses the following Calico features:
- **HostEndpoint**
- **Profile**
- **KubeControllersConfiguration**
- **GlobalNetworkPolicy**

### Concepts

### Host endpoints

Each host has one or more network interfaces that it uses to communicate externally. You can use {{site.prodname}} network policy to secure these interfaces (called host endpoints).
{{site.prodname}} host endpoints can have labels, and they work the same as labels on workload endpoints. The network policy rules can apply to both workload and host endpoints using label selectors.

Host endpoints come in two types: _named_ and _wildcard_. Named host endpoints secure a specific interface such as "eth0", and are created by setting `interfaceName: <name-of-that-interface>` -- for example, `interfaceName: eth0`.
Wildcard host endpoints secure _all_ of the hosts interfaces non-workload interfaces.

### Automatic host endpoints

In order to protect a Kubernetes node, a host endpoint has to be created for it. This is fine for a few cluster nodes but for larger clusters of hundreds or thousands of nodes, some automation is required.
{{site.prodname}} can automatically create host endpoints for your Kubernetes nodes when they are created, and similarly tear down the host endpoints when the Kubernetes nodes leave the cluster.

{{site.prodname}} creates a `wildcard` host endpoint for each node, with the host endpoint containing the same labels and IP addresses as its corresponding node.
{{site.prodname}} will ensure these managed host endpoints maintain the same labels and IP addresses as its node by periodic syncs.
This means that policy targetting these automatic host endpoints will function correctly with the policy put in place to select those nodes, even if over time the node's IPs or labels change.

Automatic host endpoints are differentiated from other host endpoints by the label `projectcalico.org/created-by: calico-kube-controllers`.

### Profiles

Profiles are similar to network policy in that you can specify ingress and egress rules. But they are very limited and are deprecated for specifying policy rules; namespaced and global network policy are more flexible than profiles.

### Default behavior of external traffic to/from host

If a host endpoint (named or wildcard) is added and network policy is not in place, the {{site.prodname}} default is to deny traffic to/from that endpoint (except for traffic allowed by failsafe rules).
For named host endpoints, {{site.prodname}} blocks traffic only to/from interfaces that it’s been explicitly told about in network policy. Traffic to/from other interfaces is ignored.
For wildcard host endpoints, {{site.prodname}} blocks traffic to/from _all_ non-workload interfaces on the host (except for traffic allowed by failsafe rules).

However, profiles can be used in conjunction with host endpoints to modify default behavior of external traffic to/from the host in the absence of network policy.
{{site.prodname}} provides a default profile resource named `projectcalico-allow-all` that consists of allow-all ingress and egress rules.
Host endpoints with the `projectcalico-allow-all` profile attached will have "allow-all" semantics instead of "deny-all" in the absence of policy.

> Auto host endpoints have the `projectcalico-allow-all` profile attached and thus they allow all traffic in the absence of policy.
{: .alert .alert-info}

### Before you begin...

Have a running {{site.prodname}} cluster with calicoctl installed.

### How to

- [Enable automatic host endpoints](#enable-automatic-host-endpoints)
- [Restrict host egress to whitelisted IPs](#restrict-host-egress-to-whitelisted-ips)

#### Enable automatic host endpoints

In order to enable automatic host endpoints, we need to edit the `default` KubeControllersConfiguration instance.
We will be setting `spec.controllers.node.hostEndpoint.autoCreate` to `true`.

```bash
calicoctl patch kubecontrollersconfiguration default --patch='{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
```

If the apply was successful, we should see host endpoints created for each of your cluster's nodes:

```bash
calicoctl get heps -owide
```

The output may look similar to this:

```
$ calicoctl get heps -owide
NAME                                                    NODE                                           INTERFACE   IPS                              PROFILES
ip-172-16-101-147.us-west-2.compute.internal-auto-hep   ip-172-16-101-147.us-west-2.compute.internal   *           172.16.101.147,192.168.228.128
ip-172-16-101-54.us-west-2.compute.internal-auto-hep    ip-172-16-101-54.us-west-2.compute.internal    *           172.16.101.54,192.168.107.128
ip-172-16-101-79.us-west-2.compute.internal-auto-hep    ip-172-16-101-79.us-west-2.compute.internal    *           172.16.101.79,192.168.91.64
ip-172-16-101-9.us-west-2.compute.internal-auto-hep     ip-172-16-101-9.us-west-2.compute.internal     *           172.16.101.9,192.168.71.192
ip-172-16-102-63.us-west-2.compute.internal-auto-hep    ip-172-16-102-63.us-west-2.compute.internal    *           172.16.102.63,192.168.108.192
```

### Restrict host egress to whitelisted IPs

In order to whitelist egress to certain destination IP ranges, you will need to gather the IP ranges that your Kubernetes nodes must be able to reach.

The list of whitelisted IPs may include:
- the IP range used by your Kubernetes nodes. This is important especially so that each node's kubelet can reach the API server.
- the IP range for your Docker image registry

> Note: some Docker image registries do not maintain whitelists of IPs backing their registry DNS names.
> In that case, you may need to ensure that images are prepulled or available in an airgapped environment.
> Calico Enterprise provides extra network policy selectors such as a [domain name selector](https://docs.tigera.io/reference/resources/globalnetworkpolicy#exact-and-wildcard-domain-names)
> that manages the potentially dynamic IPs serving a particular DNS name.
{: .alert .alert-info}

For this tutorial, we will assume the following:
- Kubernetes nodes IP range is: 10.10.100.0/24
- External MySQL database static IP: 54.54.11.11/32
- Docker images are all available locally

With a set of whitelisted egress IPs in hand, we can apply the policy:

```
calicoctl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: all-nodes-restrict-egress
spec:
  selector: projectcalico.org/created-by == 'calico-kube-controllers'
  types:
  - Egress
  egress:
  - action: Deny
    destination:
      notNets:
      - 10.10.100.10/24
      - 54.54.11.11/32
  - action: Allow
EOF
```

Note that this policy does not affect egress from pods on the hosts. Host endpoints only enforce policy that originate from or terminate at the host.

### Above and beyond

- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) 
- [Host endpoints]({{ site.baseurl }}/reference/resources/hostendpoint)
