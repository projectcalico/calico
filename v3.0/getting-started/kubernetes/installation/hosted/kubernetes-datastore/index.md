---
title: Kubernetes API datastore
canonical_url: https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/
---

This document describes how to install {{site.prodname}} on Kubernetes without a separate etcd cluster.
In this mode, {{site.prodname}} uses the Kubernetes API directly as the datastore.

Note that this mode currently comes with a number of limitations, namely:

- It does not yet support Calico IPAM.  It is recommended to use `host-local` IPAM in conjunction with Kubernetes pod CIDR assignments.
- {{site.prodname}} networking support is in beta. Control of the node-to-node mesh, default AS Number and all BGP peering configuration should be configured using `calicoctl`.

## Requirements

The provided manifest configures {{site.prodname}} to use host-local IPAM in conjunction with the Kubernetes assigned
pod CIDRs for each node.

You must have a Kubernetes cluster, which meets the following requirements:

- Running Kubernetes `v1.7.0` or higher.
- Configured to use CNI network plugins (i.e., by passing `--network-plugin=cni` to the kubelet).
- Kubernetes controller manager is configured to allocate pod CIDRs (i.e., by passing `--allocate-node-cidrs=true` to the controller manager).
- Kubernetes controller manager has been provided a cluster-cidr, for example:
  - If using kubeadm, by passing `--pod-network-cidr=192.168.0.0/16` to `kubeadm`.
  - Otherwise, by passing `--cluster-cidr=192.168.0.0/16` directly to the controller manager.


## Installation

This document describes two installation options for {{site.prodname}} using Kubernetes API as the datastore:

1. {{site.prodname}} policy with {{site.prodname}} networking (beta)
2. {{site.prodname}} policy-only with user-supplied networking

Ensure you have a cluster which meets the above requirements.  There may be additional requirements based on the installation option you choose.

> **Note**: There is currently no upgrade path to switch between
> different installation options. Therefore, if you are upgrading
> from Calico v2.1, use the
> [Calico policy-only with user-supplied networking](#policy-only)
> installation instructions to upgrade Calico policy-only which
> leaves the networking solution unchanged.
{: .alert .alert-info}

### Before you start: if your cluster has RBAC enabled

Install {{site.prodname}}'s RBAC manifest, which creates roles and role bindings for {{site.prodname}}'s components:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
```
   > **Note**: You can also
   > [view the YAML in your browser](../rbac-kdd.yaml){:target="_blank"}.
   {: .alert .alert-info}

### Option 1: {{site.prodname}} policy with {{site.prodname}} networking (beta)

When using the Kubernetes API datastore, {{site.prodname}} has beta support for
{{site.prodname}} networking.  This provides BGP-based networking with a full node-to-node
mesh and/or explicit configuration of peers.  (The "beta" label is because Calico IPAM is
not yet supported.)

To install {{site.prodname}} with BGP networking:

1. Download [the {{site.prodname}} networking manifest](calico-networking/1.7/calico.yaml)

2. If your Kubernetes cluster contains more than 50 nodes, or it is likely to grow to
   more than 50 nodes, edit the manifest to [enable Typha](#enabling-typha).

3. Make sure your cluster CIDR matches the `CALICO_IPV4POOL_CIDR` environment variable in the manifest.
   The cluster CIDR is configured by the  `--cluster-cidr` option passed to the Kubernetes
   controller manager.  If you are using `kubeadm` that option is controlled by `kubeadm`'s
   `--pod-network-cidr` option.

   > **Note**: {{site.prodname}} only uses the `CALICO_IPV4POOL_CIDR` variable if there is no
   > IP pool already created.  Changing the variable after the first node has started has no
   > effect.
   {: .alert .alert-info}

4. Apply the manifest: `kubectl apply -f calico.yaml`

5. If your Kubernetes cluster has more than 100 nodes, we recommend disabling the
   node-to-node BGP mesh and configuring a pair of redundant route reflectors.
   Due to limitations in the Kubernetes API, maintaining the node-to-node mesh
   uses significant CPU (in the `confd` process on each host and the API server)
   as the number of nodes increases.

   Alternatively, if you're running on-premise, you may want to configure Calico
   to peer with your BGP infrastructure.

   In either case, see the [Configuring BGP Peers guide]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp)
   for details on using `calicoctl` to configure your topology.

### <a name="policy-only"></a> Option 2: {{site.prodname}} policy-only with user-supplied networking

If you run {{site.prodname}} in policy-only mode it is necessary to configure your network to route pod traffic based on pod
CIDR allocations, either through static routes, a Kubernetes cloud-provider integration, or flannel (self-installed).

To install {{site.prodname}} in policy-only mode:

1. Download [the policy-only manifest](policy-only/1.7/calico.yaml)

2. If your Kubernetes cluster contains more than 50 nodes, or it is likely to grow to
   more than 50 nodes, edit the manifest to [enable Typha](#enabling-typha).

3. Make sure your cluster CIDR matches the `CALICO_IPV4POOL_CIDR` environment variable in the manifest.
   The cluster CIDR is configured by the  `--cluster-cidr` option passed to the Kubernetes
   controller manager.  If you are using `kubeadm` that option is controlled by `kubeadm`'s
   `--pod-network-cidr` option.

   > **Note**: {{site.prodname}} only uses the `CALICO_IPV4POOL_CIDR` variable if there is no
   > IP pool already created.  Changing the variable after the first node has started has no
   > effect.
   {: .alert .alert-info}

4. Apply the manifest: `kubectl apply -f calico.yaml`

### Enabling Typha

{{site.prodname}}'s Typha component helps {{site.prodname}} scale to high numbers of
nodes without over-taxing the Kubernetes API server.  It sits between Felix ({{site.prodname}}'s
per-host agent) and the API server, as fan-out proxy.

> **Important**: Typha runs as a host-networked pod and it opens a port on the host for Felix
> to connect to.  If your cluster runs in an untrusted environment, you **must** take steps to secure that
> port so that only your Kubernetes nodes can access it.  You may wish to add a `nodeSelector` to the
> manifest to control where Typha runs (for example on the master) and then use {{site.prodname}} host protection
> to secure those hosts.
{: .alert .alert-danger}

We recommend enabling Typha if you have more than 50 Kubernetes nodes in your cluster.  Without Typha, the
load on the API server and Felix's CPU usage increases substantially as the number of nodes is increased.
In our testing, beyond 100 nodes, both Felix and the API server use an unacceptable amount of CPU.

To enable Typha in either the {{site.prodname}} networking manifest or the policy only manifest:

1. Change the `typha_service_name` variable in the ConfigMap from `"none"` to `"calico-typha"`.

2. Modify the replica count in the `calico-typha` Deployment section to the desired number of replicas:

   ```
   apiVersion: apps/v1beta1
   kind: Deployment
   metadata:
     name: calico-typha
     ...
   spec:
     ...
     replicas: <number of replicas>
   ```

   We recommend starting at least one replica for every 200 nodes and, at most, 20 replicas (since each
   replica places some load on the API server).

   In production, we recommend starting at least 3 replicas to reduce the impact of rolling upgrades
   and failures.

> **Note**: If you set `typha_service_name` without increasing the replica count from its default
> of `0` Felix will fail to start because it will try to connect to Typha but there
> will be no Typha instances to connect to.
{: .alert .alert-info}

## Try it out

Once installed, you can try out NetworkPolicy by following the [simple policy guide](../../../tutorials/simple-policy).


## How it works

{{site.prodname}} typically uses `etcd` to store information about Kubernetes pods, namespaces, and network policies.  This information
is populated to etcd by the CNI plugin and the Kubernetes controllers, and is interpreted by Felix and BIRD to program the dataplane on
each host in the cluster.

The above manifest deploys {{site.prodname}} such that Felix uses the Kubernetes API directly to learn the required information to enforce policy,
removing {{site.prodname}}'s dependency on etcd and the need for the Kubernetes controllers.

The CNI plugin is still required to configure each pod's virtual ethernet device and network namespace.
