---
title: Kubernetes Datastore
sitemap: false 
---

This document describes how to install Calico on Kubernetes in a mode that does not require access to an etcd cluster.
This mode uses the Kubernetes API as the datastore.

Note that this feature currently comes with a number of limitations, namely:

- It does not yet support Calico IPAM.  It is recommended to use `host-local` IPAM in conjunction with Kubernetes pod CIDR assignments.
- It does not yet support per-node low-level Felix configuration - this must be handled using the Felix environment variables
  passed into the `calico/node` container (see [Configuring Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration)).
- Calico networking support is in Beta:
  -  Control of the node-to-node mesh, default AS Number and all BGP peering configuration should
     be configured using `calicoctl`.

## Requirements

The provided manifest configures Calico to use host-local IPAM in conjunction with the Kubernetes assigned
pod CIDRs for each node.

You must have a cluster which meets the following requirements:

- You are running Kubernetes `v1.7.0` or higher.
- You have a Kubernetes cluster configured to use CNI network plugins (i.e. by passing `--network-plugin=cni` to the kubelet)
- Your Kubernetes controller manager is configured to allocate pod CIDRs (i.e. by passing `--allocate-node-cidrs=true` to the controller manager)
- Your Kubernetes controller manager has been provided a cluster-cidr (i.e. by passing `--cluster-cidr=192.168.0.0/16`, which the manifest expects by default).

> Note:  If you are upgrading from Calico v2.1, the cluster-cidr selected for your controller manager should remain
> unchanged from the v2.1 install (the v2.1 manifests default to `10.244.0.0/16`).

> **Important**: If you are using the Kubernetes datastore and upgrading 
> from Calico v2.4.x or earlier to Calico v2.5.x or later, you must 
> [migrate your Calico configuration data](https://github.com/projectcalico/calico/blob/master/upgrade/v2.5/README.md) 
> before upgrading. Otherwise, your cluster may lose connectivity after the upgrade.
{: .alert .alert-danger}

## Installation

This document describes three installation options for Calico using Kubernetes API as the datastore:

1. Calico policy with Calico networking (beta)
2. Calico policy-only with user-supplied networking
3. Calico policy-only with flannel networking

Ensure you have a cluster which meets the above requirements.  There may be additional requirements based on the installation option you choose.

> Note:  There is currently no upgrade path to switch between different installation options.  Therefore,
> if you are upgrading from Calico v2.1, use the [Calico policy-only with user-supplied networking](#2-calico-policy-only-with-user-supplied-networking) installation instructions
> to upgrade Calico policy-only which leaves the networking solution unchanged.

### RBAC

Before you install Calico, if your Kubernetes cluster has RBAC enabled, you'll need to create the following
RBAC roles to allow API access to Calico.

Apply the following manifest to create these necessary RBAC roles and bindings.

>Note: The following RBAC policy is compatible with the Kubernetes v1.7+ manifests only.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
```

>[Click here to view the above yaml directly.](../rbac-kdd.yaml)

### 1. Calico policy with Calico networking (Beta)

With Kubernetes as the Calico datastore, Calico has Beta support for Calico networking.  This provides BGP-based
networking with a full node-to-node mesh and/or explicit configuration of peers.

To install Calico with Calico networking, run one of the commands below based on your Kubernetes version.
This will install Calico and will initially create a full node-to-node mesh.

> Note: Calico `v2.5.0` or higher with Kubernetes backend requires Kubernetes `v1.7.0` or higher.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml
```

>[Click here to view the above yaml directly.](calico-networking/1.7/calico.yaml)


#### Calico policy with Calico networking on kubeadm

The above manifests are compatible with kubeadm clusters initialized with a
pod-network-cidr matching the default pool of `192.168.0.0/16`, as follows:

```
kubeadm init --pod-network-cidr=192.168.0.0/16
```

#### Configuring your BGP topology (optional)

Some users running at high scale or on-premise may want to update Calico's BGP peering configuration using `calicoctl`.  For example,
you may wish to turn off the full node-to-node mesh and configure a pair of redundant route reflectors.

See the [Configuring BGP Peers guide]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp) for details on using `calicoctl`
to configure your topology.

### 2. Calico policy-only with user-supplied networking

If you run Calico in policy-only mode it is necessary to configure your network to route pod traffic based on pod
CIDR allocations, either through static routes, a Kubernetes cloud-provider integration, or flannel (self-installed).

To install Calico in policy-only mode, run one of the following commands based on your Kubernetes version:

> Note: Calico `v2.5.0` or higher with Kubernetes backend requires Kubernetes `v1.7.0` or higher.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/policy-only/1.7/calico.yaml
```

>[Click here to view the above yaml directly.](policy-only/1.7/calico.yaml)


### 3. Calico policy-only with flannel networking

The [Canal](https://github.com/projectcalico/canal) project provides a way to easily deploy
Calico with flannel networking.

Refer to the following [Kubernetes self-hosted install guide](https://github.com/projectcalico/canal/blob/master/k8s-install/README.md)
in the Canal project for details on installing Calico with flannel.

## Try it out

Once installed, you can try out NetworkPolicy by following the [simple policy guide](../../../tutorials/simple-policy).

Below are a few examples for how to get started.

## Configuration details

The following environment variable configuration options are supported by the various Calico components **when running without etcd**.

| Option                 | Description    | Examples
|------------------------|----------------|----------
| DATASTORE_TYPE         | Indicates the datastore to use | kubernetes
| KUBECONFIG             | When using the kubernetes datastore, the location of a kubeconfig file to use. | /path/to/kube/config
| K8S_API_ENDPOINT       | Location of the Kubernetes API.  Not required if using kubeconfig. | https://kubernetes-api:443
| K8S_CERT_FILE          | Location of a client certificate for accessing the Kubernetes API. | /path/to/cert
| K8S_KEY_FILE           | Location of a client key for accessing the Kubernetes API. | /path/to/key
| K8S_CA_FILE            | Location of a CA for accessing the Kubernetes API. | /path/to/ca
| K8S_TOKEN              | Token to be used for accessing the Kubernetes API. |

An example using `calicoctl`:

```shell
$ export DATASTORE_TYPE=kubernetes
$ export KUBECONFIG=~/.kube/config
$ calicoctl get workloadendpoints

HOSTNAME                       ORCHESTRATOR   WORKLOAD                                                         NAME
kubernetes-minion-group-tbmi   k8s            kube-system.kube-dns-v20-jhk10                                   eth0
kubernetes-minion-group-x7ce   k8s            kube-system.kubernetes-dashboard-v1.4.0-wtrtm                    eth0
```

## How it works

Calico typically uses `etcd` to store information about Kubernetes Pods, Namespaces, and NetworkPolicies.  This information
is populated to etcd by the Calico CNI plugin and policy controller, and is interpreted by Felix and BIRD to program the dataplane on
each host in the cluster.

The above manifest deploys Calico such that Felix uses the Kubernetes API directly to learn the required information to enforce policy,
removing Calico's dependency on etcd and the need for the Calico kubernetes policy controller.

The Calico CNI plugin is still required to configure each pod's virtual ethernet device and network namespace.
