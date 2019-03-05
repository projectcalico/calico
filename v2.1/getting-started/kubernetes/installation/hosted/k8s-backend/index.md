---
title: Etcdless Hosted Install
---

This document describes installing Calico on Kubernetes in a mode that does not require access to an etcd cluster.
This mode uses the Kubernetes API as the datastore.  Note that this feature
currently comes with a number of limitations, namely:

- it supports policy enforcement only and does not yet support Calico BGP networking.
- it does not yet support Calico IPAM.  It is recommended to use `host-local` IPAM in conjunction with Kubernetes pod CIDR assignments.
- it does not yet support the full set of `calicoctl` commands.
- it does not yet support the full set of calico/node options (such as IP autodiscovery).

## Requirements

The provided manifest configures Calico to use host-local IPAM in conjunction with the Kubernetes assigned
pod CIDRs for each node.

You must have a cluster which meets the following requirements:

- You have a Kubernetes cluster configured to use CNI network plugins (i.e. by passing `--network-plugin=cni` to the kubelet)
- Your Kubernetes controller manager is configured to allocate pod CIDRs (i.e. by passing `--allocate-node-cidrs=true` to the controller manager)
- Your Kubernetes controller manager has been provided a cluster-cidr (i.e. by passing `--cluster-cidr=10.244.0.0/16`, which the manifest expects by default).
- You have configured your network to route pod traffic based on pod CIDR allocations, either through static routes, a Kubernetes cloud-provider integration, or flannel.

## Installation

To install Calico, ensure you have a cluster which meets the above requirements and run the following command:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/k8s-backend/calico.yaml
```

>[Click here to view the above yaml directly.](calico.yaml)

Once installed, you can try out NetworkPolicy by following the [simple policy guide](../../../tutorials/simple-policy).

Below are a few examples for how to get started.

#### Example: kubeadm + flannel

This example explains how to install Calico on kubeadm with flannel for routing.

Follow the [official kubeadm guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/).  For
steps that require it, follow the instructions for installing flannel as the pod network.

To initialize the master run

```
kubeadm init --pod-network-cidr=10.244.0.0/16
```

Then run the following command to install Calico.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/k8s-backend/calico.yaml
```

Then continue following the guide, following the instructions for installing flannel as the pod network.

#### Example: kube-up on GCE

This example explains how to install Calico for NetworkPolicy on GCE using kube-up.

See the [GCE documentation](http://kubernetes.io/docs/getting-started-guides/gce/#prerequisites) for
a list of requirements before starting.

##### 1) Start a Kubernetes cluster

Run the following commands to start a Kubernetes cluster on GCE configured to use CNI
network plugins.

```shell
export NETWORK_PROVIDER=cni
export KUBE_NODE_OS_DISTRIBUTION=debian
export KUBE_MASTER_OS_DISTRIBUTION=debian
curl -sS https://get.k8s.io | bash
```

##### 2) Install Calico using the etcdless manifest

Once the cluster is running, install Calico:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/k8s-backend/calico.yaml
```

You should see all pods enter "Running" state.

## Configuration details

The following environment variable configuration options are supported by the various Calico components **when running without etcd**.

| Option                 | Description    | Examples
|------------------------|----------------|----------
| DATASTORE_TYPE         | Indicates the datastore to use | kubernetes, etcdv2
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
