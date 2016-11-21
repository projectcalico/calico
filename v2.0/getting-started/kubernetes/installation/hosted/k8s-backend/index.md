---
title: Etcdless Hosted Install 
---

This document describes installing Calico on Kubernetes in a mode that does not require access to an etcd cluster.  Note that this feature is
still experimental and currently comes with a number of limitations, namely:

- Calico without etcd performs policy enforcement only and does not yet support Calico BGP networking.
- Calico without etcd does not yet support Calico IPAM.  It is recommended to use `host-local` IPAM in conjunction with Kubernetes pod CIDR assignments.
- Calico without etcd does not yet support the full set of `calicoctl` commands.

## Try it out

The provided manifest configures Calico to use host-local IPAM in conjunction with the Kubernetes assigned
pod CIDRs for each node.

First, ensure the following:

- You have a Kubernetes cluster configured to use CNI network plugins (i.e by passing `--network-plugin=cni`)
- Your Kubernetes controller manager is configured to allocate pod CIDRs (i.e by passing `--allocate-node-cidrs=true`)
- You have configured your network to route pod traffic based on pod CIDR allocations, either through static routes or a Kubernetes cloud-provder integration.

For example, you could install Kubernetes with Flannel using [kubeadm](http://kubernetes.io/docs/getting-started-guides/kubeadm/) and [kube-flannel](https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml).

Then to install Calico, run the following command:

```
kubectl apply -f http://docs.projectcalico.org/{{page.version}}/getting-started/kubernetes/installation/hosted/k8s-backend/calico.yaml
```

You download the manifest [here](calico.yaml) 

You can try out policy by following the [simple policy guide](../../../tutorials/simple-policy).

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

