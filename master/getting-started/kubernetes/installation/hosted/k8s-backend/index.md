---
title: Calico without etcd 
---

This document describes a way of installing Calico on Kubernetes without requiring access to an etcd cluster for Calico.  Note that this feature is 
still experimental and currently comes with a number of limitations, namely:
- Calico without etcd performs policy enforcement only and does not yet support Calico BGP networking.
- Calico without etcd does not yet support Calico IPAM.  It is recommended to use `host-local` IPAM in conjunction with Kubernetes pod CIDR assignments.
- Calico without etcd does not yet support the full set of `calicoctl` commands.

[`calico.yaml`](calico.yaml) deploys Calico for network policy on Kubernetes without an etcd cluster.

## Try it out

The provided manifest configures Calico to use host-local IPAM in conjunction with the Kubernetes assigned
pod CIDRs for each node.  

Firt, ensure the following:
- You have a Kubernetes cluster configured to use CNI network plugins (i.e by passing `--network-plugin=cni`)
- Your Kubernetes controller manager is configured to allocate pod CIDRs (i.e by passing `--allocate-node-cidrs=true`)
- You have configured your network to route pod traffic based on pod CIDR allocations, either through static routes or a Kubernetes cloud-provder integration.

Then to install Calico, download [calico.yaml](calico.yaml) and run the following command:

```shell
kubectl apply -f calico.yaml
```

You can try out policy by following the [simple policy guide](../../../tutorials/simple-policy).

## How it works

Calico typically uses `etcd` to store information about Kubernetes Pods, Namespaces, and NetworkPolicies.  This information
is populated to etcd by the Calico CNI plugin and policy controller, and is interpreted by Felix and BIRD to program the dataplane on 
each host in the cluster.

The above manifest deploys Calico such that Felix uses the Kubernetes API directly to learn the required information to enforce policy, 
removing Calico's dependency on etcd and the need for the Calico kubernetes policy controller. 

The Calico CNI plugin is still required to configure each pod's virtual ethernet device and network namespace.

