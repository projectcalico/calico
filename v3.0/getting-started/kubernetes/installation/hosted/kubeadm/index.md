---
title: kubeadm Hosted Install
---

This document outlines how to install Calico on a kubeadm cluster.
If you have already built your cluster with kubeadm, please review the
[Requirements / Limitations](#requirements--limitations) at the bottom of
this page. It is likely you will need to recreate your cluster with the
`--pod-network-cidr` and `--service-cidr` arguments to kubeadm.

## Installation

You can easily create a cluster compatible with these manifests by following [the official kubeadm guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/).

Calico installations require kubeadm initialized clusters to have set a `--pod-network-cidr`
which should match the value set by `CALICO_IPV4POOL_CIDR` in the manifest:

```yaml
- name: CALICO_IPV4POOL_CIDR
  value: "192.168.0.0/16"
```

This value can be changed to any CIDR that does not overlap the cluster's service CIDR.
The manifests are currently setup to use the CIDR `192.168.0.0/16` so you would initialize
the cluster with the following command:

```shell
kubeadm init --pod-network-cidr=192.168.0.0/16
```

### etcd datastore

Users who have deployed their own etcd cluster outside of kubeadm should
use the [Calico only manifest](../hosted) instead, as it does not deploy its
own etcd.

To install this Calico and a single node etcd on a run the following command:

> **Note**: The following manifest requires Kubernetes 1.6.0 or later.
{: .alert .alert-info}

```shell
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubeadm/1.6/calico.yaml
```

>[Click here to view the above yaml directly.](1.6/calico.yaml)

### Kubernetes datastore

To install Calico configured to use the Kubernetes API as its sole data source, run the following commands:

> **Note**: The following manifests require Kubernetes 1.7.0 or later.
{: .alert .alert-info}

```shell
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml
```

>[Click here to view the above RBAC yaml directly.](../rbac-kdd.yaml)
>
>[Click here to view the above Calico yaml directly.](../kubernetes-datastore/calico-networking/1.7/calico.yaml)

## Using calicoctl in a kubeadm cluster

The simplest way to use calicoctl in kubeadm is by running it as a pod.
See [using calicoctl with Kubernetes](../../../tutorials/using-calicoctl#b-running-calicoctl-as-a-kubernetes-pod) for more information.

### Requirements / Limitations

* This install assumes no other pod network configurations have been installed
  in /etc/cni/net.d (or equivilent directory).
* The CIDR(s) specified with the kubeadm flag `--cluster-cidr` (pre 1.6) or
  `--pod-network-cidr` (1.6+) must match the Calico IP Pools to have Network
  Policy function correctly. The default is `192.168.0.0/16`.
* The CIDR specified with the kubeadm flag `--service-cidr` should not overlap with the Calico IP Pool.
  * The default CIDR for `--service-cidr` is `10.96.0.0/12`.
  * The calico.yaml(s) linked sets the Calico IP Pool to `192.168.0.0/16`.
