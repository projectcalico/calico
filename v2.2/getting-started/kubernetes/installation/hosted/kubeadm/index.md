---
title: Kubeadm Hosted Install
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/kubeadm/index'
---

This document outlines how to install Calico, as well as a as single node
etcd cluster for use by Calico on a Kubernetes cluster created by kubeadm.

Users who have deployed their own etcd cluster outside of kubeadm should
use the [Calico only manifest](../hosted) instead, as it does not deploy its
own etcd.

You can easily create a cluster compatible with this manifest by following [the official kubeadm guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/).


#### Installation

To install this Calico and a single node etcd on a run the following command
depending on your kubeadm / kubernetes version:

For Kubeadm 1.6 with Kubernetes 1.6.x:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubeadm/1.6/calico.yaml
```

>[Click here to view the above yaml directly.](1.6/calico.yaml)

For Kubeadm 1.5 with Kubernetes 1.5.x:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubeadm/1.5/calico.yaml
```

>[Click here to view the above yaml directly.](1.5/calico.yaml)

## Using calicoctl in a Kubeadm Cluster

The simplest way to use calicoctl in Kubeadm is by running it as a pod.
See [using calicoctl with Kubernetes](../../../tutorials/using-calicoctl#b-running-calicoctl-as-a-kubernetes-pod) for more information.

## About

This manifest deploys the standard Calico components described
[here]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted)
as well as a dedicated Calico etcd node on the Kubernetes master.  Note that in a production cluster, it is
recommended you use a secure, replicated etcd cluster.

This manifest uses a node label to select the master node on which Calico's etcd is run. This label is configured
automatically on the master when using kubeadm.

To check if the required label is applied, run the following command and
inspect the output for the correct label:

```shell
$ kubectl get node <master_name> -o yaml
```

### Requirements / Limitations

* This install does not configure etcd TLS
* This install expects that one Kubernetes master node has been labeled with:
  * For Kubeadm 1.5 `kubeadm.alpha.kubernetes.io/role: master`
  * For Kubeadm 1.6 `node-role.kubernetes.io/master: ""`
* This install assumes no other pod network has been installed.
* The CIDR(s) specified with the flag `--cluster-cidr` (pre 1.6) or
  `--pod-network-cidr` (1.6+) must match the Calico IP Pools to have Network
  Policy function correctly. The default is `192.168.0.0/16`.
* The CIDR specified with the flag `--service-cidr` should not overlap with the Calico IP Pool.
  * The default CIDR for `--service-cidr` is `10.96.0.0/12`.
  * The calico.yaml(s) linked sets the Calico IP Pool to `192.168.0.0/16`.
