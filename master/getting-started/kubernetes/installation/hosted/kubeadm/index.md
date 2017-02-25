---
title: Kubeadm Hosted Install 
---

This document outlines how to install Calico, as well as a as single node 
etcd cluster for use by Calico on a Kubernetes cluster created by kubeadm.

Users who have deployed their own etcd cluster outside of kubeadm should 
use the [Calico only manifest](../hosted) instead, as it does not deploy its
own etcd. 

You can easily create a cluster compatible with this manifest by following [the official kubeadm guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/).


#### Installation 

To install this Calico and a single node etcd, run the following command:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubeadm/calico.yaml
```

You can download the addon manfiest [here](calico.yaml)

## About

This manifest deploys the standard Calico components described 
[here]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted) 
as well as a dedicated Calico etcd node on the Kubernetes master.  Note that in a production cluster, it is 
recommended you use a secure, replicated etcd cluster.

This manifest uses a node label to select the master node on which Calico's etcd is run. This label is configured
automatically on the master when using kubeadm.

To check if the required label is applied, run the following command:

```shell
$ kubectl get node <master_name> -o yaml | grep kubeadm
   kubeadm.alpha.kubernetes.io/role: master
```

### Requirements / Limitations

* This install does not configure etcd TLS
* This install expects that one Kubernetes master node has been labeled with `kubeadm.alpha.kubernetes.io/role: master`
* This install assumes no other pod network has been installed.
