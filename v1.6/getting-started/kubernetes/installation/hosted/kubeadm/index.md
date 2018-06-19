---
title: Install for Kubeadm
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/hosted/kubeadm/'
---

This document describes a single manifest for installing Calico on kubeadm managed 
Kubernetes clusters.  It is a specific case of the more general self-hosted 
install found [here]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted)

This install is designed to work for kubeadm clusters, or any cluster which labels 
a single master node with `kubeadm.alpha.kubernetes.io/role: master`.  This label is used for deploying
a single node etcd cluster.

- [`calico.yaml`](calico.yaml): Contains all the Calico components,
as well as Kubernetes objects to deploy a single node etcd cluster.

Then use kubectl to create the manifest below using kubectl:

```shell
kubectl create -f calico.yaml
```

You can download the addon manfiest [here](calico.yaml)

## About

This manifest deploys the standard Calico components described 
[here]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted) 
as well as a dedicated Calico etcd node on the Kubernetes master.  Note that in a production cluster, it is 
recommended you use a secure, replicated etcd cluster.

### Requirements / Limitations

* This install does not configure etcd TLS
* This install expects that your Kubernetes master node has been labeled with `kubeadm.alpha.kubernetes.io/role: master`
