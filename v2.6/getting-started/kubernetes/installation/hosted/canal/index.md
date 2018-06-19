---
title: Canal/flannel Hosted Install
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/kubernetes/installation/hosted/canal/'
---

## About Canal

Canal allow users to easily deploy Calico and flannel networking
together as a unified networking solution—combining Calico’s
industry-leading network policy enforcement with the
[flannel](https://github.com/coreos/flannel#flannel)
overlay and non-overlay network connectivity options.

Note that the Canal currently uses the Calico and flannel projects as is with
no code modifications to either. Canal is simply a deployment pattern
for installing and configuring the projects to work together seamlessly as a
single network solution from the point of view of the user and orchestration
system.


## Installation

When deploying your Kubernetes cluster, please make sure it meets the
[requirements](#requirements--limitations) at the bottom of this page.
An easy way to create a cluster which meets these requirements is by following
[the official kubeadm guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/).

> **Note:** If you are upgrading from the Kubernetes
[1.6](https://github.com/projectcalico/canal/blob/master/k8s-install/README.md#for-kubernetes-16)
or [1.5](https://github.com/projectcalico/canal/blob/master/k8s-install/README.md#kubernetes-15)
manifests from the (deprecated) Canal repo to the manifests here it is
neccessary to [migrate your Calico configuration
data](https://github.com/projectcalico/calico/blob/master/upgrade/v2.5/README.md)
before upgrading. Otherwise, your cluster may lose connectivity after the
upgrade.

### RBAC

Before you install Canal, if your Kubernetes cluster has RBAC enabled, you'll
need to create the following RBAC roles to allow API access by Canal.

Apply the following manifest to create these necessary RBAC roles and bindings.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/rbac.yaml
```
> **Note**: You can also [view the YAML in your browser.](rbac.yaml){:target="_blank"}.
{: .alert .alert-info}

### Canal with the Kubernetes API datastore

The recommended Canal installation uses the Kubernetes API as the datastore,
the manifest below installs Calico and flannel configured to use the
Kubernetes API.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/canal.yaml
```
> **Note**: You can also [view the YAML in your browser.](canal.yaml){:target="_blank"}.
{: .alert .alert-info}


### (or) Canal with etcd datastore

We strongly recommend using the Kubernetes API manifests above, but if you
have a need to use etcd we have provided an example etcd with TLS manifest
[`canal-etcd.yaml`](canal-etcd.yaml).

When using an etcd datastore, the provided manifest allows you to specify
the etcd endpoints for your etcd cluster, which must be configured
independently.

By default, the manifest expects an etcd proxy to be running on each
Kubernetes node at `http://127.0.0.1:2379`.


### Requirements / Limitations

- This install assumes no other pod network configurations have been installed
  in /etc/cni/net.d (or equivalent directory).
- The Kubernetes cluster must be configured to provide service account tokens to pods.
- kubelets must be started with `--network-plugin=cni` and have
  `--cni-conf-dir` and `--cni-bin-dir` properly set.
  - If using kubeadm these will be set by default.
- The Kubernetes controller manager must be started with
  `--cluster-cidr=10.244.0.0/16` and `--allocate-node-cidrs=true`.
  - If using kubeadm, specifying `--pod-network-cidr=10.244.0.0/16` will
    ensure the above flags are set.
- The service CIDR must not overlap with the cluster CIDR.
  - The default service CIDR is `10.96.0.0/12`.
  - The expected cluster CIDR is `10.244.0.0/16`.
  - If using kubeadm, the service CIDR can be set with the flag `--service-cidr`.
