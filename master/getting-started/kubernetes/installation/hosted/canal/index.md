---
title: Canal/flannel Hosted Install
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/canal/'
---

## About Canal

Canal allows users to easily deploy {{site.prodname}} and flannel networking
together as a unified networking solution—combining {{site.prodname}}’s
industry-leading network policy enforcement with the
[flannel](https://github.com/coreos/flannel#flannel)
overlay and non-overlay network connectivity options.

Note that Canal currently uses the {{site.prodname}} and flannel projects as is with
no code modifications to either. Canal is simply a deployment pattern
for installing and configuring the projects to work together seamlessly as a
single network solution from the point of view of the user and orchestration
system.


## Before you begin 

- Ensure that your cluster meets the {{site.prodname}} [System requirements](../../../requirements).
  An easy way to create a cluster which meets the requirements is by 
  following [the official kubeadm guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/).
  
- The Kubernetes controller manager must be started with
  `--cluster-cidr=10.244.0.0/16` and `--allocate-node-cidrs=true`. If using kubeadm, specifying 
  `--pod-network-cidr=10.244.0.0/16` sets these flags.

- If your Kubernetes cluster has RBAC enabled, you'll need to create RBAC roles 
  to allow API access by Canal. Apply the following manifest to create these 
  necessary RBAC roles and bindings.

   ```
   kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/rbac.yaml
   ```
   > **Note**: You can also [view the YAML in your browser.](rbac.yaml){:target="_blank"}.
   {: .alert .alert-info}
   

### Canal with the Kubernetes API datastore

The recommended Canal installation uses the Kubernetes API as the datastore,
the manifest below installs {{site.prodname}} and flannel configured to use the
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

