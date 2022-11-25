---
title: The Calico datastore
description: The central datastore for your clusters' operational and configuration state.
canonical_url: '/getting-started/kubernetes/hardway/the-calico-datastore'
---

{{site.prodname}} stores the data about the operational and configuration state of your cluster in a central datastore. If the datastore is unavailable
your {{site.prodname}} network continues operating, but cannot be updated (no new pods can be networked, no policy changes can be applied, etc.).

{{site.prodname}} has two datastore drivers you can choose from

- **etcd** - for direct connection to an etcd cluster
- **Kubernetes** - for connection to a Kubernetes API server

## Using Kubernetes as the datastore

This guide uses the Kubernetes API datastore driver. The advantages of this driver when using {{site.prodname}} on Kubernetes are

- Doesn't require an extra datastore, so is simpler to manage
- You can use Kubernetes RBAC to control access to {{site.prodname}} resources
- You can use Kubernetes audit logging to generate audit logs of changes to {{site.prodname}} resources

For completeness, the advantages of the etcd driver are

- Allows you to run {{site.prodname}} on non-Kubernetes platforms (e.g. OpenStack)
- Allows separation of concerns between Kubernetes and {{site.prodname}} resources, for example allowing you to scale the datastores independently
- Allows you to run a {{site.prodname}} cluster that contains more than just a single Kubernetes cluster, for example, bare metal servers with {{site.prodname}}
  host protection interworking with a Kubernetes cluster; or multiple Kubernetes clusters.

## Custom Resources

When using the Kubernetes API datastore driver, most {{site.prodname}} resources are stored as {% include open-new-window.html text='Kubernetes custom resources' url='https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/' %}.

A few {{site.prodname}} resources are not stored as custom resources and instead are backed by corresponding native Kubernetes resources. For example, [workload endpoints](/reference/resources/workloadendpoint) are Kubernetes pods.

In order to use Kubernetes as the {{site.prodname}} datastore, we need to define the custom resources {{site.prodname}} uses.

Download and examine the list of {{site.prodname}} custom resource definitions, and open it in a file editor.

```
wget {{site.data.versions.first.manifests_url}}/manifests/crds.yaml
```

Create the custom resource definitions in Kubernetes.

```
kubectl apply -f crds.yaml
```

## calicoctl

To interact directly with the {{site.prodname}} datastore, use the `calicoctl` client tool.

### Install

1. Download the `calicoctl` binary to a Linux host with access to Kubernetes.

   ```bash
   wget https://github.com/projectcalico/calicoctl/releases/download/v3.20.0/calicoctl
   chmod +x calicoctl
   sudo mv calicoctl /usr/local/bin/
   ```

1. Configure `calicoctl` to access Kubernetes.

   ```bash
   export KUBECONFIG=/path/to/your/kubeconfig
   export DATASTORE_TYPE=kubernetes
   ```

   On most systems, kubeconfig is located at `~/.kube/config`. You may wish to add the `export` lines to your `~/.bashrc` so they will persist when you log in next time.

### Test

Verify `calicoctl` can reach your datastore by running

```bash
calicoctl get nodes
```

You should see output similar to

```
NAME
ip-172-31-37-123
ip-172-31-40-217
ip-172-31-40-30
ip-172-31-42-47
ip-172-31-45-29
```

Nodes are backed by the Kubernetes node object, so you should see names that match `kubectl get nodes`.

Try to get an object backed by a custom resource

```bash
calicoctl get ippools
```

You should see an empty result

```
NAME   CIDR   SELECTOR

```

## Next

[Configure IP pools](./configure-ip-pools)
