---
title: Standard Hosted Install
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/hosted/hosted'
---

The following steps install Calico as a Kubernetes add-on using your own etcd cluster.

## RBAC

If deploying Calico on an RBAC enabled cluster, you should first apply the `ClusterRole` and `ClusterRoleBinding` specs:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/rbac.yaml
```

## Install Calico

To install Calico:

1. Download [calico.yaml](calico.yaml)
2. Configure `etcd_endpoints` in the provided ConfigMap to match your etcd cluster.

Then simply apply the manifest:

```shell
kubectl apply -f calico.yaml
```

> **NOTE**
>
> Make sure you configure the provided ConfigMap with the location of your etcd cluster before running the above command.

## Configuration Options

The above manifest supports a number of configuration options documented [here](index#configuration-options)
