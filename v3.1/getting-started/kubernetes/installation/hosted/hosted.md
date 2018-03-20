---
title: Standard Hosted Install
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/hosted'
---

The following steps install {{site.prodname}} as a Kubernetes add-on using your own etcd cluster.

## RBAC

If deploying {{site.prodname}} on an RBAC-enabled cluster, you should first apply the `ClusterRole` and `ClusterRoleBinding` specs:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/rbac.yaml
```

## Install {{site.prodname}}

To install {{site.prodname}}:

1. Download [calico.yaml](calico.yaml)

1. Configure `etcd_endpoints` in the provided ConfigMap to match your etcd cluster.

1. Apply the manifest:

   ```shell
   kubectl apply -f calico.yaml
   ```

> **Note**: Make sure you configure the provided ConfigMap with the 
> location of your etcd cluster before running the above command.
{: .alert .alert-info}


## Configuration Options

The above manifest supports a number of configuration options documented [here](index#configuration-options)
