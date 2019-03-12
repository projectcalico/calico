---
title: Standard Hosted Install 
canonical_url: 'https://docs.projectcalico.org/v3.6/getting-started/kubernetes/installation/hosted/hosted'
---

To install Calico as a Kubernetes add-on using your own etcd cluster:

1. Download [`calico.yaml`](calico.yaml)
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
