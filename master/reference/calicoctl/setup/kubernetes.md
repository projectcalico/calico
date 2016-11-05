---
title: Configuring calicoctl - Kubernetes datastore 
layout: docwithnav
---

This document covers the configuration options for calicoctl when using the Kubernetes API as a datastore.  

> **Note**
>
> This is an experimental feature. If running Calico on Kubernetes with the etcdv2 datastore, see the [etcdv2 configuration document](etcdv2) instead.
> For more information on running with the Kubernetes datastore, see [the installation guide](/{{page.version}}/getting-started/kubernetes/installation/hosted/k8s-backend/)

## Environment Variables

The following environment variables are supported.

| Option                 | Description    | Examples
|------------------------|----------------|----------
| DATASTORE_TYPE         | Indicates the datastore to use | kubernetes, etcdv2 
| KUBECONFIG             | When using the kubernetes datastore, the location of a kubeconfig file to use. | /path/to/kube/config 
| K8S_API_ENDPOINT       | Location of the Kubernetes API.  Not required if using kubeconfig. | https://kubernetes-api:443 
| K8S_CERT_FILE          | Location of a client certificate for accessing the Kubernetes API. | /path/to/cert 
| K8S_KEY_FILE           | Location of a client key for accessing the Kubernetes API. | /path/to/key 
| K8S_CA_FILE            | Location of a CA for accessing the Kubernetes API. | /path/to/ca 
| K8S_TOKEN              | Token to be used for accessing the Kubernetes API. |  

#### Example commands

```shell
$ export DATASTORE_TYPE=kubernetes 
$ export KUBECONFIG=~/.kube/config 
$ calicoctl get workloadendpoints
```

