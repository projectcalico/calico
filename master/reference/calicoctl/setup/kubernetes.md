---
title: Configuring calicoctl - Kubernetes datastore 
layout: docwithnav
---

This document covers the configuration options for calicoctl when using the Kubernetes API as a datastore.  

> **Note**
>
> This is an experimental feature. If running Calico on Kubernetes with the etcdv2 datastore, see the [etcdv2 configuration document](etcdv2) instead.
> For more information on running with the Kubernetes datastore, see [the installation guide](/{{page.version}}/getting-started/kubernetes/installation/hosted/k8s-backend/)

There are two ways to configure calicoctl with your Kubernetes API details: 
configuration file or environment variables.

## Configuration file 

By default `calicoctl` looks for a configuration file at `/etc/calico/calicoctl.cfg`.

The file location may be overridden using the `--config` option on commands that required
datastore access.

The config file is a yaml or json document in the following format:

```
apiVersion: v1
kind: calicoApiConfig
metadata:
spec:
  datastoreType: "kubernetes"
  k8sKubeconfig: "/path/to/kubeconfig"
  ...
```

See table below for details on the Kubernetes API specific fields that may be included in
the spec section.

If the file exists, then it must be valid and readable by calicoctl.  If the file
does not exist, calicoctl will read access details from the environment variables.

## Environment variables

If you are not using a config file to specify your access information, calicoctl
will check a particular set of environment variables.

See the table below for details on the Kubernetes specific environment variables.

>  Note that if neither file nor environment variables are set, calicoctl defaults to
>  using etcdv2 as the datastore with a single endpoint of http://127.0.0.1:2379.


## Complete list of Kubernetes API connection configuration

| Spec field              | Environment      | Description                                                        | Examples
|-------------------------|---------------------------------------------------------------------------------------|----------
| datastoreType           | DATASTORE_TYPE   | Indicates the datastore to use (required for kubernetes as the default is etcdv2) | kubernetes
| k8sKubeconfig           | KUBECONFIG       | When using the kubernetes datastore, the location of a kubeconfig file to use. | /path/to/kube/config 
| k8sServer               | K8S_API_ENDPOINT | Location of the Kubernetes API.  Not required if using kubeconfig. | https://kubernetes-api:443 
| k8sClientCertificate    | K8S_CERT_FILE    | Location of a client certificate for accessing the Kubernetes API. | /path/to/cert 
| k8sClientKey            | K8S_KEY_FILE     | Location of a client key for accessing the Kubernetes API.         | /path/to/key 
| k8sCertificateAuthority | K8S_CA_FILE      | Location of a CA for accessing the Kubernetes API.                 | /path/to/ca 
| k8sToken                | K8S_TOKEN        | Token to be used for accessing the Kubernetes API.                 |  

## Examples

#### Example configuration file

```yaml
apiVersion: v1
kind: calicoApiConfig
metadata:
spec:
  datastoreType: "kubernetes"
  k8sKubeconfig: "/path/to/.kube/config"
```

#### Example commands

```shell
$ export DATASTORE_TYPE=kubernetes 
$ export KUBECONFIG=~/.kube/config 
$ calicoctl get workloadendpoints
```

