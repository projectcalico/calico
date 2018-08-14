---
title: Configuring calicoctl - Kubernetes datastore
canonical_url: 'https://docs.projectcalico.org/v3.2/usage/calicoctl/configure/kdd'
---

This document covers the configuration options for calicoctl when using the Kubernetes API as a datastore.

> **Note**: If running Calico on Kubernetes with the etcdv2 
> datastore, see the [etcdv2 configuration document](etcdv2) instead.
> For more information on running with the Kubernetes datastore, see 
> [the installation guide](/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/).
>
{: .alert .alert-info}

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
  kubeconfig: "/path/to/kubeconfig"
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

> **Note**: If neither file nor environment variables are set, `calicoctl` defaults to
> using etcdv2 as the datastore with a single endpoint of http://127.0.0.1:2379.
{: .alert .alert-info}


## Complete list of Kubernetes API connection configuration

| Setting (Environment variable)    | Description                                                                                               | Schema
| --------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------
| datastoreType (DATASTORE_TYPE)    | Indicates the datastore to use (required for Kubernetes as the default is etcdv2). [Default: `etcdv2`]    | kubernetes, etcdv2
| kubeconfig (KUBECONFIG)           | When using the Kubernetes datastore, the location of a kubeconfig file to use, e.g. /path/to/kube/config. | string
| k8sAPIEndpoint (K8S_API_ENDPOINT) | Location of the Kubernetes API. Not required if using kubeconfig. [Default: `https://kubernetes-api:443`] | string
| k8sCertFile (K8S_CERT_FILE)       | Location of a client certificate for accessing the Kubernetes API, e.g. /path/to/cert.                    | string
| k8sKeyFile (K8S_KEY_FILE)         | Location of a client key for accessing the Kubernetes API, e.g. /path/to/key.                             | string
| k8sCAFile (K8S_CA_FILE)           | Location of a CA for accessing the Kubernetes API, e.g. /path/to/ca.                                      | string
| k8sToken (K8S_TOKEN)              | Token to be used for accessing the Kubernetes API.                                                        | string


> **Note**: All environment variables may also be prefixed with `"CALICO_"`, for
> example `"CALICO_DATASTORE_TYPE"` and `"CALICO_KUBECONFIG"` etc. may be used.
> This is useful if the non-prefixed names clash with existing environment
> variables defined on your system.
{: .alert .alert-info}


## Examples

#### Example configuration file

```yaml
apiVersion: v1
kind: calicoApiConfig
metadata:
spec:
  datastoreType: "kubernetes"
  kubeconfig: "/path/to/.kube/config"
```

#### Example using environment variables

```shell
$ export DATASTORE_TYPE=kubernetes
$ export KUBECONFIG=~/.kube/config
$ calicoctl get workloadendpoints
```

And using `CALICO_` prefixed names:

```shell
$ export CALICO_DATASTORE_TYPE=kubernetes
$ export CALICO_KUBECONFIG=~/.kube/config
$ calicoctl get workloadendpoints
```
