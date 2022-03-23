---
title: Configure calicoctl to connect to the Kubernetes API datastore
description: Sample configuration files for kdd.
canonical_url: '/maintenance/clis/calicoctl/configure/kdd'
---

### Big picture

Learn how to configure the calicoctl CLI tool for your Kubernetes cluster.

### Value

The `calicoctl` CLI tool provides helpful administrative commands for interacting with a {{site.prodname}} cluster.

### Concepts

#### calicoctl vs kubectl

In previous releases, calicoctl has been required to manage Calico API resources in the `projectcalico.org/v3` API group. The calicoctl CLI tool provides important validation and defaulting on these APIs. 

In newer releases, the Calico API server performs that defaulting and validation server-side, exposing the same API semantics without a dependency on calicoctl. For this reason, we recommend 
[installing the Calico API server]({{site.baseurl}}/maintenance/install-apiserver.md) and using `kubectl` instead of `calicoctl` for most operations.

calicoctl is still required for the following subcommands:

- [calicoctl node]({{site.baseurl}}/reference/calicoctl/node)
- [calicoctl ipam]({{site.baseurl}}/reference/calicoctl/ipam)
- [calicoctl convert]({{site.baseurl}}/reference/calicoctl/convert)
- [calicoctl version]({{site.baseurl}}/reference/calicoctl/version)

#### Default configuration

By default, calicoctl will attempt to read from the Kubernetes API using the default kubeconfig located at `$(HOME)/.kube/config`.

If the default kubeconfig does not exist, or you would like to specify alternative API access information, you can do so using the following configuration options.

### How to

#### Complete list of Kubernetes API connection configuration

| Configuration file option | Environment variable | Description                                                                                               | Schema
| --------------------------|----------------------| ----------------------------------------------------------------------------------------------------------|
| `datastoreType`           | `DATASTORE_TYPE`     | Indicates the datastore to use. [Default: `kubernetes`]                                                       | `kubernetes`, `etcdv3`
| `kubeconfig`              | `KUBECONFIG`         | When using the Kubernetes datastore, the location of a kubeconfig file to use, e.g. /path/to/kube/config. | string
| `k8sAPIEndpoint`          | `K8S_API_ENDPOINT`   | Location of the Kubernetes API. Not required if using kubeconfig. [Default: `https://kubernetes-api:443`] | string
| `k8sCertFile`             | `K8S_CERT_FILE`      | Location of a client certificate for accessing the Kubernetes API, e.g., `/path/to/cert`.                 | string
| `k8sKeyFile`              | `K8S_KEY_FILE`       | Location of a client key for accessing the Kubernetes API, e.g., `/path/to/key`.                          | string
| `k8sCAFile`               | `K8S_CA_FILE`        | Location of a CA for accessing the Kubernetes API, e.g., `/path/to/ca`.                                   | string
| `k8sToken`                |                      | Token to be used for accessing the Kubernetes API.                                                        | string


> **Note**: All environment variables may also be prefixed with `"CALICO_"`, for
> example `"CALICO_DATASTORE_TYPE"` and `"CALICO_KUBECONFIG"` etc. may be used.
> This is useful if the non-prefixed names clash with existing environment
> variables defined on your system.
{: .alert .alert-info}

#### Kubernetes command line

```bash
DATASTORE_TYPE=kubernetes KUBECONFIG=~/.kube/config calicoctl get nodes
```

#### Example configuration file

```yaml
apiVersion: projectcalico.org/v3
kind: CalicoAPIConfig
metadata:
spec:
  datastoreType: "kubernetes"
  kubeconfig: "/path/to/.kube/config"
```

#### Example using environment variables

```bash
export DATASTORE_TYPE=kubernetes
export KUBECONFIG=~/.kube/config
calicoctl get workloadendpoints
```

And using `CALICO_` prefixed names:

```bash
export CALICO_DATASTORE_TYPE=kubernetes
export CALICO_KUBECONFIG=~/.kube/config
calicoctl get workloadendpoints
```

With multiple `kubeconfig` files:

```bash
export DATASTORE_TYPE=kubernetes
export KUBECONFIG=~/.kube/main:~/.kube/auxy
calicoctl get --context main workloadendpoints
calicoctl get --context auxy workloadendpoints
```

#### Checking the configuration

Here is a simple command to check that the installation and configuration is
correct.

```bash
calicoctl get nodes
```

A correct setup will yield a list of the nodes that have registered.  If an
empty list is returned you are either pointed at the wrong datastore or no
nodes have registered.  If an error is returned then attempt to correct the
issue then try again.


### Next steps

Now you are ready to read and configure most aspects of {{site.prodname}}.  You can
find the full list of commands in the
[Command Reference]({{ site.baseurl }}/reference/calicoctl/overview).

The full list of resources that can be managed, including a description of each,
can be found in the
[Resource Definitions]({{ site.baseurl }}/reference/resources/overview).
