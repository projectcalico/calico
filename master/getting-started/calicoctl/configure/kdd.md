---
title: Configuring calicoctl to connect to the Kubernetes API datastore
canonical_url: 'https://docs.projectcalico.org/v3.5/usage/calicoctl/configure/kdd'
---


## Complete list of Kubernetes API connection configuration

| Configuration file option | Environment variable | Description                                                                                               | Schema
| --------------------------|----------------------| ----------------------------------------------------------------------------------------------------------|
| `datastoreType`           | `DATASTORE_TYPE`     | Indicates the datastore to use. [Default: `etcdv3`]                                                       | `kubernetes`, `etcdv3`
| `kubeconfig`              | `KUBECONFIG`         | When using the Kubernetes datastore, the location of a kubeconfig file to use, e.g. /path/to/kube/config. | string
| `k8sAPIEndpoint`          | `K8S_API_ENDPOINT`   | Location of the Kubernetes API. Not required if using kubeconfig. [Default: `https://kubernetes-api:443`] | string
| `k8sCertFile`             |                      | Location of a client certificate for accessing the Kubernetes API, e.g., `/path/to/cert`.                 | string
| `k8sKeyFile`              |                      | Location of a client key for accessing the Kubernetes API, e.g., `/path/to/key`.                          | string
| `k8sCAFile`               |                      | Location of a CA for accessing the Kubernetes API, e.g., `/path/to/ca`.                                   | string
| `k8sToken`                |                      | Token to be used for accessing the Kubernetes API.                                                        | string


> **Note**: All environment variables may also be prefixed with `"CALICO_"`, for
> example `"CALICO_DATASTORE_TYPE"` and `"CALICO_KUBECONFIG"` etc. may be used.
> This is useful if the non-prefixed names clash with existing environment
> variables defined on your system.
{: .alert .alert-info}


## Examples

#### Kubernetes command line

```
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

```shell
export DATASTORE_TYPE=kubernetes
export KUBECONFIG=~/.kube/config
calicoctl get workloadendpoints
```

And using `CALICO_` prefixed names:

```shell
export CALICO_DATASTORE_TYPE=kubernetes
export CALICO_KUBECONFIG=~/.kube/config 
calicoctl get workloadendpoints
```


### Checking the configuration

Here is a simple command to check that the installation and configuration is
correct.

```
calicoctl get nodes
```

A correct setup will yield a list of the nodes that have registered.  If an
empty list is returned you are either pointed at the wrong datastore or no
nodes have registered.  If an error is returned then attempt to correct the
issue then try again.


### Next steps

Now you are ready to read and configure most aspects of {{site.prodname}}.  You can
find the full list of commands in the
[Command Reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/).

The full list of resources that can be managed, including a description of each,
can be found in the
[Resource Definitions]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/).
