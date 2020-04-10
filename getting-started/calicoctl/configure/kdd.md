---
title: Configure calicoctl to connect to the Kubernetes API datastore
description: Sample configuration files for kdd.
canonical_url: '/getting-started/calicoctl/configure/kdd'
---

{% include content/cli-config-kdd.md %}

## Examples

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


### Checking the configuration

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
