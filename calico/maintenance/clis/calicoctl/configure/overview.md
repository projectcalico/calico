---
title: Configure calicoctl
description: Configure calicoctl for datastore access.
canonical_url: '/maintenance/clis/calicoctl/configure/index'
---

### Big picture

Learn how to configure the calicoctl CLI tool for your cluster.

### Value

The `calicoctl` CLI tool provides helpful administrative commands for interacting with a {{site.prodname}} cluster.

### Concepts

#### calicoctl vs kubectl

In previous releases, calicoctl has been required to manage Calico API resources in the `projectcalico.org/v3` API group. The calicoctl CLI tool provides important validation and defaulting on these APIs. 

In newer releases, the Calico API server performs that defaulting and validation server-side, exposing the same API semantics without a dependency on calicoctl. For this reason, we recommend 
[installing the Calico API server]({{site.baseurl}}/maintenance/install-apiserver) and using `kubectl` instead of `calicoctl` for most operations.

calicoctl is still required for the following subcommands:

- [calicoctl node]({{site.baseurl}}/reference/calicoctl/node)
- [calicoctl ipam]({{site.baseurl}}/reference/calicoctl/ipam)
- [calicoctl convert]({{site.baseurl}}/reference/calicoctl/convert)
- [calicoctl version]({{site.baseurl}}/reference/calicoctl/version)

calicoctl is also required for non-Kubernetes platforms such as OpenStack.

#### Default calicoctl behavior

Most `calicoctl` commands require access to the {{site.prodname}} datastore. By default, calicoctl
will attempt to read from the Kubernetes API based on the default kubeconfig.

### How to

#### Configure access using a Configuration file

By default, `calicoctl` will look for a configuration file at `/etc/calico/calicoctl.cfg`. You can override this using the `--config` option with commands that require datastore access. 
The file can be in either YAML or JSON format. It must be valid and readable by `calicoctl`. For example:

   ```
   apiVersion: projectcalico.org/v3
   kind: CalicoAPIConfig
   metadata:
   spec:
     datastoreType: "etcdv3"
     etcdEndpoints: "http://etcd1:2379,http://etcd2:2379"
     ...
   ```

#### Configure access using environment variables

If `calicoctl` cannot locate, read, or access a configuration file, it will check a specific set of environment variables.

Refer to the section that corresponds to your datastore type for a full set of options
and examples.

- [Kubernetes API datastore](kdd)

- [etcd datastore](etcd)

> **Note**: When running `calicoctl` inside a container, any environment variables and
> configuration files must be passed to the container so they are available to
> the process inside. It can be useful to keep a running container (that sleeps) configured
> for your datastore, then it is possible to `exec` into the container and have an
> already configured environment.
{: .alert .alert-info}
