---
title: Configure calicoctl
description: Configure calicoctl for datastore access.
canonical_url: '/getting-started/clis/calicoctl/configure/index'
---

### About configuring calicoctl

Most `calicoctl` commands require access to the {{site.prodname}} datastore. By default, calicoctl
will attempt to read from the Kubernetes API based on the default kubeconfig.

You can configure `calicoctl` with alternative datastore access information using either of the following methods.

1. **Configuration file**: by default, `calicoctl` will look for a configuration file
at `/etc/calico/calicoctl.cfg`. You can override this using the `--config` option with
commands that require datastore access. The file can be in either YAML or JSON format.
It must be valid and readable by `calicoctl`. A YAML example follows.

   ```
   apiVersion: projectcalico.org/v3
   kind: CalicoAPIConfig
   metadata:
   spec:
     datastoreType: "etcdv3"
     etcdEndpoints: "http://etcd1:2379,http://etcd2:2379"
     ...
   ```

1. **Environment variables**: If `calicoctl` cannot locate, read, or access a configuration
file, it will check a specific set of environment variables.

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
