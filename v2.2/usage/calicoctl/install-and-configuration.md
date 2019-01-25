---
title: Installing and Configuring calicoctl
canonical_url: 'https://docs.projectcalico.org/v3.5/usage/calicoctl/install'
---

This document outlines how to install and configure calicoctl which is the
primary tool for viewing, manipulating, and creating Calico objects on the
command line.

### Where to run calicoctl

Calicoctl's primary function is to read or manipulate state stored in the
datastore.  As such, it can run from any host with network access to the
datastore.  There are also the `node` sub-commands of calicoctl that are for
starting and checking the calico/node container.  To use this functionality
the calicoctl tool must be run on the host where the container will run or
is running.

### Installing calicoctl

The calicoctl tool can be downloaded from the
[release page of the calicoctl repository]({{site.data.versions[page.version].first.components.calicoctl.url}}),
set executable, and then it is ready to run.

```
curl -O -L {{site.data.versions[page.version].first.components.calicoctl.download_url}}
chmod +x calicoctl
```

> *Note:* Move calicoctl to a directory in your PATH or add the directory
  it is in to your PATH to avoid prepending the path to invocations of
  calicoctl.

### Datastore configuration

Datastore configuration may be as simple as using the defaults but in most
cases the endpoint will need to be specified and possibly other settings too,
all which depend on how your datastore is configured.

Here is a simple etcdv2 example.

```
ETCD_ENDPOINTS=http://etcd:2379 calicoctl get nodes
```

Here is a simple kubernetes datastore example.

```
DATASTORE_TYPE=kubernetes KUBECONFIG=~/.kube/config calicoctl get nodes
```

For the possible options and configuration guidance see
[Configuring calicoctl]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup).

### Checking the configuration

Here is a simple command to check that the installation and configuration is
correct.

```
calicoctl get nodes
```

A correct setup will yield a list of the nodes that have registered.  If an
empty list is returned you are either pointed at the wrong datastore or no
nodes have registred.  If an error is returned then attempt to correct the
issue then try again.

### Next steps

Now you are ready to read and configure most aspects of Calico.  You can
find the full list of commands in the 
[Command Reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/).

The full list of resources that can be managed, including a description of each,
can be found in the
[Resource Definitions]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/).
