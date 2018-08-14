---
title: calico/ctl container
canonical_url: 'https://docs.projectcalico.org/v3.2/usage/calicoctl/install'
---

With each release of calicoctl the docker container `calico/ctl` is released to
Dockerhub and Quay and can be used for running calicoctl commands.
See the
[calicoctl reference overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/)
for caveats when using a containerized version.

#### Configuring the calico/ctl container

See [Configuring calicoctl]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup).
for guidance on manually configuring a calico/ctl container.  Keep in mind
when using a container that any environment variables and configuration files
must be passed to the container so they are available to the process inside.

#### Keeping a configured calico/ctl running

It can be useful to keep a running container (that sleeps) configured
for your Datastore, then it is possible to `exec` into the container and
have an already configured environment.  If using Kubernetes see
[Running calicoctl as a Kubernetes Pod]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/tutorials/using-calicoctl).
