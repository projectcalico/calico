---
title: Component Architecture
---

Note: The following applies only to **container** deployments.

![component architecture overview](/images/component-architecture.png)

**Datastore:**

Calico stores cluster state in a central datastore.

In the above diagram, arrows pointing away from the datastore
indicates that a component reads or watches the datastore.
Arrows towards the datastore represent that a component writes data to etcd.

**Orchestrator Plugin:**

Calico's cni-plugin and libnetwork-plugin serve as orchestrator plugins
which respond to networking requests made by the orchestrator.

**felix:**

Felix is Calico's core engine. It is a long-running daemon process responsible
for implementing network policy for the containers on each host.

**calico/node:**

Calico primarily distributes its components in a Docker container named `calico/node`. This typically includes:

- Felix
- confd & BIRD

This container is run in host networking mode with some privileges
to allow it to manipulate the host's networking.

Some orchestrators provide a means for running this
container using the orchestrator itself. For ones that do not, Calico's
command line tool `calicoctl` can be used to easily launch it.
