---
title: Component Architecture
---

Note: The following applies only to **container** deployments.

![component architecture overview](/images/component-architecture.png)

**Datastore:**

Calico stores cluster state in a central datastore.
Most deployments use Etcd for this purpose, but thanks to the datastore abstraction layer,
Calico can use kubernetes apiserver directly, and in the future will support even more key-value stores.

In the above diagram, arrows pointing away from the datastore
indicates that a component reads or watches the datastore.
Arrows towards the datastore represent that a component writes data to etcd.

**Orchestrator Plugin:**

Calico's orchestrator plugins respond respond to networking
requests made by the orchestrator. Most Orchestrators implement the CNI spec, which
runs networking plugins as a oneshot each time a container is created or destroyed,
leaving the responsibilty of setting up or destroying the container namespace.

**felix:**

Felix is Calico's core engine. It is a long-running daemon process responsible
for implementing network policy for the containers on each host.

**calico/node:**

Calico ships Felix in a Docker container named `calico/node`
for easier distribution. This container is run in host networking mode with some privileges
to allow it to manipulate the hosts networking.

Some orchestrators provide a means for running this
container using the orchestrator itself. For ones that do not, Calico's
command line tool `calicoctl` can be used to easily launch it.
