---
title: Component Architecture
---

Note: The following applies only to **container** deployments.

![component architecture overview](/images/component-architecture.png)

**Datastore:**
- Central Datastore
- traditionally etcd, but thanks to the datastore abstraction layer, can use kubernetes apiserver directly,
and in the future even more key-value stores.
- arrows towards components indicate those components read / watch datastore.
- arrows towards datastore represent writes

**Orchestrator Plugin:**
- cni-plugin for most orchestrators, libnetwork-plugin for Docker-as-an-orchestrator
- oneshot
- responsible for setting up container namespace and storing data about it in datastore.

**calico/node:**
- Container used to distribute and run calico core components.
- Easily launched using `calicoctl` utility.

**felix:**
- Calico's core engine
- long-running daemon process
- Enforces policy

**conf.d:**
- Watches datastore for host entries.
- Creates bird configurations used to establish BGP connections with other hosts
(or VRRs, or ToR, etc.)

**bird:**
- BGP daemon
- Shares routes with other hosts.
