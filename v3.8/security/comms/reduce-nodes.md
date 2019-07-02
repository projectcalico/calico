---
title: Scheduling to well-known nodes
redirect_from: latest/security/comms/reduce-nodes
canonical_url: 'https://docs.projectcalico.org/v3.7/security/comms/reduce-nodes'
---

If you are on Kubernetes, use the Kubernetes API datastore, and have a cluster of more
than 50 nodes, you have probably deployed Typha. Typha is a fan-out proxy that improves
performance in larger clusters. Typha agents must accept connections from other agents on
a fixed port.

As part of the {{site.prodname}} bootstrap infrastructure, Typha must be available before
pod networking begins and uses host networking instead. It opens a port on the node it is
scheduled on. By default, it can get scheduled to any node and opens TCP 5473.

To reduce the number of nodes with the port open to a subset of the
total, consider [scheduling Typha to well-known nodes](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/).
