---
title: Typha Overview
redirect_from: latest/reference/typha/index
canonical_url: 'https://docs.projectcalico.org/v3.9/reference/typha/index'
---

The Typha daemon sits between the datastore (such as the Kubernetes API server) and many instances of Felix. Typha's main purpose is to increase scale by reducing each node's impact on the datastore.  Services such as [Felix](https://github.com/projectcalico/felix) and [confd](https://github.com/projectcalico/confd) connect to Typha instead of connecting directly to the datastore as Typha maintains a single datastore connection on behalf of all its clients. It caches the datastore state and dedupes events so it can be fanned out to many listeners.

## Architecture
- Typha uses the shared [libcalico-go](https://github.com/projectcalico/libcalico-go) datastore sync APIs, which [Felix](https://github.com/projectcalico/felix) and [confd](https://github.com/projectcalico/confd) can also use directly.
- It caches a series of snapshots of the datastore state along with deltas between the snapshots.
- Snapshots are stored in an immutable datastructure that shares common data with the previous snapshot.  This allows many snapshots to be stored without taking up a lot of memory.
- Felix/confd connect over an internal gob API, which sends serialised update messages (the same datatype that is sent over the libcalico-go syncer API).
- When a new client connects, Typha sends a series of updates calculated from the current snapshot, then it follows the deltas from snapshot to snapshot, sending them to the client.
- Typha brings a large increase in scale, particularly in Kubernetes API Datastore mode, because it can filter out many datastore events that are not required for Calico.
