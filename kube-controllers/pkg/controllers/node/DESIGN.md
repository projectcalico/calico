<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# kube-controllers IPAM garbage collection

The IPAM garbage collector lives **here**, not under
`pkg/controllers/ipam/`. This directory also hosts the node
lifecycle controllers; this design pointer is specifically for
the IPAM GC subset (the files that reconcile IPAM state against
live pods, nodes, and block affinities and clean up leaked
allocations and empty blocks).

Architecture, invariants, and review criteria live in the
cross-component IPAM design:

- Index: [`design/ipam/DESIGN.md`](../../../../design/ipam/DESIGN.md)
- GC controller: [`design/ipam/ipam-gc.md`](../../../../design/ipam/ipam-gc.md)
- Datastore (paired): [`design/ipam/ipam-datastore.md`](../../../../design/ipam/ipam-datastore.md)

Update the design under `design/ipam/`, not this file. This
file is a discoverability pointer.
