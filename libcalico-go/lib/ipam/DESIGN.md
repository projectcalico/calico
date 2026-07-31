<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# libcalico-go IPAM core library

This directory is the canonical home of Calico's IPAM core
library: the public API, the `AutoAssign` allocator, the CAS
retry loop, the handle ID convention, and the `IPAMConfig`
resolver.

Architecture, invariants, and review criteria live in the
cross-component IPAM design:

- Index: [`design/ipam/DESIGN.md`](../../../design/ipam/DESIGN.md)
- Core library: [`design/ipam/ipam-core-library.md`](../../../design/ipam/ipam-core-library.md)
- Datastore (paired): [`design/ipam/ipam-datastore.md`](../../../design/ipam/ipam-datastore.md)

Update the design under `design/ipam/`, not this file. This
file is a discoverability pointer.
