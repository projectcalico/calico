<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# confd

confd watches the Calico datastore and renders BIRD's
configuration from the templates under
[`node/filesystem/etc/calico/confd/templates/`](../node/filesystem/etc/calico/confd/templates/).
It runs as a runit service inside the node container alongside
Felix and BIRD; see [`node/DESIGN.md`](../node/DESIGN.md).

This component does not yet have a design doc of its own.  The one
area that is written up is the split of route-programming
responsibility between confd/BIRD and Felix, which is
cross-component and lives at the repo level:

- [`design/cluster-route-programming/DESIGN.md`](../design/cluster-route-programming/DESIGN.md)
  — which component programs the routes to workloads on other
  nodes, per encapsulation type; the `programClusterRoutes` fields
  on `BGPConfiguration` and `FelixConfiguration`; the deprecation
  of BIRD-programmed IPIP cluster routes and of the `krt_tunnel`
  BIRD fork.

Operational guidance (flags, logging, no-op mode, BIRD config
examples) is under [`confd/docs/`](./docs/).

Update the design under `design/`, not this file.  This file is a
discoverability pointer.
