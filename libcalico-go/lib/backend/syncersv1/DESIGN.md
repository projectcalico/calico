<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# libcalico-go syncers

This directory holds the per-purpose Syncer implementations
(`felixsyncer`, `bgpsyncer`, `tunnelipsyncer`,
`nodestatussyncer`), the `updateprocessors` that convert v3
resources to the v1 key/value model, and the `dedupebuffer`
callback adaptor.

The Syncer API's contract — the callback interface, the consumer
algorithm, the eventual-consistency guarantees, and review
criteria — lives in the cross-component design:

- [`design/syncer/DESIGN.md`](../../../../design/syncer/DESIGN.md)

Update the design under `design/syncer/`, not this file. This
file is a discoverability pointer.
