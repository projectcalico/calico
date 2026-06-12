<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Calico IPAM CNI plugin

This directory is the canonical home of the Calico IPAM CNI
plugin binary entry point, IPAM lock acquisition, and annotation
handling.

Architecture, invariants, and review criteria live in the
cross-component IPAM design:

- Index: [`design/ipam/DESIGN.md`](../../../design/ipam/DESIGN.md)
- CNI plugin: [`design/ipam/ipam-cni.md`](../../../design/ipam/ipam-cni.md)
- Core library: [`design/ipam/ipam-core-library.md`](../../../design/ipam/ipam-core-library.md)

Update the design under `design/ipam/`, not this file. This
file is a discoverability pointer.
