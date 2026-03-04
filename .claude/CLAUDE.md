# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Project Calico is a large monorepo providing container networking and security for Kubernetes. The codebase contains ~2000 Go files across 30+ components, supporting multiple dataplanes (eBPF, iptables, nftables, Windows, VPP).

**Primary language:** Go (also C/eBPF, Python, Shell, TypeScript/React)
**Build system:** Make + Docker-based reproducible builds
**CI/CD:** Semaphore CI (configuration in `.semaphore/`)
**Default branch:** `master` (not `main`)
**Separate docs repo**  https://github.com/tigera/docs/

## Gotchas

- **NEVER** run `make ci` or `make cd` locally — destructive CI-only targets
- **NEVER** run `make test` at root — takes hours. Always test components individually.
- **ALWAYS** run `make fix-changed` before committing — CI rejects formatting errors
- **ALWAYS** remove `FIt`/`FDescribe` before committing — pre-commit hook rejects Ginkgo focused tests
- **ALWAYS** commit generated files alongside source changes

## Essential Build Commands

**Prerequisites:** Docker, Make, Git, Linux environment (Ubuntu 24.04+ recommended)

### Building Components

```bash
# Build specific component (2-5 minutes, RECOMMENDED)
make -C felix build
make -C typha build
make -C node build
make -C calicoctl build
make -C kube-controllers build

# Build all images (WARNING: 30+ minutes)
make image

# Build for specific architecture
make -C felix build ARCH=arm64
```

### Running Tests

```bash
# Unit tests for a component via Make (runs in Docker, rebuilds tooling)
make -C felix ut
make -C calicoctl test
make -C typha test

# Unit tests via go test (faster, no Docker overhead — use for quick iteration)
go test ./felix/calc/...
go test ./libcalico-go/lib/...

# Components with separate go.mod (must cd first)
cd api && go test ./...
cd lib/std && go test ./...
cd lib/httpmachinery && go test ./...

# Felix FV (functional verification) tests
# IMPORTANT: Always use Makefile targets — they build required tooling and set up permissions
make -C felix fv GINKGO_ARGS="-ginkgo.v"

# Run specific FV tests by pattern
make -C felix fv GINKGO_FOCUS="TestName" GINKGO_ARGS="-ginkgo.v"

# Felix FV in eBPF mode (BPF-SAFE tests only)
make -C felix fv-bpf GINKGO_FOCUS="TestName" GINKGO_ARGS="-ginkgo.v"

# Felix FV in nftables mode
make -C felix fv GINKGO_ARGS="-ginkgo.v" FELIX_FV_NFTABLES=Enabled
```

### Felix Testing Notes

- Felix FV tests are in `felix/fv/`, using **Ginkgo v2** (`github.com/onsi/ginkgo/v2`)
- Test IDs include all nested Context/Describe headings
- **Always run FVs via Makefile** — builds required tooling and sets up permissions
- Use `GINKGO_FOCUS="regex"` to target specific tests, `GINKGO_ARGS` for extra flags
- Useful flags: `-ginkgo.dryRun` (list tests), `-ginkgo.v` (verbose), `FV_FELIX_LOG_LEVEL=debug`
- **Prefer vanilla `go test` for new packages.** Only use Ginkgo if established pattern exists.
- Felix "brain" is the calculation graph in `felix/calc/` — changes require calc graph "FV" tests (`felix/calc/calc_graph_fv_test.go`)

### Validation and Formatting

```bash
make yaml-lint              # Quick YAML validation (~30 seconds)
make check-go-mod           # Go module validation
make check-dockerfiles      # Dockerfile linting
make check-language         # Language/content checks
make go-vet                 # Go static analysis (requires: make -C felix clone-libbpf)
make verify-go-mods         # Cross-component module check
make golangci-lint          # Run golangci-lint (--timeout 8m)
make fix-changed            # Auto-fix formatting for changed files (RECOMMENDED)
make pre-commit             # Run pre-commit checks in Docker
```

### Code Generation

```bash
# Regenerate all generated files (APIs, protobuf, manifests, CI config, etc.)
make generate

# Individual generation targets
make protobuf               # Regenerate protobuf files
make gen-manifests          # Update manifests/ from helm charts
make gen-semaphore-yaml     # Regenerate .semaphore/semaphore.yml from templates
```

## Generated Files (DO NOT edit directly)

| Generated file | Edit this instead | Regenerate with |
|---|---|---|
| `.semaphore/semaphore.yml` | `.semaphore/semaphore.yml.d/` templates | `make gen-semaphore-yaml` |
| `manifests/` | `charts/` | `make gen-manifests` |
| `*.pb.go` protobuf files | `.proto` sources | `make protobuf` |

After regenerating, commit the generated files alongside your source changes.

## Code Conventions

### Go Import Order

Three groups separated by blank lines: stdlib, external, calico-internal:
```go
import (
	"fmt"
	"net"

	"k8s.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis"
)
```

Run `make fix-changed` to auto-fix import ordering. Do not run `goimports` or `go fmt` directly — the project uses a custom 3-step pipeline (`hack/format-changed-files.sh`).

### Copyright Headers

All new `.go` files require:
```go
// Copyright (c) <YEAR> Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...
```

eBPF files in `felix/bpf-gpl/` require dual Apache/GPL headers with SPDX identifiers. The pre-commit hook validates license headers.

## Repository Architecture

### Component Dependency Order

Core components (dependency order):
```
api/              - Calico API definitions (CRDs, protobuf), separate go.mod
libcalico-go/     - Core Go client library and data model
typha/            - Datastore fan-out proxy for scaling (reduces etcd load)
felix/            - Core per-host networking agent (eBPF/iptables/nftables dataplane)
node/             - Node initialization container (includes Felix, confd, BIRD, startup scripts)
calicoctl/        - CLI tool for Calico management
kube-controllers/ - Kubernetes-specific controllers (namespace, pod, node, serviceaccount)
cni-plugin/       - Kubernetes CNI integration
confd/            - Configuration management daemon
app-policy/       - Application layer policy (L7)
apiserver/        - Kubernetes API aggregation layer
```

Additional components:
```
goldmane/             - Log aggregation and flow log storage
guardian/             - Secure tunnel proxy for management cluster connections
pod2daemon/           - Flex volume driver for injecting credentials into pods
key-cert-provisioner/ - TLS certificate provisioner for Calico components
whisker/              - Flow log UI (TypeScript/React frontend)
whisker-backend/      - Backend for whisker flow log UI
e2e/                  - End-to-end test suites
release/              - Release tooling and automation
lib/std/              - Internal shared Go library (separate go.mod)
lib/httpmachinery/    - Internal HTTP utility library (separate go.mod)
```

### Key Architectural Concepts

**Felix** is the core per-host agent responsible for:
- Programming dataplane (eBPF, iptables, nftables)
- Maintaining routing tables
- Processing policy and programming ACLs
- Source: `felix/daemon/daemon.go`
- **Calculation graph** (`felix/calc/`): DAG that processes datastore updates and calculates dataplane state. Changes here require calc graph FV tests.

**Typha** is a fan-out proxy that:
- Sits between Felix instances and the datastore (etcd/K8s API)
- Reduces load on datastore by caching and fanning out to multiple Felix instances
- Optional but recommended for clusters >50 nodes

**Node container** orchestrates node initialization:
- Runs Felix, confd, and BIRD in a single container
- Handles CNI plugin installation
- Source: `node/pkg/lifecycle/startup/startup.go`

### Go Module Structure

- Root `go.mod` (`github.com/projectcalico/calico`) is the primary module for most components
- `api/go.mod` (`github.com/projectcalico/api`) is separate (API exported as independent repo)
- `lib/std/go.mod` and `lib/httpmachinery/go.mod` are internal libraries
- When adding Go dependencies: `cd <component> && go mod tidy && cd .. && make check-go-mod`

### Docker Build System

- All builds run inside Docker containers using `calico/go-build` (version pinned in `metadata.mk`)
- Base images configured in `metadata.mk`
- Build cache in `.go-pkg-cache/` (speeds up rebuilds)
- Supported architectures: amd64, arm64, ppc64le, s390x (plus Windows builds)
- Cross-compilation via `ARCH=<target>` and binfmt registration (`calico/binfmt`)

## Common Development Workflows

### Making Code Changes

1. Create feature branch from `master`
2. Make changes to relevant component(s)
3. Run component-specific tests: `make -C <component> test` or `go test ./...`
4. Run validation: `make yaml-lint` (if YAML changed)
5. If APIs/config/CI changed: `make generate`
6. **MANDATORY:** Run `make fix-changed` to fix formatting
7. Commit changes (generated files must be included)
8. Push and create PR

### Updating Helm Charts and Manifests

- Charts are in `charts/`
- After editing chart templates: `make gen-manifests`
- This regenerates `manifests/` directory (mostly auto-generated)
- Commit both chart changes and regenerated manifests

### Working with eBPF Code

- eBPF programs: `felix/bpf-gpl/` (GPL v2.0 license for Linux compatibility)
- Apache licensed BPF code: `felix/bpf-apache/`
- Before building: `make -C felix clone-libbpf`
- BPF tooling configured in `metadata.mk` (LIBBPF_VERSION, BPFTOOL_IMAGE)

### Cherry-picking to Release Branches

1. Merge PR to master first
2. Use `hack/cherry-pick-pull` to create the cherry-pick PR:
   ```bash
   SRC_UPSTREAM_REMOTE=origin DST_UPSTREAM_REMOTE=origin FORK_REMOTE=<your-remote> CHERRY_PICK=1 \
     ./hack/cherry-pick-pull origin/release-vX.YY <PR_NUMBER>
   ```

## Critical Files and Locations

**Build Configuration:**
- `metadata.mk` - Version pins, tool versions, registry config (all tool/image versions pinned here)
- `lib.Makefile` - Shared Makefile logic for all components
- `Makefile` - Root orchestration

**Component Entry Points:**
- `felix/daemon/daemon.go` - Felix main entry point
- `felix/calc/` - Felix calculation graph (policy processing brain)
- `felix/dataplane/` - Dataplane implementations (eBPF, iptables, nftables)
- `node/pkg/lifecycle/startup/startup.go` - Node initialization
- `calicoctl/calicoctl/calicoctl.go` - CLI entry point

**Testing:**
- `felix/fv/` - Felix functional verification tests (Ginkgo v2-based)
- Component unit tests co-located with source code
- Felix FV supports batching: `FV_NUM_BATCHES` / `FV_BATCHES_TO_RUN` to split across CI jobs
- Race detector enabled by default on amd64/arm64 (`FV_RACE_DETECTOR_ENABLED`)

## PR Requirements

Every PR needs one docs label (`docs-pr-required`, `docs-completed`, or `docs-not-required`) and one release note label (`release-note-required` or `release-note-not-required`). Optional: `cherry-pick-candidate` (bug fix backports), `needs-operator-pr` (requires operator change).

## Additional Resources

- **Developer Guide:** `DEVELOPER_GUIDE.md`
- **Contributing Guide:** `CONTRIBUTING.md`
- **User Documentation:** https://docs.tigera.io/calico/latest/about
- **Hack docs:** `hack/docs/`
