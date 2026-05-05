# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Project Calico is a large monorepo providing container networking and security for Kubernetes. The codebase contains ~2000 Go files across 30+ components, supporting multiple dataplanes (eBPF, iptables, nftables, Windows, VPP).

**Primary language:** Go (also C/eBPF, Python, Shell, TypeScript/React)
**Build system:** Make + Docker-based reproducible builds
**CI/CD:** Semaphore CI (configuration in `.semaphore/`)
**Default branch:** `master` (not `main`)
**Separate docs repo**  https://github.com/tigera/docs/

## Documentation map

Calico's documentation is split by purpose. Before working in a
component, know where to look.

- **`<component>/DESIGN.md`** — architecture, invariants, and
  per-section review notes for that component. Authoritative source
  for "what does this code promise?". A coding agent writing a PR
  and a reviewer checking one read the same file and apply the
  same embedded review notes.
- **Complex components have an index.** Felix has
  [`felix/DESIGN.md`](../felix/DESIGN.md) at its root listing
  per-topic sub-designs under
  [`felix/design/`](../felix/design/) with an "applies to" glob
  per topic. A PR touching multiple globs must load every matching
  sub-design. This pattern applies to any component that grows
  more than one design topic.
- **`<component>/CLAUDE.md`** (or `AGENTS.md`) — operational
  agent guidance: build commands, test invocation, debugging,
  in-repo conventions. **Not** for architecture. If you are looking
  for invariants or design rationale, look for a `DESIGN.md`, not
  here.
- **[`.github/copilot-instructions.md`](../.github/copilot-instructions.md)**
  and
  **[`.github/instructions/*.instructions.md`](../.github/instructions/)**
  — repo-wide and path-scoped Copilot configuration. The
  path-scoped files are thin pointers to the relevant `DESIGN.md`
  plus meta-rules (update rule, `@copilot` invocation pattern).
  They do not restate design content.

**Rules for agents reading this repo:**

1. Before writing or reviewing code in a component, read that
   component's `DESIGN.md` (or, for Felix, the topic sub-designs
   that match the paths you're touching).
2. Follow links. A sub-design may reference sibling docs, other
   components' designs, or external references. Load them — a
   design is a graph, not a single node.
3. A PR that changes how a component works in a way that
   introduces a new invariant, flag, map, mark, sub-program, or
   alters the packet/data path must update the relevant
   `DESIGN.md` in the same PR. For components with a design
   directory (Felix uses `felix/design/`), "update `DESIGN.md`"
   means update the relevant file under that directory — the
   sub-design covering the area — and/or the index itself when
   the sub-design table or scope changes. Exemptions: bug fix
   restoring documented behaviour, mechanical refactor, comment
   or log-message edits, dependency bumps. If in doubt, update
   the doc.

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

**After modifying API types** (e.g., `api/pkg/apis/projectcalico/v3/felixconfig.go`), run `make generate` — it regenerates OpenAPI specs, CRDs, deep copy, Felix config docs, manifests, and runs `fix-changed`. See also `hack/docs/adding-an-api.md`.

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

### File layout

- Place utility methods/functions after (but close to) the methods/functions 
  that use them, generally want the context that a function is called in to 
  appear before the detail of the function body.
- For files that contain "object" structs:
  - Small typedefs/enums/constants.
  - Main struct definition
  - Constructors
  - Methods; in some intuitive ordering
    - Expected call order works well for readability "Add" before "Remove", "Start" before "Stop"
    - Group similar methods together
  - Utility functions; can be interspersed with methods if tightly coupled with particular methods.
  - Larger secondary structs at the bottom.

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

### Combined `calico` binary

Most component daemons are registered as subcommands of a single `calico` binary rather than shipping as independent binaries — felix, confd, kube-controllers, goldmane, guardian, whisker-backend, key-cert-provisioner, typha, dikastes, csi, flexvol, and webhooks all dispatch through `calico component <name>`. Inside the node container, runit services exec the subcommand directly (see `node/filesystem/etc/service/available/<name>/run`).

**Adding a new component:**

1. Expose a `NewCommand() *cobra.Command` from the component's package.
2. Register it in `cmd/calico/component.go` under `newComponentCommand`.
3. If the component runs in the node container, add a runit service at `node/filesystem/etc/service/available/<name>/run` whose body is `exec calico component <name>`.
4. The component's `Run` handler should call `logutils.ConfigureFormatter("<name>")` so log lines carry a consistent component prefix.

**Restart-on-config-change (exit 129):** A component that intentionally exits with `cmdwrapper.RestartReturnCode` (129) to request a live restart on config change (currently felix and kube-controllers) must wrap its cobra `Run` with `cmdwrapper.WrapSelf(innerEnvVar, fn)` from `pkg/cmdwrapper`. Without this, `exec calico component <name>` from runit just exits — there is no outer process to restart the child.

- Pick a unique `innerEnvVar` per component (e.g. `CALICO_FELIX_INNER`, `CALICO_KUBE_CONTROLLERS_INNER`). `WrapSelf` strips any pre-existing value before re-execing.
- The caller configures logrus before calling `WrapSelf`; `fn` is the inner daemon body.
- Don't change the log line format in `cmdwrapper` — integration tests grep stdout for `"Received exit status N, restarting"`.

### Health reporting

Components expose liveness/readiness through the shared aggregator in `libcalico-go/lib/health`.

1. Construct once per component: `ha := health.NewHealthAggregator()`.
2. For each independent health source, register a named reporter declaring what it will report: `ha.RegisterReporter("Startup", &health.HealthReport{Live: true, Ready: true}, timeout)`. A non-zero timeout means reports must refresh before expiry or the aggregator treats that reporter as unhealthy — use this for long-running loops where silent stalls matter.
3. Call `ha.Report(name, &health.HealthReport{...})` at startup and as state changes inside running goroutines.
4. Serve the endpoints with `ha.ServeHTTP(enabled, host, port)` — this exposes `/readiness` and `/liveness` on the given port.

For Kubernetes probes, use the generic `calico health --port=<port> --type=readiness|liveness` exec command (`cmd/calico/health.go`) rather than adding a per-component healthcheck binary or a bare `httpGet` probe. It does the HTTP GET and exits 0 on 2xx/3xx — that's the standard for pods running the combined image.

Examples worth copying from: `kube-controllers/pkg/kubecontrollers/run.go` (Startup / CalicoDatastore / KubeAPIServer reporters, no timeout) and `felix/daemon/daemon.go` (lifecycle reporter plus per-subsystem reporters with timeouts).

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

### Kind Cluster Development

Kind cluster targets are defined in `lib.Makefile` and orchestrated from the root `Makefile`. Scripts and infrastructure live in `hack/test/kind/`.

```bash
make kind-up                # Build all images + create cluster + deploy Calico (full bringup)
make kind-cluster-create    # Create the kind cluster (no images, no Calico)
make kind-build-images      # Build all container images needed for the kind cluster
make kind-deploy            # Load images + install Calico via Helm + wait for readiness
make kind-reload            # Reload only changed images onto an existing cluster (incremental)
make kind-cluster-destroy   # Tear down the kind cluster
make kind-down              # Alias for kind-cluster-destroy
```

Image loading is incremental — `kind-reload` and `kind-deploy` compare local Docker image IDs against what's on the cluster and only transfer changed images. Override the cluster name with `KIND_NAME=<name>`.

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

**Kind Cluster Infrastructure:**
- `hack/test/kind/` - Kind cluster scripts (creation, image loading, deployment, teardown)
- `hack/test/kind/infra/` - Kind cluster config, Helm values, supporting manifests

**Testing:**
- `felix/fv/` - Felix functional verification tests (Ginkgo v2-based)
- Component unit tests co-located with source code
- Felix FV supports batching: `FV_NUM_BATCHES` / `FV_BATCHES_TO_RUN` to split across CI jobs
- Race detector enabled by default on amd64/arm64 (`FV_RACE_DETECTOR_ENABLED`)

## PR Requirements

**ALWAYS** use the PR template (`.github/PULL_REQUEST_TEMPLATE.md`) when submitting pull requests. The only mandatory section is the **Release Note** — fill it in with a one-line summary of the user-facing impact of the change. Take a broad view of "user-facing": bug fixes, new features, performance improvements, and behavioral changes all qualify. If there is genuinely no user-facing impact, write "None".

Every PR needs one docs label (`docs-pr-required`, `docs-completed`, or `docs-not-required`) and one release note label (`release-note-required` or `release-note-not-required`). Optional: `cherry-pick-candidate` (bug fix backports), `needs-operator-pr` (requires operator change).

## Additional Resources

- **Developer Guide:** `DEVELOPER_GUIDE.md`
- **Contributing Guide:** `CONTRIBUTING.md`
- **User Documentation:** https://docs.tigera.io/calico/latest/about
- **Hack docs:** `hack/docs/`
