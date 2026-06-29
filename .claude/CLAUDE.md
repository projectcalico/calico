# CLAUDE.md

This file is **operational guidance** for agents working in this repo: build commands, test invocation, debugging, conventions, and the process rules every PR follows. For **architecture, invariants, and review criteria**, see [`DESIGN.md`](../DESIGN.md) at the repo root, and the per-component `DESIGN.md` files it links to. Do not look here for architecture; look there.

## Repository Overview

Project Calico is a large monorepo providing container networking and security 
for Kubernetes. The codebase contains ~2000 Go files across 30+ components, 
supporting multiple dataplanes (eBPF, iptables, nftables, Windows, VPP).

**Primary language:** Go (also C/eBPF, Python, Shell, TypeScript/React)
**Build system:** Make + Docker-based reproducible builds
**CI/CD:** Semaphore CI (configuration in `.semaphore/`)
**Default branch:** `master` (not `main`)
**Separate docs repo**  https://github.com/tigera/docs/

## Gotchas

- **NEVER** run `make ci` or `make cd` locally — destructive CI-only targets
- **NEVER** run `make test` at root — takes hours. Always test components individually.
- **NEVER**, include customer names in code comments, commit
  messages, or PR descriptions. If you must reference, refer to the ticket only (GitHub issue number/JIRA key).
- **ALWAYS** remove `FIt`/`FDescribe` before committing — pre-commit hook rejects Ginkgo focused tests
- **ALWAYS** commit generated files alongside source changes

## Essential Build Commands

**Prerequisites:** Docker, Make, Go, Git, Linux environment (Ubuntu 24.04+ recommended)

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

### Docker Build System

- All builds run inside Docker containers using `calico/go-build` (version pinned in `metadata.mk`)
- Base images configured in `metadata.mk`
- Build cache in `.go-pkg-cache/` (speeds up rebuilds)
- Supported architectures: amd64, arm64, ppc64le, s390x (plus Windows builds)
- Cross-compilation via `ARCH=<target>` and binfmt registration (`calico/binfmt`)

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
make gen-deps-files         # Regenerate deps.txt files after adding new imports to a component; used to trigger downstream CI.
```

**After modifying API types** (e.g., `api/pkg/apis/projectcalico/v3/felixconfig.go`), 
run `make generate` — it regenerates OpenAPI specs, CRDs, deep copy, Felix 
config docs, manifests, and runs `fix-changed`. See also `hack/docs/adding-an-api.md`.

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

A repo-scoped PostToolUse hook (`.claude/settings.json`) re-formats `.go` files automatically after every Edit/Write/MultiEdit.

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

## Documentation map

This repo carries an extensive corpus of architecture and review
guidance. **Consult it first, instead of reverse-engineering from
the code** — it captures invariants, design rationale, and review
criteria that are hard to recover from the source alone.

Where it lives:

- **[`DESIGN.md`](../DESIGN.md) at the repo root** — Calico's
  cross-cutting architecture: the component dependency tables,
  the combined `calico` binary pattern, health reporting, Go
  module structure, build system, and entry points. The
  authoritative starting point for *what the repo is*.
- **`<component>/DESIGN.md`** — per-component architecture,
  invariants, and per-section review notes. Authoritative source
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
- **`design/<topic>/`** — cross-component designs for
  subsystems that span multiple components (e.g. IPAM spans
  `libcalico-go/lib/ipam`, `cni-plugin`, `kube-controllers`,
  `node`). Same shape as a component design index: a `DESIGN.md`
  plus per-topic sub-files with `applies to` globs. Use this when
  no single component owns the subsystem. Discoverability pointer
  stubs may live in consumer subdirectories (see e.g.
  `libcalico-go/lib/ipam/DESIGN.md`,
  `cni-plugin/pkg/ipamplugin/DESIGN.md`,
  `kube-controllers/pkg/controllers/node/DESIGN.md`) but the
  canonical content lives under `design/<topic>/`.
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
3. A PR that changes how a component works — its behaviour,
   data model, configuration surface, or any invariant the
   design doc records — must update the relevant `DESIGN.md` in
   the same PR. For components with a design directory (Felix
   uses `felix/design/`), this means updating the relevant file
   under that directory — the sub-design covering the area —
   and/or the index itself when the sub-design table or scope
   changes. Exemptions: bug fix restoring documented behaviour,
   mechanical refactor, comment or log-message edits, dependency
   bumps. If in doubt, update the doc.

## Tests required for code changes

A PR that fixes a bug must include a test in the same PR that
reproduces the bug. A PR that adds a feature must include tests
that exercise the feature. A change without a corresponding test
is the exception, not the default, and requires explicit
justification (untestable interface boundary, infrastructure-only
change).

Prefer the lowest test level that meaningfully exercises the
change:

1. **Unit tests** — deterministic, fast, hermetic. Always the
   first choice when the behaviour can be reached without real
   infrastructure. UT failures point at the change directly.
2. **Functional verification (FV) tests** — real binary against
   real infrastructure (containers, dataplane, kernel). Catch
   integration bugs UT cannot, but slower, harder to write, and
   can flake. Use FV when the integration *is* the thing being
   tested.
3. **End-to-end / Kubernetes tests** — full stack against a real
   cluster. Reserve for behaviour that genuinely requires it.

Tests-only follow-ups are an anti-pattern: by the time they land,
the change has shipped untested. A reviewer who sees "I tested it
manually" or "tests in a follow-up PR" should push back.

Per-area sub-designs carry the area-specific test conventions on
top of this general rule (e.g.
[`felix/design/bpf-tests.md`](../felix/design/bpf-tests.md) for
the BPF dataplane).

## Common Development Workflows

### Making Code Changes

1. Create feature branch from `master`
2. Make changes to relevant component(s)
3. Run component-specific tests: `make -C <component> test` or `go test ./...`
4. Run validation: `make yaml-lint` (if YAML changed)
5. If APIs/config/CI changed: `make generate` (formats regenerated files itself)
6. Commit changes (generated files must be included)
7. Push and create PR

### Updating Helm Charts and Manifests

- Charts are in `charts/`
- After editing chart templates: `make gen-manifests`
- This regenerates `manifests/` directory (mostly auto-generated)
- Commit both chart changes and regenerated manifests
- The install/upgrade instructions in `charts/tigera-operator/README.md` and `charts/crd.projectcalico.org.v1/README.md` are hand-written and drift silently. A chart change that alters how a user installs or upgrades Calico via Helm (moving resources between charts, adding/removing a manual step, renaming a chart, changing a documented values key or example command) must update the matching README in the same PR. See [`.github/instructions/helm-charts.instructions.md`](../.github/instructions/helm-charts.instructions.md).

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

For component entry points and architectural code paths, see [`DESIGN.md`](../DESIGN.md) §5.

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
