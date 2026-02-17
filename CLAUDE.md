# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Project Calico is a large monorepo providing container networking and security for Kubernetes. The codebase contains ~2000 Go files across 30+ components, supporting multiple dataplanes (eBPF, iptables, nftables, Windows, VPP).

**Primary language:** Go (also C/eBPF, Python, Shell, TypeScript/React)
**Build system:** Make + Docker-based reproducible builds
**CI/CD:** Semaphore CI (configuration in `.semaphore/`)

## Essential Build Commands

**Prerequisites:** Docker, Make, Git, Linux environment (Ubuntu 22.04+ recommended)

### Building Components

```bash
# Build all images (WARNING: 30+ minutes)
make image

# Build specific component (2-5 minutes, RECOMMENDED)
make -C calicoctl build
make -C felix build
make -C node build
make -C typha build
make -C kube-controllers build

# Build for specific architecture
make -C felix build ARCH=arm64

# Clean build artifacts
make clean
```

### Running Tests

```bash
# Run unit tests for specific component (RECOMMENDED)
make -C felix ut          # ~5-10 minutes
make -C calicoctl test      # ~2-3 minutes
make -C typha test

# DO NOT run 'make test' at root - takes hours
# Always test components individually

# Run Felix FV (functional verification) tests
# IMPORTANT: Always use the Makefile targets - they build required tooling and set up permissions
make -C felix fv GINKGO_ARGS="-ginkgo.v"

# Run specific FV tests by pattern
make -C felix fv GINKGO_FOCUS="TestName" GINKGO_ARGS="-ginkgo.v"

# Run Felix FV in eBPF mode (BPF-SAFE tests only)
make -C felix fv-bpf GINKGO_FOCUS="TestName" GINKGO_ARGS="-ginkgo.v"

# Run Felix FV in nftables mode
make -C felix fv GINKGO_ARGS="-ginkgo.v" FELIX_FV_NFTABLES=Enabled
```

### Felix Testing Notes

- Felix FV tests are in `felix/fv/`
- Uses **Ginkgo v2** (`github.com/onsi/ginkgo/v2`) with Context()/Describe()/It() blocks
- Test IDs include all nested Context/Describe headings
- **Always run FVs via Makefile** (`make -C felix fv` / `make -C felix fv-bpf`) - this builds required tooling and sets up permissions correctly
- Use `GINKGO_FOCUS="regex"` to target specific tests, `GINKGO_ARGS` for extra Ginkgo flags
- Useful flags:
  - `GINKGO_ARGS="-ginkgo.dryRun"`: Print test names without execution
  - `GINKGO_ARGS="-ginkgo.v"`: Verbose output
  - `FV_FELIX_LOG_LEVEL=debug`: Increase verbosity
- FV batching for CI: `FV_NUM_BATCHES=N FV_BATCHES_TO_RUN=M` to split and run subsets
- **IMPORTANT:** Prefer vanilla `go test` for new packages. Only use Ginkgo if established pattern exists.
- Felix "brain" is the calculation graph in `felix/calc/` - changes require calc graph FV tests (`felix/calc/calc_graph_fv_test.go`)
- Pre-commit hook checks for focused tests (`FIt`, `FDescribe`) - remove before committing

### Validation Commands

```bash
# Quick YAML validation (~30 seconds)
make yaml-lint

# Individual checks
make check-go-mod           # Go module validation
make check-dockerfiles      # Dockerfile linting
make check-language         # Language/content checks
make go-vet                 # Go static analysis (requires: make -C felix clone-libbpf)
make verify-go-mods         # Cross-component module check
make golangci-lint          # Run golangci-lint (--timeout 8m)

# Regenerate generated files (run after API changes, config changes, CI changes)
make generate

# Auto-fix formatting for changed files (RECOMMENDED after making changes)
make fix-changed

# Fix formatting for all files
make fix-all

# Run pre-commit checks in Docker (goimports, go fmt, copyright headers, license checks)
make pre-commit
```

### Code Generation

```bash
# Regenerate all generated files (APIs, protobuf, manifests, CI config, etc.)
make generate

# Individual generation targets
make protobuf               # Regenerate protobuf files
make gen-manifests          # Update manifests/ from helm charts
make gen-semaphore-yaml     # Regenerate .semaphore/semaphore.yml from templates

# After generation, generated files should be committed to git
```

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

**Typha** is a fan-out proxy that:
- Sits between Felix instances and the datastore (etcd/K8s API)
- Reduces load on datastore by caching and fanning out to multiple Felix instances
- Optional but recommended for clusters >50 nodes

**Node container** orchestrates node initialization:
- Runs Felix, confd, and BIRD in a single container
- Handles CNI plugin installation
- Source: `node/pkg/lifecycle/startup/startup.go`

**Calculation Graph** (Felix brain):
- Located in `felix/calc/`
- DAG that processes datastore updates and calculates dataplane state
- Changes to calc graph require additional FV tests

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
- **NEVER** run `make ci` or `make cd` locally - destructive CI-only targets

## Semaphore CI Configuration

- Main CI config: `.semaphore/semaphore.yml` (GENERATED - do not edit directly)
- Config templates: `.semaphore/semaphore.yml.d/` (edit these)
- After editing templates: run `make gen-semaphore-yaml` to regenerate
- Generated files must be committed

## Common Development Workflows

### Making Code Changes

1. Create feature branch from `master`
2. Make changes to relevant component(s)
3. Run component-specific tests: `make -C <component> test`
4. Run validation: `make yaml-lint` (if YAML changed)
5. If APIs/config/CI changed: `make generate`
6. **MANDATORY before committing:** Run `make fix-changed` to fix formatting. CI will reject PRs with formatting errors.
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
- **License headers matter:** GPL code requires dual Apache/GPL headers; Apache code requires Apache headers only. The pre-commit hook validates this.
- SPDX license identifiers are required in BPF source files

### Cherry-picking to Release Branches

1. Merge PR to master first
2. Use `hack/cherry-pick-pull` to create the cherry-pick PR:
   ```bash
   SRC_UPSTREAM_REMOTE=origin DST_UPSTREAM_REMOTE=origin FORK_REMOTE=<your-remote> CHERRY_PICK=1 \
     ./hack/cherry-pick-pull origin/release-vX.YY <PR_NUMBER>
   ```

## Critical Files and Locations

**Build Configuration:**
- `metadata.mk` - Version pins, tool versions, registry config
- `lib.Makefile` - Shared Makefile logic for all components
- `Makefile` - Root orchestration

**Component-Specific:**
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

**Linting and Formatting:**
- `golangci-lint` - Primary Go linter (run via `make golangci-lint`)
- `make fix-changed` - Custom 3-step formatting pipeline (`hack/format-changed-files.sh`):
  1. `goimports -w -local github.com/projectcalico/calico/` (coalesce single-line imports into blocks)
  2. `hack/cmd/coalesce-imports` (remove stray whitespace within import blocks)
  3. `goimports` again (insert only the desired grouping whitespace)
  Operates on `.go` files changed vs the parent release branch. Use this instead of running `goimports` or `go fmt` directly.
- Pre-commit hook: `hack/git-hooks/pre-commit-in-container` (run via `make pre-commit`)

## PR Requirements

Every PR needs these labels:

**Documentation labels (one required):**
- `docs-pr-required` - User-facing changes need docs
- `docs-completed` - Documentation already done
- `docs-not-required` - No user-facing impact

**Release note labels (one required):**
- `release-note-required` - User-facing changes (most PRs)
- `release-note-not-required` - No user-facing impact

**Optional labels:**
- `cherry-pick-candidate` - Should be backported (bug fixes only)
- `needs-operator-pr` - Requires corresponding operator change

## Build Time Expectations

- Individual component build: 2-5 minutes
- Unit tests per component: 2-10 minutes
- Full `make image`: 30+ minutes
- CI preflight checks: 10+ minutes
- YAML lint: ~30 seconds
- Felix FV tests (full suite): hours

## Common Build Issues

1. **"failed to remove builder" during clean** - Normal, ignored by Makefile
2. **Go module download timeouts** - CI uses `GOFLAGS="-mod=readonly"`
3. **Permission errors in Docker** - Uses `LOCAL_USER_ID=1001` for consistency
4. **eBPF build failures** - Run `make -C felix clone-libbpf` first
5. **Cross-compilation issues** - Pass `ARCH=<target>` explicitly

## Version Information

All tool and image versions are pinned in `metadata.mk` — check there for current values. Key variables include `GO_BUILD_VER`, `K8S_VERSION`, `CALICO_BASE_VER`, `BIRD_VERSION`, `LIBBPF_VERSION`, `BPFTOOL_IMAGE`, `ETCD_VERSION`, and `HELM_VERSION`. The Go version is in `go.mod`.

## Additional Resources

- **Developer Guide:** `DEVELOPER_GUIDE.md` - Comprehensive development information
- **Contributing Guide:** `CONTRIBUTING.md` - PR process and contributor agreements
- **Component READMEs:** Each component directory has specific build/test instructions
- **User Documentation:** https://docs.tigera.io/calico/latest/about
- **Slack:** https://slack.projectcalico.org
- **Hack docs:** `hack/docs/` - Additional developer documentation
