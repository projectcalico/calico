# Calico Repository Copilot Instructions

## Repository Overview

This is the main **Project Calico** repository - an open-source container networking and security solution. Calico provides data plane choice (eBPF, standard Linux, Windows, VPP), advanced security features, and scales to power 8M+ nodes daily. The repository is a large monorepo (~2000 Go files, 33 Dockerfiles) containing multiple interconnected components.

**Key Stats:**
- Type: Kubernetes networking and security platform
- Size: Large monorepo with 20+ components
- Languages: Go (primary), C/eBPF, Python, Shell, TypeScript/React
- Runtime: Kubernetes, Docker containers
- Build System: Make + Docker-based reproducible builds
- CI/CD: Semaphore CI with extensive end-to-end testing

## Build Instructions

### Prerequisites
- **Docker** - Required for all builds (validated: Docker Engine 28.0.4+)
- **Make** - Primary build orchestration
- **git** - Repository management
- **Linux** - Required build environment (Ubuntu 16.04+ recommended)

### Core Build Commands

**ALWAYS run these commands from the repository root unless specified otherwise.**

#### Bootstrap/Setup
```bash
# No specific bootstrap needed - Docker handles toolchain
# Clean previous builds if needed:
make clean
```

#### Building All Components
```bash
# Build all Calico container images (WARNING: takes 30+ minutes)
make image

# Build for specific architecture
make image ARCH=arm64

# Clean build (removes caches)
make clean image
```

#### Building Individual Components
```bash
# Build specific component (much faster - ~2-5 minutes)
make -C calicoctl build      # CLI tool
make -C felix build          # Core networking agent  
make -C node build           # Node agent
make -C typha build          # Datastore proxy
make -C kube-controllers build
```

#### Testing
```bash
# Run unit tests for specific component (recommended)
make -C calicoctl test       # Takes ~2-3 minutes
make -C felix test          # Takes ~5-10 minutes

# WARNING: Do NOT run 'make test' at root - takes hours
# Each directory has its own test suite - run individually
```

#### Linting and Validation
```bash
# YAML linting (always works)
make yaml-lint

# Full CI preflight checks (WARNING: takes 10+ minutes)
make ci-preflight-checks

# Individual validation steps:
make check-go-mod           # Go module validation
make check-dockerfiles      # Dockerfile linting  
make check-language         # Language checks
make go-vet                # Go static analysis
```

## Critical Build Notes

### Docker Dependencies
- All builds run inside Docker containers using `calico/go-build:1.24.6-llvm18.1.8-k8s1.32.7`
- **NEVER** run `make ci` or `make cd` locally - these are destructive CI-only targets
- Build errors like "docker image rm" failures during clean are normal and ignored

### Build Time Expectations
- Individual component build: 2-5 minutes
- Unit tests per component: 2-10 minutes  
- Full image build: 30+ minutes
- CI preflight checks: 10+ minutes
- yamllint: ~30 seconds

### Common Build Failures & Workarounds
1. **"failed to remove builder" during clean** - Normal, ignored by Makefile
2. **Go module download timeouts** - CI uses `GOFLAGS="-mod=readonly"` to prevent downloads
3. **Permission errors in Docker** - Uses `LOCAL_USER_ID=1001` for consistency
4. **eBPF build failures** - Felix requires specific libbpf setup: `make -C felix clone-libbpf`

## Repository Architecture

### Major Components (in dependency order)
```
libcalico-go/     - Core Go client library and data model
api/              - Calico API definitions (CRDs, protobuf)
felix/            - Core networking agent (eBPF/iptables dataplane)
typha/            - Datastore fan-out proxy for scaling
node/             - Node initialization and management
calicoctl/        - CLI tool for managing Calico
kube-controllers/ - Kubernetes-specific controllers
cni-plugin/       - Kubernetes CNI integration
confd/            - Configuration management
```

### Configuration Files Locations
- **Go modules**: `go.mod`, `go.sum` (root)
- **Build config**: `metadata.mk`, `lib.Makefile` 
- **Linting**: `.yamllint.yaml`, `.golangci.yaml` (per component)
- **CI/CD**: `.semaphore/semaphore.yml` (generated from template)
- **Docker**: `Dockerfile.*` in each component directory

### Key Source Files
- `felix/daemon/daemon.go` - Felix main daemon  
- `node/pkg/lifecycle/startup/startup.go` - Node initialization
- `calicoctl/calicoctl/calicoctl.go` - CLI entry point
- `kube-controllers/cmd/kube-controllers/main.go` - Controllers main

## Validation Pipeline

### Pre-commit Checks (CI runs these)
1. `make check-go-mod` - Go module consistency
2. `make verify-go-mods` - Cross-component module verification  
3. `make check-dockerfiles` - Dockerfile validation
4. `make check-language` - Language and content checks
5. `make generate` - Regenerate generated files
6. `make fix-all` - Auto-fix formatting issues
7. `make yaml-lint` - YAML validation
8. `make go-vet` - Go static analysis

### Manual Validation Commands
```bash
# Check if your changes broke anything:
make check-dirty          # Ensure no uncommitted generated files
make -C <component> test   # Run relevant component tests
make yaml-lint            # Quick validation
```

### GitHub Workflows
- **yamllint.yml** - YAML validation on PRs
- **codeql.yml** - Security scanning  
- **check_release_notes.yml** - Release note validation
- **inactive_issues.yml** - Issue management

## Developer Workflow

### Making Changes
1. **Always run component-specific tests** after changes
2. **Use `make clean` sparingly** - builds are cached for speed
3. **Run `make yaml-lint`** before committing YAML changes
4. **Check `make -C <component> help`** for component-specific targets

### Common Tasks
```bash
# Add new Go dependency:
cd <component> && go mod tidy && cd .. && make check-go-mod

# Update generated files:
make generate

# Fix formatting issues:
make fix-all

# Test specific component changes:
make -C <component> build test
```

### Architecture Dependencies
- **felix** depends on: libcalico-go, api
- **node** depends on: felix, confd, libcalico-go
- **calicoctl** depends on: libcalico-go, kube-controllers
- **All components** use: api, libcalico-go

## Quick Reference

### Essential Commands (most reliable)
```bash
make clean                    # Clean all components
make -C <component> build     # Build single component  
make -C <component> test      # Test single component
make yaml-lint               # Fast validation
make image                   # Build all images (slow)
```

### Files to Always Check
- `DEVELOPER_GUIDE.md` - Comprehensive development guide
- `CONTRIBUTING.md` - Contribution guidelines and PR process
- Component `README.md` files for specific build instructions
- Component `Makefile` for available targets

### Trust These Instructions
These instructions are based on actual testing of the build system. Only search for additional information if you encounter specific errors not covered here or if the repository structure has changed significantly.