#################################################################################################
# This file contains Makefile configuration parameters and metadata for this branch.
#################################################################################################
# The project Go version
GO_VERSION=1.26.4
# Version of Kubernetes to use for dependencies, tests, registry.k8s.io/kubectl, and kubectl binary release.
K8S_VERSION=v1.36.2
# The version of LLVM to use for go-build and calico/base images.
LLVM_VERSION=21.1.8
# Calico toolchain versions and the calico/base image to use.
GO_BUILD_VER=$(GO_VERSION)-llvm$(LLVM_VERSION)-k8s$(K8S_VERSION:v%=%)
RUST_BUILD_VER=1.96.0

CALICO_BASE_VER=ubi9-1781722225

# Version of various tools used in the build and tests.
COREDNS_VERSION=1.5.2
CRANE_VERSION=v0.21.6
ETCD_VERSION=v3.5.31
GHR_VERSION=v0.18.3
GITHUB_CLI_VERSION=2.94.0
GOTESTSUM_VERSION=v1.13.0
HELM_VERSION=v3.21.1
# KINDEST_NODE_VERSION is the Kubernetes version of the KIND cluster used in
# tests, and is deliberately held one minor behind K8S_VERSION: the KubeVirt
# live-migration tests deploy KubeVirt (tigera/kubevirt mockvirt-v1.8.1, i.e.
# KubeVirt 1.8), which only supports Kubernetes 1.33-1.35. On a 1.36 node image
# VMIs never leave the "Scheduled" phase and the suite times out. v1.35.5 is the
# 1.35.x node image shipped with KIND_VERSION below. Bump this only once a
# KubeVirt/mockvirt release that supports the target Kubernetes minor exists.
KINDEST_NODE_VERSION=v1.35.5
KIND_VERSION=v0.32.0

# Configuration for Semaphore/Github integration.  This needs to be set
# differently for a forked repo.
ORGANIZATION  ?= projectcalico
GIT_REPO      ?= calico
GIT_REMOTE    ?= origin

RELEASE_BRANCH_PREFIX ?=release
DEV_TAG_SUFFIX        ?= 0.dev

# Part of the git remote that is common to git and HTTP representations.
# Used to auto-detect the right remote.
GIT_REPO_SLUG ?= $(ORGANIZATION)/$(GIT_REPO)

# Configure git to access repositories using SSH.
GIT_USE_SSH = true

# The version of BIRD to use for calico/node builds and confd tests.
BIRD_VERSION=v0.3.3-211-g9111ec3c

# DEV_REGISTRIES configures the container image registries which are built from this
# repository. By default, just build images with calico/. Allow this variable to be overridden,
# as both CI/CD and the release tooling will override this to build publishable images.
DEV_REGISTRIES ?= calico

# The directory for windows image tarballs
WINDOWS_DIST = dist/windows

# FIXME: Use WINDOWS_HPC_VERSION and remove WINDOWS_VERSIONS when containerd v1.6 is EOL'd
# The Windows HPC container version used as base for Calico Windows images
WINDOWS_HPC_VERSION ?= v1.0.0
# The Windows versions used as base for Calico Windows images
WINDOWS_VERSIONS ?= ltsc2019 ltsc2022

# The CNI plugin and flannel code that will be cloned and rebuilt with this repo's go-build image.
# Pinned so the content-addressed third-party-cni-plugins image hash changes when these move.
# CNI_VERSION is a commit SHA because the fork has no release tag at the toolchain we build with;
# bump it to pick up upstream changes.
CNI_VERSION=9ffe547cb3b66f80dd32a00fc69a6d0082b55321
FLANNEL_VERSION=v1.2.0-flannel2-go1.22.7

# The libbpf version to use
LIBBPF_VERSION=v1.6.2

# The bpftool image to use; this is the output of the https://github.com/projectcalico/bpftool repo.
BPFTOOL_IMAGE=calico/bpftool:v7.5.0

# Patched nftables + libnftnl shipped in calico/node and the istio CNI install
# image. Built by hack/rpms/nftables/ and consumed via calico/nftables-rpms:<sha>-<arch>.
# Do not bump NFTABLES_VER past 1.1.1 - see projectcalico/calico#11750.
NFTABLES_VER=1.1.1
NFTABLES_SHA256=6358830f3a64f31e39b0ad421d7dadcd240b72343ded48d8ef13b8faf204865a
LIBNFTNL_VER=1.2.8
LIBNFTNL_SHA256=37fea5d6b5c9b08de7920d298de3cdc942e7ae64b1a3e8b880b2d390ae67ad95

# The operator branch corresponding to this branch.
OPERATOR_BRANCH ?= master
OPERATOR_ORGANIZATION ?= tigera
OPERATOR_GIT_REPO     ?= operator

# quay.io expiry time for hashrelease/dev images
QUAY_EXPIRE_DAYS=90
