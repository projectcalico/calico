# Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#################################################################################################
# This file contains Makefile configuration parameters and metadata for this branch.
#################################################################################################
# The Go and Kubernetes versions are set in the root go.mod: its `go` line and
# its k8s.io/kubernetes requirement. Kubernetes is used for tests,
# registry.k8s.io/kubectl and the kubectl binary release. Both are empty when
# this file is read without the repo around it, as the release binary does.
METADATA_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
GO_VERSION := $(shell awk '$$1 == "go" {print $$2; exit}' $(METADATA_DIR)go.mod 2>/dev/null)
K8S_VERSION := $(shell awk '$$1 == "k8s.io/kubernetes" {print $$2; exit}' $(METADATA_DIR)go.mod 2>/dev/null)
# The version of LLVM to use for go-build and calico/base images.
LLVM_VERSION=21.1.8
# A rebuild of calico/go-build that moves neither Go nor LLVM is published as
# <tag>-1, -2 and so on. GO_BUILD_REV names that full tag, and applies only
# while its prefix is the current Go and LLVM, so a version bump needs no reset.
GO_BUILD_REV=
GO_BUILD_BASE_VER := $(GO_VERSION)-llvm$(LLVM_VERSION)
GO_BUILD_VER := $(if $(filter $(GO_BUILD_BASE_VER)-%,$(GO_BUILD_REV)),$(GO_BUILD_REV),$(GO_BUILD_BASE_VER))
# calico/rust-build is tagged with its Rust version. RUST_BUILD_REV works as
# GO_BUILD_REV does.
RUST_VERSION=1.96.0
RUST_BUILD_REV=1.96.0-1
RUST_BUILD_VER := $(if $(filter $(RUST_VERSION)-%,$(RUST_BUILD_REV)),$(RUST_BUILD_REV),$(RUST_VERSION))
# calico/binfmt is tagged with the Fedora qemu-user-static version it ships.
# BINFMT_REV works as GO_BUILD_REV does.
QEMU_VERSION=10.2.2
BINFMT_REV=qemu-v10.2.2-1
BINFMT_BASE_VER := qemu-v$(QEMU_VERSION)
BINFMT_VER := $(if $(filter $(BINFMT_BASE_VER)-%,$(BINFMT_REV)),$(BINFMT_REV),$(BINFMT_BASE_VER))

CALICO_BASE_VER=ubi9-1790725174

# Version of various tools used in the build and tests.
COREDNS_VERSION=1.5.2
CRANE_VERSION=v0.21.9
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
WINDOWS_VERSIONS ?= ltsc2019 ltsc2022 ltsc2025

# The CNI plugin and flannel code that will be cloned and rebuilt with this repo's go-build image.
# Pinned so the content-addressed third-party-cni-plugins image hash changes when these move.
# CNI_VERSION is a commit SHA because the fork has no release tag at the toolchain we build with;
# bump it to pick up upstream changes.
CNI_VERSION=9ffe547cb3b66f80dd32a00fc69a6d0082b55321
FLANNEL_VERSION=v1.2.0-flannel2-go1.22.7
CONTAINERNETWORKING_PLUGINS_REPO=https://github.com/projectcalico/containernetworking-plugins.git
FLANNEL_CNI_PLUGIN_REPO=https://github.com/projectcalico/flannel-cni-plugin.git

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

# quay.io expiry time for hashrelease/dev images
QUAY_EXPIRE_DAYS=90

