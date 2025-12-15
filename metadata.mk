#################################################################################################
# This file contains Makefile configuration parameters and metadata for this branch.
#################################################################################################

# The version of calico/go-build and calico/base to use.
GO_BUILD_VER=1.25.5-llvm18.1.8-k8s1.34.2
CALICO_BASE_VER=ubi9-1764706938

# Env var to ACK Ginkgo deprecation warnings, may need updating with go-build.
ACK_GINKGO=ACK_GINKGO_DEPRECATIONS=1.16.5

# Version of Kubernetes to use for tests, rancher/kubectl, and kubectl binary release.
K8S_VERSION=v1.34.1

# Version of various tools used in the build and tests.
COREDNS_VERSION=1.5.2
CRANE_VERSION=v0.20.6
ETCD_VERSION=v3.5.24
GHR_VERSION=v0.17.0
GITHUB_CLI_VERSION=2.76.2
GOTESTSUM_VERSION=v1.12.3
HELM_VERSION=v3.11.3
KINDEST_NODE_VERSION=v1.34.0
KIND_VERSION=v0.29.0

# Configuration for Semaphore/Github integration.  This needs to be set
# differently for a forked repo.
ORGANIZATION  ?= projectcalico
GIT_REPO      ?= calico

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

# The CNI plugin and flannel code that will be cloned and rebuilt with this repo's go-build image
# whenever the cni-plugin image is created.
CNI_VERSION=master
FLANNEL_VERSION=main

# The libbpf version to use
LIBBPF_VERSION=v1.4.6

# The bpftool image to use; this is the output of the https://github.com/projectcalico/bpftool repo.
BPFTOOL_IMAGE=calico/bpftool:v7.5.0

# The operator branch corresponding to this branch.
OPERATOR_BRANCH ?= master
OPERATOR_ORGANIZATION ?= tigera
OPERATOR_GIT_REPO     ?= operator

# quay.io expiry time for hashrelease/dev images
QUAY_EXPIRE_DAYS=90
