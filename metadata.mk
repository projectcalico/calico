#################################################################################################
# This file contains Makefile configuration parameters and metadata for this branch.
#################################################################################################

# The version of calico/go-build and calico/base to use.
GO_BUILD_VER=1.24.1-llvm18.1.8-k8s1.32.2
CALICO_BASE_VER=ubi8-1741131622
# TODO Remove once CALICO_BASE is updated to UBI9
CALICO_BASE_UBI9_VER=ubi9-1741131622

# Env var to ACK Ginkgo deprecation warnings, may need updating with go-build.
ACK_GINKGO=ACK_GINKGO_DEPRECATIONS=1.16.5

# Version of Kubernetes to use for tests, bitnami/kubectl, and kubectl binary release.
K8S_VERSION=v1.32.3

# Version of various tools used in the build and tests.
COREDNS_VERSION=1.5.2
ETCD_VERSION=v3.5.6
GHR_VERSION=v0.17.0
HELM_VERSION=v3.11.3
KINDEST_NODE_VERSION=v1.31.6
KIND_VERSION=v0.27.0

# Configuration for Semaphore/Github integration.  This needs to be set
# differently for a forked repo.
ORGANIZATION = projectcalico
GIT_REPO = calico

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
WINDOWS_VERSIONS ?= 1809 ltsc2022

# The CNI plugin and flannel code that will be cloned and rebuilt with this repo's go-build image
# whenever the cni-plugin image is created.
CNI_VERSION=master
FLANNEL_VERSION=main

# The libbpf version to use
LIBBPF_VERSION=v1.4.6

# The bpftool image to use; this is the output of the https://github.com/projectcalico/bpftool repo.
BPFTOOL_IMAGE=calico/bpftool:v7.5.0

# The operator branch corresponding to this branch.
OPERATOR_BRANCH=master
