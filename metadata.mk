#################################################################################################
# This file contains Makefile configuration parameters and metadata for this branch.
#################################################################################################

# The version of github.com/projectcalico/go-build to use.
GO_BUILD_VER=v0.95
# Env var to ACK Ginkgo deprecation warnings, may need updating with go-build.
ACK_GINKGO=ACK_GINKGO_DEPRECATIONS=1.16.5

# Version of Kubernetes to use for tests, bitnami/kubectl, and kubectl binary release.
K8S_VERSION=v1.30.7

# Version of various tools used in the build and tests.
COREDNS_VERSION=1.5.2
ETCD_VERSION=v3.5.6
GHR_VERSION=v0.17.0
HELM_VERSION=v3.11.3
KINDEST_NODE_VERSION=v1.30.6
KIND_VERSION=v0.25.0
PROTOC_VER=v0.1
UBI_VERSION=8.10

# Configuration for Semaphore/Github integration.  This needs to be set
# differently for a forked repo.
ORGANIZATION = projectcalico
GIT_REPO = calico

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

# The operator branch corresponding to this branch.
OPERATOR_BRANCH=master

