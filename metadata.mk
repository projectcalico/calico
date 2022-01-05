#################################################################################################
# This file contains Makefile configuration parameters and metadata for this branch.
#################################################################################################

# The version of github.com/projectcalico/go-build to use.
GO_BUILD_VER = v0.65

# Version of Kubernetes to use for tests.
K8S_VERSION     = v1.22.1
KUBECTL_VERSION = v1.22.1

# Version of various tools used in the build and tests.
COREDNS_VERSION=1.5.2
ETCD_VERSION=v3.5.0
PROTOC_VER=v0.1

# Configuration for Semaphore integration.
ORGANIZATION = projectcalico

# Configure git to access repositories using SSH.
GIT_USE_SSH = true

# The version of BIRD to use for calico/node builds and confd tests.
BIRD_VERSION=v0.3.3-184-g202a2186

# DEV_REGISTRIES configures the container image registries which are built from this
# repository. By default, just build images with calico/. CI/CD will override this
# variable to quay.io/calico and docker.io/calico
DEV_REGISTRIES = calico

# RELEASE_REGISTIRES configures the container images registries which are published to 
# as part of an official release.
RELEASE_REGISTRIES = quay.io/calico docker.io/calico gcr.io/projectcalico-org eu.gcr.io/projectcalico-org asia.gcr.io/projectcalico-org us.gcr.io/projectcalico-org
