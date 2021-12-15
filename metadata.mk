#################################################################################################
# This file contains Makefile configuration parameters and metadata for this branch.
#################################################################################################

# The version of github.com/projectcalico/go-build to use.
GO_BUILD_VER = v0.62

# Version of Kubernetes to use for tests.
K8S_VERSION     = v1.22.1
KUBECTL_VERSION = v1.22.1

# Configuration for Semaphore integration.
ORGANIZATION = projectcalico

# Configure git to access repositories using SSH.
GIT_USE_SSH = true

# The version of BIRD to use for calico/node builds and confd tests.
BIRD_VERSION=v0.3.3-184-g202a2186

# TODO: Update Makefiles to pull registry configuration from here.
# DEV_REGISTRIES configures the container image registries which are published to as part of 
# this branches CI/CD pipeline.
#DEV_REGISTRIES = quay.io docker.io

# TODO: Update Makefiles to pull registry configuration from here.
# RELEASE_REGISTIRES configures the container images registries which are published to 
# as part of an official release.
#RELEASE_REGISTRIES = $(DEV_REGISTRIES)
