# Disable built-in rules
.SUFFIXES:

# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut fv st

###############################################################################
# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
# This variable is only set if ARCHES is not set
ARCHES ?= $(patsubst docker-image/Dockerfile.%,%,$(wildcard docker-image/Dockerfile.*))

# Some repositories keep their Dockerfile(s) in the root directory instead of in
# the 'docker-image' subdir. Make sure ARCHES gets filled in either way.
ifeq ($(ARCHES),)
	ARCHES=$(patsubst Dockerfile.%,%,$(wildcard Dockerfile.*))
endif

# If architectures cannot infer from Dockerfiles, set default supported architecture.
ifeq ($(ARCHES),)
	ARCHES=amd64 arm64 ppc64le s390x
endif

# list of arches *not* to build when doing *-all
EXCLUDEARCH?=
VALIDARCHES = $(filter-out $(EXCLUDEARCH),$(ARCHES))

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
# Note: OS is always set on Windows
ifeq ($(OS),Windows_NT)
BUILDARCH = x86_64
BUILDOS = Windows
else
BUILDARCH ?= $(shell uname -m)
BUILDOS ?= $(shell uname -s | tr A-Z a-z)
endif

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
	BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
	BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
ARCH ?= $(BUILDARCH)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
	override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
	override ARCH=amd64
endif

# detect the local outbound ip address
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')

LATEST_IMAGE_TAG?=latest

# these macros create a list of valid architectures for pushing manifests
comma := ,
double_quote := $(shell echo '"')

## Targets used when cross building.
.PHONY: native register
native:
ifneq ($(BUILDARCH),$(ARCH))
	@echo "Target $(MAKECMDGOALS)" is not supported when cross building! && false
endif

# Enable binfmt adding support for miscellaneous binary formats.
# This is only needed when running non-native binaries.
register:
ifneq ($(BUILDARCH),$(ARCH))
	docker run --privileged --rm calico/binfmt:qemu-v10.1.3 --install all || true
endif

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGES+=$(RELEASE_IMAGES)
endif

DOCKERHUB_REGISTRY ?=registry.hub.docker.com
# filter-registry filters out registries we don't want to include when tagging / pushing docker images. For instance,
# we don't include the registry name when pushing to docker hub because that registry is the default.
filter-registry ?= $(if $(filter-out $(1),$(DOCKERHUB_REGISTRY)),$(1)/)

# Convenience function to get the first dev image repo in the list.
DEV_REGISTRY ?= $(firstword $(DEV_REGISTRIES))

# remove from the list to push to manifest any registries that do not support multi-arch
MANIFEST_REGISTRIES         ?= $(DEV_REGISTRIES)

PUSH_MANIFEST_IMAGES := $(foreach registry,$(MANIFEST_REGISTRIES),$(foreach image,$(BUILD_IMAGES),$(call filter-registry,$(registry))$(image)))

# location of docker credentials to push manifests
DOCKER_CONFIG ?= $(HOME)/.docker/config.json

# If a repository still relies on vendoring, it must set GOMOD_VENDOR to "true".
# If that's not the case and we're running in CI, set -mod=readonly to prevent builds
# from being flagged as dirty due to updates in go.mod or go.sum _except_ for:
# - for local builds, which _require_ a change to go.mod.
# - the targets 'commit-pin-updates' and  'golangci-lint' which require
#   updating go.mod and/or go.sum
SKIP_GOMOD_READONLY_FLAG =
ifeq ($(MAKECMDGOALS),commit-pin-updates)
	SKIP_GOMOD_READONLY_FLAG = yes
endif
ifeq ($(MAKECMDGOALS),golangci-lint)
	SKIP_GOMOD_READONLY_FLAG = yes
endif

ifeq ($(GOMOD_VENDOR),true)
	GOFLAGS?="-mod=vendor"
else
ifeq ($(CI),true)
ifndef SKIP_GOMOD_READONLY_FLAG
	GOFLAGS?="-mod=readonly"
endif
endif
endif

# For building, we use the go-build image for the *host* architecture, even if the target is different
# the one for the host should contain all the necessary cross-compilation tools
# we do not need to use the arch since go-build:v0.15 now is multi-arch manifest
GO_BUILD_IMAGE ?= calico/go-build
CALICO_BUILD    = $(GO_BUILD_IMAGE):$(GO_BUILD_VER)


# We use BoringCrypto as FIPS validated cryptography in order to allow users to run in FIPS Mode (amd64 only).
ifeq ($(ARCH), $(filter $(ARCH),amd64))
GOEXPERIMENT?=boringcrypto
TAGS?=boringcrypto,osusergo,netgo
CGO_ENABLED?=1
else
CGO_ENABLED?=0
endif

# Build a binary with boring crypto support.
# This function expects you to pass in two arguments:
#   1st arg: path/to/input/package(s)
#   2nd arg: path/to/output/binary
# Only when arch = amd64 it will use boring crypto to build the binary.
# Uses LDFLAGS, CGO_LDFLAGS, CGO_CFLAGS when set.
# Tests that the resulting binary contains boringcrypto symbols.
define build_cgo_boring_binary
	$(DOCKER_RUN) \
		-e CGO_ENABLED=1 \
		-e CGO_CFLAGS=$(CGO_CFLAGS) \
		-e CGO_LDFLAGS=$(CGO_LDFLAGS) \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) GOEXPERIMENT=boringcrypto go build -o $(2) -tags fipsstrict -v -buildvcs=false -ldflags "$(LDFLAGS)" $(1) \
			&& go tool nm $(2) | grep '_Cfunc__goboringcrypto_' 1> /dev/null'
endef

# Use this when building binaries that need cgo, but have no crypto and therefore would not contain any boring symbols.
define build_cgo_binary
	$(DOCKER_RUN) \
		-e CGO_ENABLED=1 \
		-e CGO_CFLAGS=$(CGO_CFLAGS) \
		-e CGO_LDFLAGS=$(CGO_LDFLAGS) \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -o $(2) -v -buildvcs=false -ldflags "$(LDFLAGS)" $(1)'
endef

# For binaries that do not require boring crypto.
define build_binary
	$(DOCKER_RUN) \
		-e CGO_ENABLED=0 \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -o $(2) -v -buildvcs=false -ldflags "$(LDFLAGS)" $(1)'
endef

# For windows builds that do not require cgo.
define build_windows_binary
	$(DOCKER_RUN) \
		-e CGO_ENABLED=0 \
		-e GOARCH=amd64 \
		-e GOOS=windows \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -o $(2) -v -buildvcs=false -ldflags "$(LDFLAGS)" $(1)'
endef

# Images used in build / test across multiple directories.
ETCD_IMAGE ?= quay.io/coreos/etcd:$(ETCD_VERSION)-$(ARCH)
ifeq ($(BUILDARCH),amd64)
	# *-amd64 tagged images for etcd are not available until v3.5.0
	ETCD_IMAGE = quay.io/coreos/etcd:$(ETCD_VERSION)
endif

UBI_IMAGE ?= registry.access.redhat.com/ubi9/ubi-minimal:latest

ifeq ($(GIT_USE_SSH),true)
	GIT_CONFIG_SSH ?= git config --global url."ssh://git@github.com/".insteadOf "https://github.com/";
endif

# Get version from git. We allow setting this manually for the hashrelease process.
# By default, includes commit count and hash (--long). During releases (RELEASE=true),
# only the tag is used without the commit count suffix.
GIT_VERSION ?= $(shell git describe --tags --dirty --always --abbrev=12 --long)
ifeq ($(RELEASE),true)
	GIT_VERSION := $(shell git describe --tags --dirty --always --abbrev=12)
endif

# Figure out version information.  To support builds from release tarballs, we default to
# <unknown> if this isn't a git checkout.
GIT_COMMIT:=$(shell git rev-parse HEAD || echo '<unknown>')
BUILD_ID:=$(shell git rev-parse HEAD || uuidgen | sed 's/-//g')

# Lazily set the git version we embed into the binaries we build. We want the
# git tag at the time we build the binary.
# Variables elsewhere that depend on this (such as LDFLAGS) must also be lazy.
GIT_DESCRIPTION=$(shell git describe --tags --dirty --always --abbrev=12 || echo '<unknown>')

# Calculate a timestamp for any build artifacts.
ifneq ($(OS),Windows_NT)
DATE:=$(shell date -u +'%FT%T%z')
endif

# Common linker flags.
#
# We use -X to insert the version information into the placeholder variables
# in the buildinfo package.
LDFLAGS=-X github.com/projectcalico/calico/pkg/buildinfo.Version=$(GIT_DESCRIPTION) \
	-X github.com/projectcalico/calico/pkg/buildinfo.BuildDate=$(DATE) \
	-X github.com/projectcalico/calico/pkg/buildinfo.GitRevision=$(GIT_COMMIT)

# We use -B to insert a build ID note into the executable, without which, the
# RPM build tools complain.
ifneq ($(BUILDOS),darwin)
	LDFLAGS+=-B 0x$(BUILD_ID)
endif

# Figure out the users UID/GID.  These are needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
ifneq ($(OS),Windows_NT)
LOCAL_USER_ID:=$(shell id -u)
LOCAL_GROUP_ID:=$(shell id -g)
endif

ifeq ("$(LOCAL_USER_ID)", "0")
# The build needs to run as root.
EXTRA_DOCKER_ARGS+=-e RUN_AS_ROOT='true'
endif

# Allow the ssh auth sock to be mapped into the build container.
ifdef SSH_AUTH_SOCK
	EXTRA_DOCKER_ARGS += -v $(SSH_AUTH_SOCK):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent
endif

# Volume-mount gopath into the build container to cache go module's packages. If the environment is using multiple
# comma-separated directories for gopath, use the first one, as that is the default one used by go modules.
ifneq ($(GOPATH),)
	# If the environment is using multiple comma-separated directories for gopath, use the first one, as that
	# is the default one used by go modules.
	GOMOD_CACHE = $(shell echo $(GOPATH) | cut -d':' -f1)/pkg/mod
else
	# If gopath is empty, default to $(HOME)/go.
	GOMOD_CACHE = $(HOME)/go/pkg/mod
endif

EXTRA_DOCKER_ARGS += -v $(GOMOD_CACHE):/go/pkg/mod:rw

# Define go architecture flags
GOARCH_FLAGS :=-e GOARCH=$(ARCH)

ifeq ($(ARCH),amd64)
GOARCH_FLAGS += -e GOAMD64=v2
endif

# Location of certificates used in UTs.
REPO_ROOT := $(shell git rev-parse --show-toplevel)
CERTS_PATH := $(REPO_ROOT)/hack/test/certs

# Support for git worktrees.  In a worktree, .git is a file pointing to
# <main-repo>/.git/worktrees/<name>.  When Docker containers need git access,
# the main .git directory must also be mounted, and GIT_DIR / GIT_WORK_TREE
# must be set so that git can find objects and the correct working tree.
_GIT_DIR := $(shell git rev-parse --absolute-git-dir 2>/dev/null)
_GIT_COMMON_DIR := $(realpath $(shell git rev-parse --git-common-dir 2>/dev/null))
ifneq ($(_GIT_DIR),$(_GIT_COMMON_DIR))
# Running in a git worktree: mount the main .git directory at its host path
# so the worktree .git file pointer resolves inside the container.
# DOCKER_GIT_WORK_TREE can be overridden by Makefiles that mount the repo at
# a different container path (e.g. api/Makefile).
DOCKER_GIT_WORK_TREE ?= /go/src/github.com/projectcalico/calico
DOCKER_GIT_WORKTREE_ARGS := \
	-v $(_GIT_COMMON_DIR):$(_GIT_COMMON_DIR):ro \
	-e GIT_DIR=$(_GIT_DIR) \
	-e GIT_WORK_TREE=$(DOCKER_GIT_WORK_TREE)
else
DOCKER_GIT_WORKTREE_ARGS :=
endif

# Configure the Calico API group to use. Projects importing this Makefile can override this variable
# if they need to.
# Supported values:
# - crd.projectcalico.org/v1 (default)
# - projectcalico.org/v3
CALICO_API_GROUP ?= crd.projectcalico.org/v1

# Where to find Calico CRD files depends on which API group we are using to back them.
CALICO_CRD_PATH ?= api/config/crd/
ifneq ($(CALICO_API_GROUP),projectcalico.org/v3)
CALICO_CRD_PATH = libcalico-go/config/crd/
endif

# The image to use for building calico/base-dependent modules (e.g. apiserver, typha).
ifdef USE_UBI_AS_CALICO_BASE
CALICO_BASE ?= $(UBI_IMAGE)
else
CALICO_BASE ?= calico/base:$(CALICO_BASE_VER)
endif

ifndef NO_DOCKER_PULL
DOCKER_PULL = --pull
else
DOCKER_PULL =
endif

# DOCKER_BUILD is the base build command used for building all images.
DOCKER_BUILD=docker buildx build --load --platform=linux/$(ARCH) $(DOCKER_PULL)\
	--build-arg UBI_IMAGE=$(UBI_IMAGE) \
	--build-arg GIT_VERSION=$(GIT_VERSION) \
	--build-arg CALICO_BASE=$(CALICO_BASE) \
	--build-arg BPFTOOL_IMAGE=$(BPFTOOL_IMAGE)

DOCKER_RUN_PRIV_NET := mkdir -p $(REPO_ROOT)/.go-pkg-cache bin $(GOMOD_CACHE) && \
	docker run --rm \
		--init \
		$(EXTRA_DOCKER_ARGS) \
		$(DOCKER_GIT_WORKTREE_ARGS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		$(GOARCH_FLAGS) \
		-e GOPATH=/go \
		-e OS=$(BUILDOS) \
		-e GOOS=$(BUILDOS) \
		-e CALICO_API_GROUP=$(CALICO_API_GROUP) \
		-e "GOFLAGS=$(GOFLAGS)" \
		-v $(REPO_ROOT):/go/src/github.com/projectcalico/calico:rw \
		-v $(REPO_ROOT)/.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

DOCKER_RUN := $(DOCKER_RUN_PRIV_NET) --net=host

DOCKER_GO_BUILD := $(DOCKER_RUN) $(CALICO_BUILD)

# A target that does nothing but it always stale, used to force a rebuild on certain targets based on some non-file criteria.
.PHONY: force-rebuild
force-rebuild:

###############################################################################
# Updating pins
#   the repo importing this Makefile _must_ define the update-pins target
#   for example:
#     update-pins: update-libcalico-pin update-typha-pin
###############################################################################
PIN_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)

# The docker entrypoint script might echo output that could be included in the output of the following command, so this
# prefixes the commit tag with "commit-tag:" so can reliable get the commit tag from the output.
define get_remote_version
	$(shell $(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) echo "commit-tag:$$(git ls-remote https://$(1) $(2) | cut -f1)"' | awk -F "commit-tag:" '{print $$2}')
endef

# update_pin updates the given package's version to the latest available in the specified repo and branch.
# $(1) should be the name of the package, $(2) and $(3) the repository and branch from which to update it.
# If $(4) is specified it's treated as the module version and use in the go get -d command.
define update_pin
	$(eval new_ver := $(call get_remote_version,$(2),$(3)))
	$(eval repo := $(if $(4),$(1)/$(4),$(1)))

	$(DOCKER_RUN) -i $(CALICO_BUILD) sh -c '\
		if [ ! -z "$(new_ver)" ]; then \
			$(GIT_CONFIG_SSH) \
			go get -d $(repo)@$(new_ver); \
			go mod tidy; \
		fi'
endef

# update_replace_pin updates the given package's version to the latest available in the specified repo and branch.
# This routine can only be used for packages being replaced in go.mod, such as private versions of open-source packages.
# $(1) should be the name of the package, $(2) and $(3) the repository and branch from which to update it. If $(4) is
# specified it's treated as the module version and use in the go mod edit -replace command.
define update_replace_pin
	$(eval new_ver := $(call get_remote_version,$(2),$(3)))
	$(eval original_repo := $(if $(4),$(1)/$(4),$(1)))
	$(eval replace_repo := $(if $(4),$(2)/$(4),$(2)))

	$(DOCKER_RUN) -i $(CALICO_BUILD) sh -c '\
		if [ ! -z "$(new_ver)" ]; then \
			$(GIT_CONFIG_SSH) \
			go mod edit -replace $(original_repo)=$(replace_repo)@$(new_ver); \
			go mod tidy; \
		fi'
endef

# Get the latest release tag from projectcalico/go-build.
GO_BUILD_REPO=https://github.com/projectcalico/go-build.git
define get_go_build_version
	$(shell git ls-remote --tags --refs --sort=-version:refname $(GO_BUILD_REPO) | head -n 1 | awk -F '/' '{print $$NF}')
endef

# update_go_build_pin updates the GO_BUILD_VER in metadata.mk or Makefile.
# for annotated git tags, we need to remove the trailing `^{}`.
# for the obsoleted vx.y go-build version, we need to remove the leading `v` for bash string comparison to work properly.
define update_go_build_pin
	$(eval new_ver := $(subst ^{},,$(call get_go_build_version)))
	$(eval old_ver := $(shell grep -E "^GO_BUILD_VER" $(1) | cut -d'=' -f2 | xargs | sed 's/^v//'))

	@echo "current GO_BUILD_VER=$(old_ver)"
	@echo "latest GO_BUILD_VER=$(new_ver)"

	bash -c '\
		if [[ "$(new_ver)" > "$(old_ver)" ]]; then \
			sed -i "s/^GO_BUILD_VER[[:space:]]*=.*/GO_BUILD_VER=$(new_ver)/" $(1); \
			echo "GO_BUILD_VER is updated to $(new_ver)"; \
		else \
			echo "no need to update GO_BUILD_VER"; \
		fi'
endef

# update_calico_base_pin updates the CALICO_BASE_VER in metadata.mk.
define update_calico_base_pin
	$(eval new_ver := $(shell curl -s "https://hub.docker.com/v2/repositories/calico/base/tags/?page_size=100" | jq -r '.results[].name' | grep -E "^ubi9-[0-9]+$$" | sort -r | head -n 1))
	$(eval old_ver := $(shell grep -E "^CALICO_BASE_VER" $(1) | cut -d'=' -f2 | xargs))

	@echo "current CALICO_BASE_VER=$(old_ver)"
	@echo "latest CALICO_BASE_VER=$(new_ver)"

	bash -c '\
		if [[ "$(new_ver)" > "$(old_ver)" ]]; then \
			sed -i "s/^CALICO_BASE_VER[[:space:]]*=.*/CALICO_BASE_VER=$(new_ver)/" $(1); \
			echo "CALICO_BASE_VER is updated to $(new_ver)"; \
		else \
			echo "no need to update CALICO_BASE_VER"; \
		fi'
endef

GIT_REMOTE?=origin
API_BRANCH?=$(PIN_BRANCH)
API_REPO?=github.com/projectcalico/calico/api
BASE_API_REPO?=github.com/projectcalico/calico/api
APISERVER_BRANCH?=$(PIN_BRANCH)
APISERVER_REPO?=github.com/projectcalico/calico/apiserver
TYPHA_BRANCH?=$(PIN_BRANCH)
TYPHA_REPO?=github.com/projectcalico/calico/typha
LIBCALICO_BRANCH?=$(PIN_BRANCH)
LIBCALICO_REPO?=github.com/projectcalico/calico/libcalico-go
CONFD_BRANCH?=$(PIN_BRANCH)
CONFD_REPO?=github.com/projectcalico/calico/confd
FELIX_BRANCH?=$(PIN_BRANCH)
FELIX_REPO?=github.com/projectcalico/calico/felix
CNI_BRANCH?=$(PIN_BRANCH)
CNI_REPO?=github.com/projectcalico/calico/cni-plugin

update-api-pin:
	$(call update_pin,$(API_REPO),$(API_REPO),$(API_BRANCH))

replace-api-pin:
	$(call update_replace_pin,$(BASE_API_REPO),$(API_REPO),$(API_BRANCH))

update-apiserver-pin:
	$(call update_pin,github.com/projectcalico/calico/apiserver,$(APISERVER_REPO),$(APISERVER_BRANCH))

replace-apiserver-pin:
	$(call update_replace_pin,github.com/projectcalico/calico/apiserver,$(APISERVER_REPO),$(APISERVER_BRANCH))

update-typha-pin:
	$(call update_pin,github.com/projectcalico/calico/typha,$(TYPHA_REPO),$(TYPHA_BRANCH))

replace-typha-pin:
	$(call update_replace_pin,github.com/projectcalico/calico/typha,$(TYPHA_REPO),$(TYPHA_BRANCH))

update-libcalico-pin:
	$(call update_pin,github.com/projectcalico/calico/libcalico-go,$(LIBCALICO_REPO),$(LIBCALICO_BRANCH))

replace-libcalico-pin:
	$(call update_replace_pin,github.com/projectcalico/calico/libcalico-go,$(LIBCALICO_REPO),$(LIBCALICO_BRANCH))

update-confd-pin:
	$(call update_replace_pin,github.com/kelseyhightower/confd,$(CONFD_REPO),$(CONFD_BRANCH))

update-felix-pin:
	$(call update_pin,github.com/projectcalico/calico/felix,$(FELIX_REPO),$(FELIX_BRANCH))

replace-felix-pin:
	$(call update_replace_pin,github.com/projectcalico/calico/felix,$(FELIX_REPO),$(FELIX_BRANCH))

update-cni-plugin-pin:
	$(call update_pin,github.com/projectcalico/calico/cni-plugin,$(CNI_REPO),$(CNI_BRANCH))

replace-cni-pin:
	$(call update_replace_pin,github.com/projectcalico/calico/cni-plugin,$(CNI_REPO),$(CNI_BRANCH))

update-go-build-pin:
	$(call update_go_build_pin,$(GIT_GO_BUILD_UPDATE_COMMIT_FILE))

update-calico-base-pin:
	$(call update_calico_base_pin,$(GIT_GO_BUILD_UPDATE_COMMIT_FILE))

git-status:
	git status --porcelain

git-config:
ifdef CONFIRM
	git config --global user.name "marvin-tigera"
	git config --global user.email "marvin@projectcalico.io"
endif

git-commit:
	git diff --quiet HEAD || git commit -m "Semaphore Automatic Update" go.mod go.sum $(EXTRA_FILES_TO_COMMIT)

###############################################################################
# External resource affecting macros
# The following macros affect resources outside of the local environment that
# they're run in, i.e. pushing to docker or github. If CONFIM is not defined,
# then the commands are just printed, instead of run.
#
# The <command>-cmd macro should never be run directly, it's used to define
# the command the macro runs but depending on whether CONFIRM is defined the
# command may be printed or run.
#
# You can redefine <command>-cmd to have the targets in this makefile use a
# different implementation.
###############################################################################

ifdef LOCAL_CRANE
CRANE_CMD         = crane
else
CRANE_CMD         = $(REPO_ROOT)/bin/crane
endif

ifdef LOCAL_PYTHON
PYTHON3_CMD       = python3
else
PYTHON3_CMD       = docker run --rm -e QUAY_API_TOKEN -v $(REPO_ROOT):$(REPO_ROOT) -w $(REPO_ROOT) python:3.13 python3.13
endif

GIT_CMD           = git
DOCKER_CMD        = docker


# RELEASE_PY3 is for Python invocations used for releasing,
# where we want to be able to DRY_RUN them.
ifdef CONFIRM
CRANE         = $(CRANE_CMD)
GIT           = $(GIT_CMD)
DOCKER        = $(DOCKER_CMD)
RELEASE_PY3   = $(PYTHON3_CMD)
else
CRANE         = echo [DRY RUN] $(CRANE_CMD)
GIT           = echo [DRY RUN] $(GIT_CMD)
DOCKER        = echo [DRY RUN] $(DOCKER_CMD)
RELEASE_PY3   = echo [DRY RUN] $(PYTHON3_CMD)
endif

QUAY_SET_EXPIRY_SCRIPT = $(REPO_ROOT)/hack/set_quay_expiry.py

commit-and-push-pr:
	$(GIT) add $(GIT_COMMIT_FILES)
	$(GIT) commit -m $(GIT_COMMIT_MESSAGE)
	$(GIT) push $(GIT_REMOTE) $(GIT_PR_BRANCH_HEAD)

###############################################################################
# GitHub API helpers
#   Helper macros and targets to help with communicating with the github API
###############################################################################
GIT_COMMIT_MESSAGE?="Automatic Pin Updates"
GIT_COMMIT_TITLE?="Semaphore Auto Pin Update"
GIT_PR_BRANCH_BASE?=$(SEMAPHORE_GIT_BRANCH)
PIN_UPDATE_BRANCH?=semaphore-auto-pin-updates-$(GIT_PR_BRANCH_BASE)
GIT_PR_BRANCH_HEAD?=$(PIN_UPDATE_BRANCH)
GIT_PIN_UPDATE_COMMIT_FILES?=go.mod go.sum
GIT_GO_BUILD_UPDATE_COMMIT_FILE?=metadata.mk
GIT_PIN_UPDATE_COMMIT_EXTRA_FILES?=$(GIT_COMMIT_EXTRA_FILES)
GIT_COMMIT_FILES?=$(GIT_PIN_UPDATE_COMMIT_FILES) $(GIT_PIN_UPDATE_COMMIT_EXTRA_FILES)

# Call the github API. $(1) is the http method type for the https request, $(2) is the repo slug, and is $(3) is for json
# data (if omitted then no data is set for the request). If GITHUB_API_EXIT_ON_FAILURE is set then the macro exits with 1
# on failure. On success, the ENV variable GITHUB_API_RESPONSE will contain the response from github
define github_call_api
	$(eval CMD := curl -f -X$(1) \
		-H "Content-Type: application/json"\
		-H "Authorization: token ${GITHUB_TOKEN}"\
		https://api.github.com/repos/$(2) $(if $(3),--data '$(3)',))
	$(eval GITHUB_API_RESPONSE := $(shell $(CMD) | sed -e 's/#/\\\#/g'))
	$(if $(GITHUB_API_EXIT_ON_FAILURE), $(if $(GITHUB_API_RESPONSE),,exit 1),)
endef

# Create the pull request. $(1) is the repo slug, $(2) is the title, $(3) is the head branch and $(4) is the base branch.
# If the call was successful then the ENV variable PR_NUMBER will contain the pull request number of the created pull request.
define github_pr_create
	$(eval JSON := {"title": "$(2)", "head": "$(3)", "base": "$(4)"})
	$(call github_call_api,POST,$(1)/pulls,$(JSON))
	$(eval PR_NUMBER := $(filter-out null,$(shell echo '$(GITHUB_API_RESPONSE)' | jq '.number')))
endef

# Create a comment on a pull request. $(1) is the repo slug, $(2) is the pull request number, and $(3) is the comment
# body.
define github_pr_add_comment
	$(eval JSON := {"body":"$(3)"})
	$(call github_call_api,POST,$(1)/issues/$(2)/comments,$(JSON))
endef

# List pull open pull requests for a head and base. $(1) is the repo slug, $(2) is the branch head, $(3) is the branch base,
# and $(4) is the state.
define github_pr_list
	$(eval QUERY := $(if $(2),head=$(2),)$(if $(3),\&base=$(3))$(if $(4),\&state=$(4),))
	$(call github_call_api,GET,$(1)/pulls?$(QUERY),)
endef

# Check if there is a pull request with head GIT_PR_BRANCH_HEAD and base GIT_PR_BRANCH_BASE for the repo with slug
# GIT_REPO_SLUG. If there is a PR that exists the PR_EXISTS will be set to 0, otherwise it is set to 1.
check-if-pin-update-pr-exists:
ifndef ORGANIZATION
	@echo "ORGANIZATION must be set for the project."
	exit 1
endif
	$(call github_pr_list,$(GIT_REPO_SLUG),$(ORGANIZATION):$(GIT_PR_BRANCH_HEAD),$(GIT_PR_BRANCH_BASE),open)
	$(eval PR_EXISTS := $(if $(filter-out 0,$(shell echo '$(GITHUB_API_RESPONSE)' | jq '. | length')),0,1))

###############################################################################
# Auto pin update targets
#   Targets updating the pins
###############################################################################
GITHUB_API_EXIT_ON_FAILURE?=1

## Update dependency pins to their latest changeset, committing and pushing it.
## DEPRECATED This will be removed along with associated helper functions in future releases. Use the trigger-auto-pin-update-process
## to create PR with the pin updates.
.PHONY: commit-pin-updates
commit-pin-updates: update-pins git-status git-config git-commit ci git-push

# Creates and checks out the branch defined by GIT_PR_BRANCH_HEAD. It attempts to delete the branch from the local and
# remote repositories. Requires CONFIRM to be set, otherwise it fails with an error.
create-pin-update-head: var-require-one-of-CONFIRM-DRYRUN
ifeq ($(shell git rev-parse --abbrev-ref HEAD),$(GIT_PR_BRANCH_HEAD))
	@echo "Current branch is pull request head, cannot set it up."
	exit 1
endif
	-git branch -D $(GIT_PR_BRANCH_HEAD)
	-$(GIT) push $(GIT_REMOTE) --delete $(GIT_PR_BRANCH_HEAD)
	git checkout -b $(GIT_PR_BRANCH_HEAD)

create-pin-update-pr:
	$(call github_pr_create,$(GIT_REPO_SLUG),[$(GIT_PR_BRANCH_BASE)] $(GIT_COMMIT_TITLE),$(GIT_PR_BRANCH_HEAD),$(GIT_PR_BRANCH_BASE))
	echo 'Created pin update pull request $(PR_NUMBER)'

# Add the "/merge-when-ready" comment to enable the "merge when ready" functionality, i.e. when the pull request is passing
# the tests and approved merge it. The PR_NUMBER is set by the dependent target
set-merge-when-ready-on-pin-update-pr:
	$(call github_pr_add_comment,$(GIT_REPO_SLUG),$(PR_NUMBER),/merge-when-ready delete-branch)
	echo "Added '/merge-when-ready' comment command to pull request $(PR_NUMBER)"

# Call the update-pins target with the GIT_PR_BRANCH_BASE as the PIN_BRANCH
trigger-pin-updates:
	PIN_BRANCH=$(GIT_PR_BRANCH_BASE) $(MAKE) update-pins

# POST_PIN_UPDATE_TARGETS is used to specify targets that should be run after the pins have been updated to run targets
# that modify files that are tied to the dependencies. An example would be generated files that would changed based on
# a dependency update. This target would likely need to be used in tandem with GIT_PIN_UPDATE_COMMIT_EXTRA_FILES so the
# update files are committed with the pin update.
POST_PIN_UPDATE_TARGETS ?=

# Trigger the auto pin update process. This involves updating the pins, committing and pushing them to github, creating
# a pull request, and add the "/merge-when-ready" comment command. If there is already a pin update PR for the base
# branch the pin update is not done and the target will exit.
trigger-auto-pin-update-process: check-if-pin-update-pr-exists
	$(if $(filter $(PR_EXISTS),0),echo "A pull request for head '$(GIT_PR_BRANCH_HEAD)' and base '$(GIT_PR_BRANCH_BASE)' already exists.",\
		$(MAKE) trigger-auto-pin-update-process-wrapped)

trigger-auto-pin-update-process-wrapped: create-pin-update-head trigger-pin-updates $(POST_PIN_UPDATE_TARGETS)
	$(if $(shell git diff --quiet HEAD $(GIT_COMMIT_FILES) || echo "true"),\
		$(MAKE) commit-and-push-pr create-pin-update-pr set-merge-when-ready-on-pin-update-pr,echo "Pins are up to date")

###############################################################################
# Static checks
#   repos can specify additional checks by setting LOCAL_CHECKS
###############################################################################
.PHONY: static-checks
## Run static source code checks (lint, formatting, ...)
static-checks: $(LOCAL_CHECKS)
	$(MAKE) golangci-lint

LINT_ARGS ?= --max-issues-per-linter 0 --max-same-issues 0 --timeout 8m

.PHONY: golangci-lint
golangci-lint: $(GENERATED_FILES)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) golangci-lint run $(LINT_ARGS)'

REPO_DIR=$(shell if [ -e hack/format-changed-files.sh ]; then echo '.'; else echo '..'; fi )

.PHONY: fix-changed go-fmt-changed goimports-changed
# Format changed files only.
fix-changed go-fmt-changed goimports-changed:
	if [ "$(SKIP_FIX_CHANGED)" != "true" ]; then \
	  $(DOCKER_RUN) -e release_prefix=$(RELEASE_BRANCH_PREFIX)-v \
	                -e git_repo_slug=$(GIT_REPO_SLUG) \
	                -e parent_branch=$(shell $(REPO_DIR)/hack/find-parent-release-branch.sh) \
	                $(CALICO_BUILD) $(REPO_DIR)/hack/format-changed-files.sh; \
	fi

.PHONY: fix-all go-fmt-all goimports-all
fix-all go-fmt-all goimports-all:
	$(DOCKER_RUN) $(CALICO_BUILD) $(REPO_DIR)/hack/format-all-files.sh

GOMODDER=$(REPO_DIR)/hack/cmd/gomodder/main.go

.PHONY: verify-go-mods
verify-go-mods:
	$(DOCKER_RUN) $(CALICO_BUILD) go run $(GOMODDER)

.PHONY: pre-commit
pre-commit:
	$(DOCKER_RUN) $(CALICO_BUILD) git-hooks/pre-commit-in-container

.PHONY: install-git-hooks
install-git-hooks:
	./install-git-hooks

.PHONY: check-module-path-tigera-api
check-module-path-tigera-api:
	@echo "Checking the repo importing tigera/api and not importing projectcalico/api"
	@IMPORT_TIGERA_API=$$($(DOCKER_GO_BUILD) sh -c 'go list -m github.com/tigera/api > /dev/null 2>&1 && echo yes || echo no'); \
	echo Is tigera/api imported? $$IMPORT_TIGERA_API; \
	if [ "$$IMPORT_TIGERA_API" != "yes" ]; then \
	     echo "Error: This repo should import tigera/api module."; \
	     false; \
	fi
	@IMPORT_PROJECTCALICO_API=$$($(DOCKER_GO_BUILD) sh -c 'go list -m github.com/projectcalico/calico/api > /dev/null 2>&1 && echo yes || echo no'); \
	echo Is projectcalico/api imported? $$IMPORT_PROJECTCALICO_API; \
	if [ "$$IMPORT_PROJECTCALICO_API" != "no" ]; then \
	     echo "Error: This repo should NOT import projectcalico/api module."; \
	     false; \
	fi

.PHONY: check-module-path-projectcalico-api
check-module-path-projectcalico-api:
	@echo "Checking the repo importing projectcalico/api and not importing tigera/api"
	@IMPORT_PROJECTCALICO_API=$$($(DOCKER_GO_BUILD) sh -c 'go list -m github.com/projectcalico/calico/api > /dev/null 2>&1 && echo yes || echo no'); \
	echo Is projectcalico/api imported? $$IMPORT_PROJECTCALICO_API; \
	if [ "$$IMPORT_PROJECTCALICO_API" != "yes" ]; then \
	     echo "Error: This repo should import projectcalico/api module."; \
	     false; \
	fi
	@IMPORT_TIGERA_API=$$($(DOCKER_GO_BUILD) sh -c 'go list -m github.com/tigera/api > /dev/null 2>&1 && echo yes || echo no'); \
	echo Is tigera/api imported? $$IMPORT_TIGERA_API; \
	if [ "$$IMPORT_TIGERA_API" != "no" ]; then \
	     echo "Error: This repo should NOT import tigera/api module."; \
	     false; \
	fi

###############################################################################
# go mod helpers
###############################################################################
mod-download:
	-$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go mod download'

mod-tidy:
	-$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go mod tidy'

###############################################################################
# Semaphore helpers
###############################################################################

# This semaphore project IDs are defined here because you cannot easily look them up in the semaphore API. This gives
# us a single place to define these values, then projects can reference the readable ENV variable when they need a semaphore
# project ID.
SEMAPHORE_API_PROJECT_ID=9625623e-bfc5-435f-9c22-74f9cd8622fc
SEMAPHORE_API_TIGERA_PROJECT_ID=48d23719-405f-4827-b58a-7de0598a6bf5
SEMAPHORE_ANOMALY_DETECTION_JOBS_PROJECT_ID=e506a098-3e89-4802-8165-c59b2a95f8ae
SEMAPHORE_API_SERVER_PROJECT_ID=6e4eb5b2-0150-4624-968d-f96a1cd9c37d
SEMAPHORE_API_SERVER_OSS_PROJECT_ID=10f6c7c1-7eaa-4e75-a9d1-83e5426158b1
SEMAPHORE_APP_POLICY_PRIVATE_PROJECT_ID=fa098f05-b2d2-4cf6-ac83-aa1e38e95670
SEMAPHORE_APP_POLICY_PROJECT_ID=bc654d5c-bb68-4b00-9d02-289291762b1d
SEMAPHORE_BIRD_PROJECT_ID=c1cc5eaf-873b-4113-a85e-a555361413e6
SEMAPHORE_CC_PORTAL=2b3f9721-a851-4a97-981f-0cb81f93ddd0
SEMAPHORE_CALICO_PRIVATE_PROJECT_ID=8a309869-f767-49dc-924f-fa927edbf657
SEMAPHORE_CALICO_PROJECT_ID=828e6de6-ed4b-49c7-9cb5-ac1246d454de
SEMAPHORE_CALICO_USAGE_PROJECT_ID=29f53c2b-8266-4873-879d-19b65960b3fd
SEMAPHORE_CALICOCTL_PRIVATE_PROJECT_ID=8d885379-6a1b-4fc8-aa45-dc0cfb87894a
SEMAPHORE_CALICOCTL_PROJECT_ID=193ce75a-7a47-4c9f-b966-f25c83e62213
SEMAPHORE_CALICOQ_PROJECT_ID=dc79e0e9-a7b3-40f5-8dc2-2818210ee0a9
SEMAPHORE_CLOUD_CONTROLLERS_PRIVATE_PROJECT_ID=f70e6c08-887b-481d-9591-68e243b32b32
SEMAPHORE_CNI_PLUGIN_PRIVATE_PROJECT_ID=f2c02a84-5fcd-49ed-b4cb-a6273409f0de
SEMAPHORE_CNI_PLUGIN_PROJECT_ID=741ec781-5dbb-4494-ba90-ec6831a9b176
SEMAPHORE_COMPLIANCE_PROJECT_ID=958a9147-ec94-4e99-b4c8-de7857653bb9
SEMAPHORE_CONFD_PROJECT_ID=4c6b815f-d42c-4436-aafa-651fbaf5859e
SEMAPHORE_CONFD_PRIVATE_PROJECT_ID=d3a7649a-3a39-45bf-95e9-fd6df3d0a7b1
SEMAPHORE_CURATOR_PROJECT_ID=c391dcff-6933-40e7-a6d1-1dcf7e6e231d
SEMAPHORE_DEEP_PACKET_INSPECTION_PROJECT_ID=81c0981e-979c-4741-8143-22166384afa1
SEMAPHORE_DEXIDP_DOCKER_PROJECT_ID=ee618372-35c8-4f83-bd05-d3a96ac2b276
SEMAPHORE_EGRESS_GATEWAY_PROJECT_ID=f01056ec-75f9-46a0-9ae2-6fc5e391136c
SEMAPHORE_ELASTICSEARCH_DOCKER_PROJECT_ID=0a3a5bf6-19e4-4210-a3fa-15fc857596ac
SEMAPHORE_ELASTICSEARCH_METRICS_PROJECT_ID=306b29c0-aa86-4b76-9c3e-c78a327e7d83
SEMAPHORE_ENVOY_DOCKER_PROJECT_ID=b8db000b-c2c4-44cd-a22d-51df73dfdcba
SEMAPHORE_ES_PROXY_IMAGE_PROJECT_ID=bc7ee48d-0051-4ceb-961d-03659463ada4
SEMAPHORE_ES_GATEWAY_PROJECT_ID=3c01c819-532b-4ccc-8305-5dd45c10bf93
SEMAPHORE_FELIX_PRIVATE_PROJECT_ID=e439cca4-156c-4d23-b611-002601440ad0
SEMAPHORE_FELIX_PROJECT_ID=48267e65-4acc-4f27-a88f-c3df0e8e2c3b
SEMAPHORE_FIREWALL_INTEGRATION_PROJECT_ID=d4307a31-1e46-4622-82e2-886165b77008
SEMAPHORE_FLUENTD_DOCKER_PROJECT_ID=50383fb9-d234-461a-ae00-23e18b7cd5b8
SEMAPHORE_HONEYPOD_CONTROLLER_PROJECT_ID=c010a63a-ac85-48b4-9077-06188408eaee
SEMAPHORE_HONEYPOD_RECOMMENDATION_PROJECT_ID=f07f5fd4-b15a-4ded-ae1e-04801ae4d99a
SEMAPHORE_INGRESS_COLLECTOR_PROJECT_ID=cf7947e4-a886-404d-ac6a-c3f3ac1a7b93
SEMAPHORE_INTRUSION_DETECTION_PROJECT_ID=2beffe81-b05a-41e0-90ce-e0d847dee2ee
SEMAPHORE_KEY_CERT_PROVISIONER_PROJECT_ID=9efb25f3-8c5d-4f22-aab5-4a1f5519bc7c
SEMAPHORE_KUBE_CONTROLLERS_PRIVATE_PROJECT_ID=0b8651d0-6c5d-4076-ab1d-25b120d0f670
SEMAPHORE_KUBE_CONTROLLERS_PROJECT_ID=d688e2ce-8c4a-4402-ba54-3aaa0eb53e5e
SEMAPHORE_KUBECTL_CALICO_PROJECT_ID=37d7cb2b-62b0-4178-9424-de766f2de59b
SEMAPHORE_KIBANA_DOCKER_PROJECT_ID=eaafdbad-4546-4582-b8fa-cea05a80a04d
SEMAPHORE_LIBCALICO_GO_PRIVATE_PROJECT_ID=72fa12b5-5ad5-43ae-b0ac-17f9f7c71030
SEMAPHORE_LIBCALICO_GO_PROJECT_ID=ce3e6bed-1fb6-4501-80e5-2121a266a386
SEMAPHORE_LICENSE_AGENT_PROJECT_ID=beb13609-8ee0-461a-a08b-dab86af1c128
SEMAPHORE_LICENSING_PROJECT_ID=344f1cf0-0c3f-4fa3-b89b-3c35127b3054
SEMAPHORE_L7_COLLECTOR_PROJECT_ID=b02e7bbf-39ee-4c0c-a6f6-793cdf89daa7
SEMAPHORE_LMA_PROJECT_ID=5130e1d3-d9cd-4270-9e62-57f98d34495e
SEMAPHORE_MANAGER_PROJECT_ID=325ca49d-5111-4b07-a54f-dc0c7ec538bb
SEMAPHORE_NETWORKING_CALICO_PROJECT_ID=0a7883cb-b727-4113-948d-b95cb00df6b6
SEMAPHORE_NODE_PRIVATE_PROJECT_ID=edd8246c-7116-473a-81c8-7a3bbbc07228
SEMAPHORE_NODE_PROJECT_ID=980a06a4-9d43-43f8-aedd-a3bfad258de6
SEMAPHORE_OPERATOR_PROJECT_ID=8343e619-cc44-4be4-a9d7-21963ebc1c8f
SEMAPHORE_PACKETCAPTURE_API_PROJECT_ID=f505b00c-57c3-4859-8b97-ff4095b5ab25
SEMAPHORE_PERFORMANCE_HOTSPOTS_PROJECT_ID=6a343a02-0acf-4c52-9cc7-24ee51377e32
SEMAPHORE_POD2DAEMON_PROJECT_ID=eb2eea4f-c185-408e-9837-da0d231428fb
SEMAPHORE_PROMETHEUS_SERVICE_PROJECT_ID=d5b7ed99-8966-46cc-90f2-9027c428db48
SEMAPHORE_SKIMBLE_PROJECT_ID=35171baf-8daf-4725-882f-c301851a6e1d
SEMAPHORE_TS_QUERYSERVER_PROJECT_ID=5dbe4688-0c21-40fb-89f7-a2d64c17401b
SEMAPHORE_TYPHA_PROJECT_ID=c2ea3f0a-58a0-427a-9ed5-6eff8d6543b3
SEMAPHORE_TYPHA_PRIVATE_PROJECT_ID=51e84cb9-0f38-408a-a113-0f5ca71844d7
SEMAPHORE_VOLTRON_PROJECT_ID=9d239362-9594-4c84-8983-868ee19ebd41

SEMAPHORE_WORKFLOW_BRANCH?=master

# Sends a request to the semaphore API to run the request workflow. It requires setting the SEMAPHORE_API_TOKEN, SEMAPHORE_PROJECT_ID,
# SEMAPHORE_WORKFLOW_BRANCH, and SEMAPHORE_WORKFLOW_FILE ENV variables.
semaphore-run-workflow:
	$(eval CMD := curl -f -X POST \
		-H "Authorization: Token $(SEMAPHORE_API_TOKEN)" \
		-d "project_id=$(SEMAPHORE_PROJECT_ID)&reference=$(SEMAPHORE_WORKFLOW_BRANCH)&commit_sha=$(SEMAPHORE_COMMIT_SHA)&pipeline_file=.semaphore/$(SEMAPHORE_WORKFLOW_FILE)" \
		"https://tigera.semaphoreci.com/api/v1alpha/plumber-workflows")
	$(eval SEMAPHORE_API_RESPONSE := $(shell $(CMD) | jq -R '.' | sed -e 's/#/\\\#/g'))
	$(if $(SEMAPHORE_API_RESPONSE),,exit 1)
	$(eval WORKFLOW_ID := $(shell echo $(SEMAPHORE_API_RESPONSE) | jq -r '.workflow_id'))
	@echo Semaphore workflow successfully created here https://tigera.semaphoreci.com/workflows/$(WORKFLOW_ID)

# This is a helpful wrapper of the semaphore-run-workflow target to run the update_pins workflow file for a project.
semaphore-run-auto-pin-update-workflow:
	SEMAPHORE_WORKFLOW_FILE=update_pins.yml $(MAKE) semaphore-run-workflow
	@echo Successfully triggered the semaphore pin update workflow

# This target triggers the 'semaphore-run-auto-pin-update-workflow' target for every SEMAPHORE_PROJECT_ID in the list of
# SEMAPHORE_AUTO_PIN_UPDATE_PROJECT_IDS.
semaphore-run-auto-pin-update-workflows:
	for ID in $(SEMAPHORE_AUTO_PIN_UPDATE_PROJECT_IDS); do\
		SEMAPHORE_WORKFLOW_BRANCH=$(SEMAPHORE_GIT_BRANCH) SEMAPHORE_PROJECT_ID=$$ID $(MAKE) semaphore-run-auto-pin-update-workflow; \
	done

###############################################################################
# Mock helpers
###############################################################################
# Helper targets for testify mock generation

# Generate testify mocks in the build container.
gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(MAKE) mockery-run'

# Run mockery for each path in MOCKERY_FILE_PATHS. The the generated mocks are
# created in package and in test files. Look here for more information https://github.com/vektra/mockery
mockery-run:
	for FILE_PATH in $(MOCKERY_FILE_PATHS); do\
		DIR=$$(dirname $$FILE_PATH); \
		INTERFACE_NAME=$$(basename $$FILE_PATH); \
		mockery --dir $$DIR --name $$INTERFACE_NAME --inpackage; \
	done

###############################################################################
# Docker helpers
###############################################################################
# Helper targets working with docker images.

# docker-compress takes the docker image specified by IMAGE_NAME and compresses all the layers into a single one. This is
# done by exporting the given image then re importing it with the given IMAGE_NAME.
#
# When a docker image is exported all of the instructions are lost (i.e. ENTRYPOINT, ENV, ...), so before the image is
# compressed the target inspects the image and pulls out the instructions. Each instruction that is pulled out is converted
# into a change directive, or change directives, of the format "--change 'INSTRUCTION <instruction>". These directives
# are given to the docker import command so the instructions can be re added to the compressed image.
#
# NOTE: This target does not attempt to copy every instruction from the original image to the compressed one. Any user of
# this target should ensure that any required instructions are copied over by this target.
docker-compress:
	$(eval JSONOBJ := "$(shell docker inspect $(IMAGE_NAME) | jq '.[0].Config' | jq -R '.' | sed -e 's/#/\\\#/g' ) ")
#	Re add the entry point.
	$(eval CHANGE := $(CHANGE)$(shell echo $(JSONOBJ) | jq -r \
		"if has(\"Entrypoint\") and .Entrypoint != \"\" then \" --change 'ENTRYPOINT \(.Entrypoint)'\" else \"\" end"\
	))
#	Re add the command.
	$(eval CHANGE := $(CHANGE)$(shell echo $(JSONOBJ) | jq -r \
		"if has(\"Cmd\") and .Cmd != \"\" then \" --change 'CMD \(.Cmd)'\" else \"\" end"\
	))
#	Re add the working directory.
	$(eval CHANGE := $(CHANGE)$(shell echo $(JSONOBJ) | jq -r \
		"if has(\"WorkingDir\") and .WorkingDir != \"\" then \" --change 'WORKDIR \(.WorkingDir)'\" else \"\" end"\
	))
#	Re add the user.
	$(eval CHANGE := $(CHANGE)$(shell echo $(JSONOBJ) | jq -r \
		"if has(\"User\") and .User != \"\" then \" --change 'USER \(.User)'\" else \"\" end"\
	))
#	Re add the environment variables. .Env is an array of strings so add a "--change 'ENV <value>'" for each value in
#	the array.
	$(eval CHANGE := $(CHANGE)$(shell echo $(JSONOBJ) | jq -r \
		"if has(\"Env\") and (.Env | length) > 0 then .Env | map(\" --change 'ENV \(.)'\") | join(\"\") else \"\" end"\
	))
#	Re add the labels. .Labels is a map of label names to label values, so add a "--change 'LABEL <key> <value>'" for
#	each map entry.
	$(eval CHANGE := $(CHANGE)$(shell echo $(JSONOBJ) | jq -r \
		"if has(\"Labels\") and (.Labels | length) > 0 then .Labels | to_entries | map(\" --change 'LABEL \(.key) \(.value)'\") | join(\"\") else \"\" end"\
	))
#	Re add the exposed ports. .ExposedPorts is a map, but we're only interested in the keys of the map so for each key
#	add "--change EXPOSE <key>".
	$(eval CHANGE := $(CHANGE)$(shell echo $(JSONOBJ) | jq -r \
		"if has(\"ExposedPorts\") and (.ExposedPorts | length) > 0 then .ExposedPorts | keys | map(\" --change 'EXPOSE \(.)'\") | join(\"\") else \"\" end"\
	))
	$(eval CONTAINER_ID := $(shell docker run -d -it --entrypoint /bin/true $(IMAGE_NAME) /bin/true))
	docker export $(CONTAINER_ID) | docker import $(CHANGE) - $(IMAGE_NAME)

###############################################################################
# Image building and pushing
###############################################################################

###############################################################################
# we want to be able to run the same recipe on multiple targets keyed on the image name
# to do that, we would use the entire image name, e.g. calico/node:abcdefg, as the stem, or '%', in the target
# however, make does **not** allow the usage of invalid filename characters - like / and : - in a stem, and thus errors out
# to get around that, we "escape" those characters by converting all : to --- and all / to ___ , so that we can use them
# in the target, we then unescape them back
escapefs = $(subst :,---,$(subst /,___,$(1)))
unescapefs = $(subst ---,:,$(subst ___,/,$(1)))

# retag-build-images-with-registries retags the build / arch images specified by BUILD_IMAGES and VALIDARCHES with
# the registries specified by DEV_REGISTRIES. The end tagged images are of the format
# $(REGISTRY)/$(BUILD_IMAGES):<tag>-$(ARCH).
retag-build-images-with-registries: $(addprefix retag-build-images-with-registry-,$(call escapefs,$(DEV_REGISTRIES)))

# retag-build-images-with-registry-% retags the build / arch images specified by BUILD_IMAGES and VALIDARCHES with
# the registry specified by $*.
retag-build-images-with-registry-%:
	$(MAKE) $(addprefix retag-build-image-with-registry-,$(call escapefs,$(BUILD_IMAGES))) REGISTRY=$(call unescapefs,$*)

# retag-build-image-with-registry-% retags the build arch images specified by $* and VALIDARCHES with the
# registry specified by REGISTRY.
retag-build-image-with-registry-%: var-require-all-REGISTRY-BUILD_IMAGES
	$(MAKE) -j12 $(addprefix retag-build-image-arch-with-registry-,$(VALIDARCHES)) BUILD_IMAGE=$(call unescapefs,$*)

# retag-build-image-arch-with-registry-% retags the build / arch image specified by $* and BUILD_IMAGE with the
# registry specified by REGISTRY.
retag-build-image-arch-with-registry-%: var-require-all-REGISTRY-BUILD_IMAGE-IMAGETAG
	docker tag $(BUILD_IMAGE):$(LATEST_IMAGE_TAG)-$* $(call filter-registry,$(REGISTRY))$(BUILD_IMAGE):$(IMAGETAG)-$*
	$(if $(filter $*,amd64),\
		docker tag $(BUILD_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH) $(REGISTRY)/$(BUILD_IMAGE):$(IMAGETAG),\
		$(NOECHO) $(NOOP)\
	)

# push-images-to-registries pushes the build / arch images specified by BUILD_IMAGES and VALIDARCHES to the registries
# specified by DEV_REGISTRY.
push-images-to-registries: $(addprefix push-images-to-registry-,$(call escapefs,$(DEV_REGISTRIES)))

# push-images-to-registry-% pushes the build / arch images specified by BUILD_IMAGES and VALIDARCHES to the registry
# specified by %*.
push-images-to-registry-%:
	$(MAKE) $(addprefix push-image-to-registry-,$(call escapefs,$(BUILD_IMAGES))) REGISTRY=$(call unescapefs,$*)

# push-image-to-registry-% pushes the build / arch images specified by $* and VALIDARCHES to the registry
# specified by REGISTRY.
#
# We also build a list of all of the iamges we're going to be pushing and then, once we're done, we set the expiry
# on those images, either adding an expiry for normal pushes or removing it for releases, if we're pushing to quay.io
# that is.
push-image-to-registry-%:
	$(eval BUILD_IMAGE=$(call unescapefs,$*))
	$(eval EXPIRY_IMAGES_LIST=$(REGISTRY)/$(BUILD_IMAGE):$(IMAGETAG) $(addprefix $(REGISTRY)/$(BUILD_IMAGE):$(IMAGETAG)-,$(VALIDARCHES)))

	$(MAKE) -j6 $(addprefix push-image-arch-to-registry-,$(VALIDARCHES)) BUILD_IMAGE=$(BUILD_IMAGE)

ifeq ($(findstring quay.io,$(REGISTRY)),quay.io)
	$(if $(RELEASE), \
		-$(RELEASE_PY3) $(QUAY_SET_EXPIRY_SCRIPT) remove $(EXPIRY_IMAGES_LIST), \
		-$(RELEASE_PY3) $(QUAY_SET_EXPIRY_SCRIPT) add --expiry-days=$(QUAY_EXPIRE_DAYS) $(EXPIRY_IMAGES_LIST) \
	)
endif

# push-image-arch-to-registry-% pushes the build / arch image specified by $* and BUILD_IMAGE to the registry
# specified by REGISTRY.
push-image-arch-to-registry-%:
# If the registry we want to push to doesn't not support manifests don't push the ARCH image.
	$(DOCKER) push --quiet $(call filter-registry,$(REGISTRY))$(BUILD_IMAGE):$(IMAGETAG)-$*
	$(if $(filter $*,amd64),\
		$(DOCKER) push $(REGISTRY)/$(BUILD_IMAGE):$(IMAGETAG),\
		$(NOECHO) $(NOOP)\
	)

# push multi-arch manifest where supported.
push-manifests: var-require-all-IMAGETAG  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-manifest-%:
	$(DOCKER) manifest create $(call unescapefs,$*):$(IMAGETAG) $(addprefix --amend ,$(addprefix $(call unescapefs,$*):$(IMAGETAG)-,$(VALIDARCHES)))
	$(DOCKER) manifest push --purge $(call unescapefs,$*):$(IMAGETAG)

push-manifests-with-tag: var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) push-manifests IMAGETAG=$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(BRANCH_NAME) EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) push-manifests IMAGETAG=$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(GIT_VERSION) EXCLUDEARCH="$(EXCLUDEARCH)"

# cd-common tags and pushes images with the branch name and git version. This target uses PUSH_IMAGES, BUILD_IMAGE,
# and BRANCH_NAME env variables to figure out what to tag and where to push it to.
cd-common: var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) retag-build-images-with-registries push-images-to-registries IMAGETAG=$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(BRANCH_NAME) EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) retag-build-images-with-registries push-images-to-registries IMAGETAG=$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(shell git describe --tags --dirty --long --always --abbrev=12) EXCLUDEARCH="$(EXCLUDEARCH)"

###############################################################################
# Release targets and helpers
#
# The following targets and macros are used to help start and cut releases.
# At high level, this involves:
# - Creating release branches
# - Adding empty commits to start next release, and updating the 'dev' tag
# - Adding 'release' tag to the commit that will be release
# - Creating an empty commit for the next potential patch release, and updating
#   the dev tag on that commit
# - Copying images for the released commit over to the release registries, and
#   re tagging those images with the release tag
#
# The following definitions will be helpful in understanding this process:
# - 'dev' tag: A git tag of the form of `v3.8.0-calient-0.dev-36-g3a618e61c2d3`
#   that every commit has. The start of the dev tag, i.e. v3.8.0, is the
#   the release that this commit will go into.
# - 'release' tag: A git tag of the form of `v3.8.0`. The commit that a release
#   is cut from will have this tag, i.e. you can find the commit that release
#   3.8 uses by finding the commit with the tag v3.8.0.
# - 'dev' image: The image that is created for every commit that is merged to
#   master or a release branch. This image is tagged with the dev tag, i.e.
#   if commit 3a618e61c2d3 is on master or a release branch, there will be
#   an image for that commit in the dev registry with the tag
#   `v3.8.0-calient-0.dev-36-g3a618e61c2d3`.
# - 'release' image: The public image the customers will use to install our
#   our product. Producing this is the goal of cutting the release. This image
#   will be in the release registries, and will be tagged with the release tag,
#   i.e. the release image for release 3.8 will have the v3.8.0 tag, or if it's
#   a patch release it will be v3.8.<patch version>
###############################################################################
fetch-all:
	git fetch --all -q

# git-dev-tag retrieves the dev tag for the current commit (the one are dev images are tagged with).
git-dev-tag = $(shell git describe --tags --long --always --abbrev=12 --match "*dev*")
# git-release-tag-from-dev-tag gets the release version from the current commits dev tag.
git-release-tag-from-dev-tag = $(shell echo $(call git-dev-tag) | grep -P -o "^v\d*.\d*.\d*")
# git-release-tag-for-current-commit gets the release tag for the current commit if there is one.
git-release-tag-for-current-commit = $(shell git describe --tags --exact-match --exclude "*dev*")

# release-branch-for-tag finds the latest branch that corresponds to the given tag.
release-branch-for-tag = $(firstword $(shell git --no-pager branch --format='%(refname:short)' --contains $1 | grep -P "^release"))
# commit-for-tag finds the latest commit that corresponds to the given tag.
commit-for-tag = $(shell git rev-list -n 1 $1)
git-commit-for-remote-tag = $(shell git ls-remote -q --tags $(GIT_REMOTE) $1 | awk '{print $$1}')
# current-branch gets the name of the branch for the current commit.
current-branch = $(shell git rev-parse --abbrev-ref HEAD)

# RELEASE_BRANCH_BASE is used when creating a release branch to confirm the correct base is being used. It's
# configurable so that a dry run can be done from a PR branch.
RELEASE_BRANCH_BASE ?=master

# var-set-% checks if there is a non empty variable for the value describe by %. If FAIL_NOT_SET is set, then var-set-%
# fails with an error message. If FAIL_NOT_SET is not set, then var-set-% appends a 1 to VARSET if the variable isn't
# set.
var-set-%:
	$(if $($*),$(eval VARSET+=1),$(if $(FAIL_NOT_SET),$(error $* is required but not set),))

# var-require is used to check if one or all of the variables are set in REQUIRED_VARS, and fails if not. The variables
# in REQUIRE_VARS are hyphen separated.
#
# If FAIL_NOT_SET is set, then all variables described in REQUIRED_VARS must be set for var-require to not fail,
# otherwise only one variable needs to be set for var-require to not fail.
var-require: $(addprefix var-set-,$(subst -, ,$(REQUIRED_VARS)))
	$(if $(VARSET),,$(error one of $(subst -, ,$(REQUIRED_VARS)) is not set or empty, but at least one is required))

# var-require-all-% checks if the there are non empty variables set for the hyphen separated values in %, and fails if
# there isn't a non empty variable for each given value. For instance, to require FOO and BAR both must be set you would
# call var-require-all-FOO-BAR.
var-require-all-%:
	@$(MAKE) --quiet --no-print-directory var-require REQUIRED_VARS=$* FAIL_NOT_SET=true

# var-require-one-of-% checks if the there are non empty variables set for the hyphen separated values in %, and fails
# there isn't a non empty variable for at least one of the given values. For instance, to require either FOO or BAR both
# must be set you would call var-require-all-FOO-BAR.
var-require-one-of-%:
	@$(MAKE) --quiet --no-print-directory var-require REQUIRED_VARS=$*

# build-images echos the images that would be built.
# If WINDOWS_IMAGE is set then it echos the windows image that would be built as well.
build-images: var-require-all-BUILD_IMAGES
	$(if $(WINDOWS_IMAGE),\
		@echo $(BUILD_IMAGES) $(WINDOWS_IMAGE),\
		@echo $(BUILD_IMAGES)\
	)

# sem-cut-release triggers the cut-release pipeline (or test-cut-release if CONFIRM is not specified) in semaphore to
# cut the release. The pipeline is triggered for the current commit, and the branch it's triggered on is calculated
# from the RELEASE_VERSION, CNX, and OS variables given.
#
# Before the pipeline is triggered, this target validates that the expected release will be cut using the
# RELEASE_TAG (optional and defaults to the current tag) and RELEASE_VERSION (required) variables. The RELEASE_TAG
# should be the dev tag that the release is cut from, and RELEASE_VERSION should be the version expected to be released.
# This target verifies that the current commit is tagged with the RELEASE_TAG and that cutting this commit will result
# in RELEASE_VERSION being cut.
sem-cut-release: var-require-one-of-CONFIRM-DRYRUN var-require-all-RELEASE_VERSION var-require-one-of-CNX-OS
ifndef RELEASE_TAG
	$(eval RELEASE_TAG = $(call git-dev-tag))
else
	$(eval RELEASE_TAG_COMMIT = $(call commit-for-tag,$(RELEASE_TAG)))
	$(if $(filter-out $(RELEASE_TAG_COMMIT),$(GIT_COMMIT)),\
		echo Current commit is not tagged with $(RELEASE_TAG) && exit 1)
endif
	$(eval CURRENT_RELEASE_VERSION = $(call git-release-tag-from-dev-tag))
	$(if $(filter-out $(CURRENT_RELEASE_VERSION),$(RELEASE_VERSION)),\
		echo Given release version $(RELEASE_VERSION) does not match current commit release version $(CURRENT_RELEASE_VERSION). && exit 1)

	$(eval RELEASE_BRANCH = release-$(if $CNX,calient-,)$(shell echo "$(RELEASE_VERSION)" | awk -F  "." '{print $$1"."$$2}'))
	$(eval WORKFLOW_FILE = $(if $(CONFIRM),cut-release.yml,test-cut-release.yml))

	@echo Cutting release for $(RELEASE_VERSION) from dev tag $(RELEASE_TAG) \(commit $(GIT_COMMIT)\)
	SEMAPHORE_WORKFLOW_BRANCH=$(RELEASE_BRANCH) SEMAPHORE_COMMIT_SHA=$(GIT_COMMIT) SEMAPHORE_WORKFLOW_FILE=$(WORKFLOW_FILE) $(MAKE) semaphore-run-workflow

# cut-release uses the dev tags on the current commit to cut the release, more specifically cut-release does the
# following:
# - Calculates the release tag from the dev tag on the commit
# - tags the current commit with the release tag then pushes that tag to github
# - retags the build images (specified by BUILD_IMAGES) in the dev registries (specified DEV_REGISTRIES) with the
#	release tag
# - copies the build images (specified by BUILD_IMAGES) from the first dev registry to the release registries (specified
#	by RELEASE_REGISTRIES) and retags those images with the release tag
# - tags an empty commit at the head of the release branch with the next patch release dev tag and pushed that to github
cut-release: var-require-one-of-CONFIRM-DRYRUN
	$(MAKE) cut-release-wrapped RELEASE=true

cut-release-wrapped: var-require-one-of-CONFIRM-DRYRUN
	$(eval DEV_TAG = $(call git-dev-tag))
	$(eval RELEASE_TAG = $(call git-release-tag-from-dev-tag))
	$(eval RELEASE_BRANCH = $(call release-branch-for-tag,$(DEV_TAG)))
ifdef EXPECTED_RELEASE_TAG
	$(if $(filter-out $(RELEASE_TAG),$(EXPECTED_RELEASE_TAG)),\
		@echo "Failed to verify release tag$(comma) expected release version is $(EXPECTED_RELEASE_TAG)$(comma) actual is $(RELEASE_TAG)."\
		&& exit 1)
endif
	$(eval NEXT_RELEASE_VERSION = $(shell echo "$(call git-release-tag-from-dev-tag)" | awk '{ split($0,tag,"-"); if (tag[2] ~ /^1\./) { split(tag[2],subver,"."); print tag[1]"-"subver[1]+1".0" } else { split(tag[1],ver,"."); print ver[1]"."ver[2]"."ver[3]+1 } }'))
ifndef IMAGE_ONLY
	$(MAKE) maybe-tag-release maybe-push-release-tag\
		RELEASE_TAG=$(RELEASE_TAG) BRANCH=$(RELEASE_BRANCH) DEV_TAG=$(DEV_TAG)
endif
ifdef BUILD_IMAGES
	$(eval IMAGE_DEV_TAG = $(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(DEV_TAG))
	$(eval IMAGE_RELEASE_TAG = $(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(RELEASE_TAG))
	$(MAKE) release-dev-images\
		RELEASE_TAG=$(IMAGE_RELEASE_TAG) BRANCH=$(RELEASE_BRANCH) DEV_TAG=$(IMAGE_DEV_TAG)
endif
ifndef IMAGE_ONLY
	$(MAKE) maybe-dev-tag-next-release maybe-push-next-release-dev-tag\
		NEXT_RELEASE_VERSION=$(NEXT_RELEASE_VERSION) BRANCH=$(RELEASE_BRANCH) DEV_TAG=$(DEV_TAG)
endif

# maybe-tag-release calls the tag-release target only if the current commit is not tagged with the tag in RELEASE_TAG.
# If the current commit is already tagged with the value in RELEASE_TAG then this is a NOOP.
maybe-tag-release: var-require-all-RELEASE_TAG
	$(if $(filter-out $(call git-release-tag-for-current-commit),$(RELEASE_TAG)),\
		$(MAKE) tag-release,\
		@echo "Current commit already tagged with $(RELEASE_TAG)")

# tag-release tags the current commit with an annotated tag with the value in RELEASE_TAG. This target throws an error
# if the current branch is not master.
tag-release: var-require-one-of-CONFIRM-DRYRUN var-require-all-DEV_TAG_SUFFIX-RELEASE_TAG
	$(if $(filter-out $(RELEASE_BRANCH_BASE),$(call current-branch)),,$(error tag-release cannot be called on $(RELEASE_BRANCH_BASE)))
	git tag -a $(RELEASE_TAG) -m "Release $(RELEASE_TAG)"

# maybe-push-release-tag calls the push-release-tag target only if the tag in RELEASE_TAG is not already pushed to
# github. If the tag is pushed to github then this is a NOOP.
# TODO should we check the commit tagged in remote is the current commit? Probably yes... that could catch some annoying problems that would be hard to find if they happened...
maybe-push-release-tag: var-require-all-RELEASE_TAG
	$(if $(shell git ls-remote -q --tags $(GIT_REMOTE) $(RELEASE_TAG)),\
		@echo Release $(RELEASE_TAG) already in github,\
		$(MAKE) push-release-tag)

# push-release-tag pushes the tag in RELEASE_TAG to github. If the current commit is not tagged with this tag then this
# target fails.
push-release-tag: var-require-one-of-CONFIRM-DRYRUN var-require-all-DEV_TAG_SUFFIX-RELEASE_TAG
	$(if $(call git-release-tag-for-current-commit),,$(error Commit does not have a release tag))
	$(GIT) push $(GIT_REMOTE) $(RELEASE_TAG)

# maybe-dev-tag-next-release calls the dev-tag-next-release-target only if the tag NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX
# doesn't exist locally. If the tag does exist then this is a NOOP.
maybe-dev-tag-next-release: var-require-all-NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX
	$(if $(shell git rev-parse --verify -q "$(NEXT_RELEASE_VERSION)-$(DEV_TAG_SUFFIX)"),\
		echo "Tag for next release $(NEXT_RELEASE_VERSION) already exists$(comma) not creating.",\
		$(MAKE) dev-tag-next-release)

# dev-tag-next-release creates a new commit empty commit at the head of BRANCH and tags it with
# NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX.
dev-tag-next-release: var-require-one-of-CONFIRM-DRYRUN var-require-all-NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX-BRANCH
	git checkout $(BRANCH)
	$(GIT) pull $(GIT_REMOTE) $(BRANCH)
	git commit --allow-empty -m "Begin development on $(NEXT_RELEASE_VERSION)"
	git tag $(NEXT_RELEASE_VERSION)-$(DEV_TAG_SUFFIX)

# maybe-push-next-release-dev-tag calls the push-next-release-dev-tag target if the tag
# NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX doesn't exist remotely. If the tag exists remotely then this is a NOOP.
maybe-push-next-release-dev-tag: var-require-one-of-CONFIRM-DRYRUN var-require-all-NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX
	$(if $(shell git ls-remote --tags $(GIT_REMOTE) $(NEXT_RELEASE_VERSION)-$(DEV_TAG_SUFFIX)),\
		echo "Dev tag for next release $(NEXT_RELEASE_VERSION) already pushed to github.",\
		$(MAKE) push-next-release-dev-tag)

# push-next-release-dev-tag pushes the tag NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX and the current branch to github. If
# the current branch is not the head of the branch then this target fails.
push-next-release-dev-tag: var-require-one-of-CONFIRM-DRYRUN var-require-all-NEXT_RELEASE_VERSION-DEV_TAG_SUFFIX
	# The next release commit should always be at the head of a release branch.
	$(if $(filter-out HEAD,$(call current-branch)),,\
		$(error "Refusing to push commit for next release while in a detached state."))
	$(GIT) push $(GIT_REMOTE) $(call current-branch)
	$(GIT) push $(GIT_REMOTE) $(NEXT_RELEASE_VERSION)-$(DEV_TAG_SUFFIX)

# release-dev-images releases the dev images by calling the release-tag-dev-image-% and publish-dev-image-% on each
# value in BUILD_IMAGES. This results in retagging all the dev images with the release tag and copying the dev images
# over to the release registries.
ifndef SKIP_DEV_IMAGE_RETAG
RELEASE_DEV_IMAGES_RETAG_TARGETS ?= $(addprefix release-retag-dev-images-in-registry-,$(call escapefs, $(DEV_REGISTRIES)))
endif

RELEASE_DEV_IMAGES_TARGETS ?= $(addprefix release-dev-images-to-registry-,$(call escapefs, $(RELEASE_REGISTRIES)))
release-dev-images: var-require-one-of-CONFIRM-DRYRUN var-require-all-BUILD_IMAGES $(RELEASE_DEV_IMAGES_RETAG_TARGETS) $(RELEASE_DEV_IMAGES_TARGETS)

# release-retag-dev-images-in-registry-% retags all the build / arch images specified by BUILD_IMAGES and VALIDARCHES in
# the registry specified by $* with the release tag specified by RELEASE_TAG.
release-retag-dev-images-in-registry-%:
	$(MAKE) $(addprefix release-retag-dev-image-in-registry-,$(call escapefs, $(BUILD_IMAGES))) DEV_REGISTRY=$(call unescapefs,$*)

# release-retag-dev-image-in-registry-% retags the build image specified by $* in the dev registry specified by
# DEV_REGISTRY with the release tag specified by RELEASE_TAG. If DEV_REGISTRY is in the list of registries specified by
# RELEASE_REGISTRIES then the retag is not done
release-retag-dev-image-in-registry-%: bin/crane
	$(if $(filter-out $(RELEASE_REGISTRIES),$(DEV_REGISTRY)),\
		$(CRANE) cp $(DEV_REGISTRY)/$(call unescapefs,$*):$(DEV_TAG) $(DEV_REGISTRY)/$(call unescapefs,$*):$(RELEASE_TAG))

# release-dev-images-to-registry-% copies and retags all the build / arch images specified by BUILD_IMAGES and
# VALIDARCHES from the registry specified by DEV_REGISTRY to the registry specified by RELEASE_REGISTRY using the tag
# specified by DEV_TAG and RELEASE_TAG.
release-dev-images-to-registry-%:
	$(MAKE) $(addprefix release-dev-image-to-registry-,$(call escapefs, $(BUILD_IMAGES))) RELEASE_REGISTRY=$(call unescapefs,$*)

# release-dev-image-to-registry-% copies the build image and build arch images specified by $* and VALIDARCHES from
# the dev repo specified by DEV_TAG and RELEASE.
release-dev-image-to-registry-%: bin/crane
	$(if $(SKIP_MANIFEST_RELEASE),,\
		$(CRANE) cp $(DEV_REGISTRY)/$(call unescapefs,$*):$(DEV_TAG) $(RELEASE_REGISTRY)/$(call unescapefs,$*):$(RELEASE_TAG))
	$(if $(SKIP_ARCH_RELEASE),,\
		$(MAKE) $(addprefix release-dev-image-arch-to-registry-,$(VALIDARCHES)) BUILD_IMAGE=$(call unescapefs,$*))

# release-dev-image-to-registry-% copies the build arch image specified by BUILD_IMAGE and ARCH from the dev repo
# specified by DEV_TAG and RELEASE.
release-dev-image-arch-to-registry-%: bin/crane
	$(CRANE) cp $(DEV_REGISTRY)/$(BUILD_IMAGE):$(DEV_TAG)-$* $(RELEASE_REGISTRY)/$(BUILD_IMAGE):$(RELEASE_TAG)-$*

# release-prereqs checks that the environment is configured properly to create a release.
.PHONY: release-prereqs
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif

# Check if the codebase is dirty or not.
check-dirty:
	@if [ "$$(git --no-pager diff --stat)" != "" ]; then \
	echo "The following files are dirty"; git --no-pager diff; exit 1; fi

bin/yq:
	mkdir -p bin
	$(eval TMP := $(shell mktemp -d))
	curl -sSf -L --retry 5 -o $(TMP)/yq4.tar.gz https://github.com/mikefarah/yq/releases/download/v4.34.2/yq_linux_$(BUILDARCH).tar.gz
	tar -zxvf $(TMP)/yq4.tar.gz -C $(TMP)
	mv $(TMP)/yq_linux_$(BUILDARCH) bin/yq

# This setup is used to download and install the `crane` binary into $(REPOROOT)/bin/crane.
# Normalize architecture for go-containerregistry filenames
CRANE_ARCH = $(subst amd64,x86_64,$(BUILDARCH))
ifeq ($(OS),Windows_NT)
CRANE_OS = Windows
else
CRANE_OS = $(shell uname -s)
endif
CRANE_URL = https://github.com/google/go-containerregistry/releases/download/$(CRANE_VERSION)/go-containerregistry_$(CRANE_OS)_$(CRANE_ARCH).tar.gz

.PHONY: bin/crane
bin/crane: $(REPO_ROOT)/bin/crane
$(REPO_ROOT)/bin/crane:
	$(info ::: Downloading crane from $(CRANE_URL))
	@mkdir -p $(REPO_ROOT)/bin
	@curl -sSfL --retry 5 $(CRANE_URL) | tar xz -C $(REPO_ROOT)/bin crane

###############################################################################
# Common functions for launching a local Kubernetes control plane.
###############################################################################
## Kubernetes apiserver used for tests
APISERVER_NAME := calico-local-apiserver
run-k8s-apiserver: stop-k8s-apiserver run-etcd
	docker run --detach --net=host \
		--name $(APISERVER_NAME) \
		-v $(REPO_ROOT):/go/src/github.com/projectcalico/calico \
		-v $(CERTS_PATH):/home/user/certs \
		-e KUBECONFIG=/home/user/certs/kubeconfig \
		$(CALICO_BUILD) kube-apiserver \
		--etcd-servers=http://$(LOCAL_IP_ENV):2379 \
		--service-cluster-ip-range=10.101.0.0/16,fd00:96::/112 \
		--authorization-mode=RBAC \
		--service-account-key-file=/home/user/certs/service-account.pem \
		--service-account-signing-key-file=/home/user/certs/service-account-key.pem \
		--service-account-issuer=https://localhost:443 \
		--api-audiences=kubernetes.default \
		--client-ca-file=/home/user/certs/ca.pem \
		--tls-cert-file=/home/user/certs/kubernetes.pem \
		--tls-private-key-file=/home/user/certs/kubernetes-key.pem \
		--enable-priority-and-fairness=false \
		--max-mutating-requests-inflight=0 \
		--max-requests-inflight=0 \
		--enable-aggregator-routing \
		--requestheader-client-ca-file=/home/user/certs/ca.pem \
		--requestheader-username-headers=X-Remote-User \
		--requestheader-group-headers=X-Remote-Group \
		--requestheader-extra-headers-prefix=X-Remote-Extra- \
		--proxy-client-cert-file=/home/user/certs/kubernetes.pem \
		--proxy-client-key-file=/home/user/certs/kubernetes-key.pem


	# Wait until the apiserver is accepting requests.
	while ! docker exec $(APISERVER_NAME) kubectl get nodes; do echo "Waiting for apiserver to come up..."; sleep 2; done

	# Wait until we can configure a cluster role binding which allows anonymous auth.
	while ! docker exec $(APISERVER_NAME) kubectl create \
		clusterrolebinding anonymous-admin \
		--clusterrole=cluster-admin \
		--user=system:anonymous 2>/dev/null ; \
		do echo "Waiting for $(APISERVER_NAME) to come up"; \
		sleep 1; \
		done

	# Create CustomResourceDefinition (CRD) for Calico resources
	while ! docker exec $(APISERVER_NAME) kubectl \
		apply -f /go/src/github.com/projectcalico/calico/$(CALICO_CRD_PATH); \
		do echo "Trying to create CRDs"; \
		sleep 1; \
		done

# Stop Kubernetes apiserver
stop-k8s-apiserver:
	@-docker rm -f $(APISERVER_NAME)

# Run a local Kubernetes controller-manager in a docker container, useful for tests.
CONTROLLER_MANAGER_NAME := calico-local-controller-manager
run-k8s-controller-manager: stop-k8s-controller-manager run-k8s-apiserver
	docker run --detach --net=host \
		--name $(CONTROLLER_MANAGER_NAME) \
		-v $(CERTS_PATH):/home/user/certs \
		$(CALICO_BUILD) kube-controller-manager \
		--master=https://127.0.0.1:6443 \
		--kubeconfig=/home/user/certs/kube-controller-manager.kubeconfig \
		--min-resync-period=3m \
		--allocate-node-cidrs=true \
		--cluster-cidr=192.168.0.0/16 \
		--v=5 \
		--service-account-private-key-file=/home/user/certs/service-account-key.pem \
		--root-ca-file=/home/user/certs/ca.pem

## Stop Kubernetes controller manager
stop-k8s-controller-manager:
	@-docker rm -f $(CONTROLLER_MANAGER_NAME)

###############################################################################
# Common functions for create a local kind cluster.
###############################################################################
KIND_DIR := $(REPO_ROOT)/hack/test/kind
KIND ?= $(KIND_DIR)/kind
KUBECTL ?= $(KIND_DIR)/kubectl

# Different tests may require different kind configurations.
KIND_CONFIG ?= $(KIND_DIR)/kind.config
KIND_NAME = $(basename $(notdir $(KIND_CONFIG)))
KIND_KUBECONFIG?=$(KIND_DIR)/$(KIND_NAME)-kubeconfig.yaml

kind-cluster-create: $(REPO_ROOT)/.$(KIND_NAME).created
$(REPO_ROOT)/.$(KIND_NAME).created: $(KUBECTL) $(KIND)
	# First make sure any previous cluster is deleted
	$(MAKE) kind-cluster-destroy

	# Create a kind cluster.
	$(KIND) create cluster \
		--config $(KIND_CONFIG) \
		--kubeconfig $(KIND_KUBECONFIG) \
		--name $(KIND_NAME) \
		--image kindest/node:$(KINDEST_NODE_VERSION)

	# Wait for controller manager to be running and healthy, then create Calico CRDs.
	while ! KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) get serviceaccount default; do echo "Waiting for default serviceaccount to be created..."; sleep 2; done
	while ! KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) create -f $(REPO_ROOT)/charts/crd.projectcalico.org.v1/templates/; do echo "Waiting for operator CRDs to be created"; sleep 2; done
	while ! KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) create -f $(REPO_ROOT)/$(CALICO_CRD_PATH); do echo "Waiting for calico CRDs to be created"; sleep 2; done

	# These may have already been created, depending on where we're getting our CRDs from. So use apply.
	while ! KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) apply -f $(REPO_ROOT)/libcalico-go/config/crd/policy.networking.k8s.io_clusternetworkpolicies.yaml; do echo "Waiting for CRDs to be created"; sleep 2; done

	# Install mutating admission policies.
	while ! KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) apply -f $(REPO_ROOT)/api/admission/; do echo "Waiting for mutating admission policies to be created"; sleep 2; done

	touch $@

kind-cluster-destroy: $(KIND) $(KUBECTL)
	# We need to drain the cluster gracefully when shutting down to avoid a netdev unregister error from the kernel.
	# This requires we execute CNI del on pods with pod networking.
	-$(KIND) delete cluster --name $(KIND_NAME)
	rm -f $(KIND_KUBECONFIG)
	rm -f $(REPO_ROOT)/.$(KIND_NAME).created

$(KIND)-$(KIND_VERSION):
	mkdir -p $(KIND_DIR)/$(KIND_VERSION)
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/github.com/projectcalico/calico/hack/test/kind/$(KIND_VERSION) go install sigs.k8s.io/kind@$(KIND_VERSION)"
	mv $(KIND_DIR)/$(KIND_VERSION)/kind $(KIND_DIR)/kind-$(KIND_VERSION)
	rm -r $(KIND_DIR)/$(KIND_VERSION)

$(KIND_DIR)/.kind-updated-$(KIND_VERSION): $(KIND)-$(KIND_VERSION)
	rm -f $(KIND_DIR)/.kind-updated-*
	cd $(KIND_DIR) && ln -fs kind-$(KIND_VERSION) kind
	touch $@

.PHONY: kind
kind: $(KIND)
	@echo "kind: $(KIND)"
$(KIND): $(KIND_DIR)/.kind-updated-$(KIND_VERSION)

$(KUBECTL)-$(K8S_VERSION):
	mkdir -p $(KIND_DIR)
	curl -fsSL --retry 5 https://dl.k8s.io/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@

$(KIND_DIR)/.kubectl-updated-$(K8S_VERSION): $(KUBECTL)-$(K8S_VERSION)
	rm -f $(KIND_DIR)/.kubectl-updated-*
	cd $(KIND_DIR) && ln -fs kubectl-$(K8S_VERSION) kubectl
	touch $@

.PHONY: kubectl
kubectl: $(KUBECTL)
	@echo "kubectl: $(KUBECTL)"
$(KUBECTL): $(KIND_DIR)/.kubectl-updated-$(K8S_VERSION)

bin/helm-$(HELM_VERSION):
	mkdir -p bin
	$(eval TMP := $(shell mktemp -d))
	curl -sSf -L --retry 5 -o $(TMP)/helm3.tar.gz https://get.helm.sh/helm-$(HELM_VERSION)-linux-$(ARCH).tar.gz
	tar -zxvf $(TMP)/helm3.tar.gz -C $(TMP)
	mv $(TMP)/linux-$(ARCH)/helm bin/helm-$(HELM_VERSION)

bin/.helm-updated-$(HELM_VERSION): bin/helm-$(HELM_VERSION)
	# Remove old marker files so that bin/helm will be stale if we switch
	# branches and the helm version changes.
	rm -f bin/.helm-updated-*
	cd bin && ln -fs helm-$(HELM_VERSION) helm
	touch $@

.PHONY: helm
helm: bin/helm
	@echo "helm: $^"
bin/helm: bin/.helm-updated-$(HELM_VERSION)

###############################################################################
# Common functions for launching a local etcd instance.
###############################################################################
## Run etcd as a container (calico-etcd)
# TODO: We shouldn't need to tear this down every time it is called.
# TODO: We shouldn't need to enable the v2 API, but some of our test code still relies on it.
.PHONY: run-etcd stop-etcd
run-etcd: stop-etcd
	docker run --detach \
		--net=host \
		--entrypoint=/usr/local/bin/etcd \
		--name calico-etcd $(ETCD_IMAGE) \
		--enable-v2 \
		--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
		--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

stop-etcd:
	@-docker rm -f calico-etcd

###############################################################################
# Helpers
###############################################################################
## Help
.PHONY: help
help:
	$(info Available targets)
	@echo
	@awk '/^[a-zA-Z\-\_\%0-9\/]+:/ {                                  \
	   nb = sub( /^## /, "", helpMsg );                               \
	   if(nb == 0) {                                                  \
	      helpMsg = $$0;                                              \
	      nb = sub( /^[^:]*:.* ## /, "", helpMsg );                   \
	   }                                                              \
	   if (nb)                                                        \
	      printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg;  \
	}                                                                 \
	{ helpMsg = $$0 }'                                                \
	width=30                                                          \
	$(MAKEFILE_LIST)
	@echo
	@echo "-----------------------------------------------------------"
	@echo "Building for $(BUILDOS)-$(ARCH) INSTALL_FLAG=$(INSTALL_FLAG)"
	@echo
	@echo "ARCH (target):		$(ARCH)"
	@echo "OS (target):		$(BUILDOS)"
	@echo "BUILDARCH (host):	$(BUILDARCH)"
	@echo "CALICO_BUILD:		$(CALICO_BUILD)"
	@echo "-----------------------------------------------------------"

###############################################################################
# Common functions for building windows images.
###############################################################################

DOCKER_MANIFEST_CMD := docker manifest

ifdef CONFIRM
CRANE_BINDMOUNT = $(CRANE_BINDMOUNT_CMD)
DOCKER_MANIFEST = $(DOCKER_MANIFEST_CMD)
else
CRANE_BINDMOUNT = echo [DRY RUN] $(CRANE_BINDMOUNT_CMD)
DOCKER_MANIFEST = echo [DRY RUN] $(DOCKER_MANIFEST_CMD)
endif

# Clean up the docker builder used to create Windows image tarballs.
.PHONY: clean-windows-builder
clean-windows-builder:
	-docker buildx rm calico-windows-builder

# Set up the docker builder used to create Windows image tarballs.
.PHONY: setup-windows-builder
setup-windows-builder: clean-windows-builder
	docker buildx create --name=calico-windows-builder --use --platform windows/amd64

# FIXME: Use WINDOWS_HPC_VERSION and image instead of nanoserver and WINDOWS_VERSIONS when containerd v1.6 is EOL'd
# .PHONY: image-windows release-windows
# NOTE: WINDOWS_IMAGE_REQS must be defined with the requirements to build the windows
# image. These must be added as reqs to 'image-windows' (originally defined in
# lib.Makefile) on the specific package Makefile otherwise they are not correctly
# recognized.
# # Build Windows image with tag and possibly push it to $DEV_REGISTRIES
# image-windows-with-tag: var-require-all-WINDOWS_IMAGE-WINDOWS_DIST-WINDOWS_IMAGE_REQS-IMAGETAG
# 	push="$${PUSH:-false}"; \
# 	for registry in $(DEV_REGISTRIES); do \
# 		echo Building and pushing Windows image to $${registry}; \
# 		image="$${registry}/$(WINDOWS_IMAGE):$(IMAGETAG)"; \
# 		docker buildx build \
# 			--platform windows/amd64 \
# 			--output=type=image,push=$${push} \
# 			-t $${image} \
# 			--pull \
# 			--no-cache \
# 			--build-arg GIT_VERSION=$(GIT_VERSION) \
# 			--build-arg WINDOWS_HPC_VERSION=$(WINDOWS_HPC_VERSION) \
# 			-f Dockerfile-windows .; \
# 	done ;

# image-windows: var-require-all-BRANCH_NAME
# 	$(MAKE) image-windows-with-tag PUSH=$(PUSH) IMAGETAG=$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(BRANCH_NAME)
# 	$(MAKE) image-windows-with-tag PUSH=$(PUSH) IMAGETAG=$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(shell git describe --tags --dirty --long --always --abbrev=12)

# # Build and push Windows image
# release-windows: var-require-one-of-CONFIRM-DRYRUN release-prereqs clean-windows
# 	$(MAKE) image-windows PUSH=true

# Windows image pushing is different because we do not build docker images directly.
# Since the build machine is linux, we output the images to a tarball. (We can
# produce images but there will be no output because docker images
# built for Windows cannot be loaded on linux.)
#
# The resulting image tarball is then pushed to registries during cd/release.
# The image tarballs are located in WINDOWS_DIST and have files names
# with the format 'node-windows-v3.21.0-2-abcdef-20H2.tar'.
#
# In addition to pushing the individual images, we also create the manifest
# directly using 'docker manifest'. This is possible because Semaphore is using
# a recent enough docker CLI version (20.10.0)
#
# - Create the manifest with 'docker manifest create' using the list of all images.
# - For each windows version, 'docker manifest annotate' its image with "os.image: <windows_version>".
#   <windows_version> is the version string that looks like, e.g. 10.0.19041.1288.
#   Setting os.image in the manifest is required for Windows hosts to load the
#   correct image in manifest.
# - Finally we push the manifest, "purging" the local manifest.

$(WINDOWS_DIST)/$(WINDOWS_IMAGE)-$(GIT_VERSION)-%.tar: windows-sub-image-$*

DOCKER_CREDENTIAL_VERSION="2.1.18"
DOCKER_CREDENTIAL_OS="linux"
DOCKER_CREDENTIAL_ARCH="amd64"
$(WINDOWS_DIST)/bin/docker-credential-gcr:
	-mkdir -p $(WINDOWS_DIST)/bin
	curl -fsSL  --retry 5 "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v$(DOCKER_CREDENTIAL_VERSION)/docker-credential-gcr_$(DOCKER_CREDENTIAL_OS)_$(DOCKER_CREDENTIAL_ARCH)-$(DOCKER_CREDENTIAL_VERSION).tar.gz" -o docker-credential-gcr.tar.gz
	tar xzf docker-credential-gcr.tar.gz --to-stdout docker-credential-gcr | tee $@ > /dev/null && chmod +x $@
	rm -f docker-credential-gcr.tar.gz

.PHONY: docker-credential-gcr-binary
docker-credential-gcr-binary: var-require-all-WINDOWS_DIST-DOCKER_CREDENTIAL_VERSION-DOCKER_CREDENTIAL_OS-DOCKER_CREDENTIAL_ARCH $(WINDOWS_DIST)/bin/docker-credential-gcr

# NOTE: WINDOWS_IMAGE_REQS must be defined with the requirements to build the windows
# image. These must be added as reqs to 'image-windows' (originally defined in
# lib.Makefile) on the specific package Makefile otherwise they are not correctly
# recognized.
windows-sub-image-%: var-require-all-GIT_VERSION-WINDOWS_IMAGE-WINDOWS_DIST-WINDOWS_IMAGE_REQS
	# ensure dir for windows image tars exits
	-mkdir -p $(WINDOWS_DIST)
	docker buildx build \
		--platform windows/amd64 \
		--output=type=docker,dest=$(CURDIR)/$(WINDOWS_DIST)/$(WINDOWS_IMAGE)-$(GIT_VERSION)-$*.tar \
		$(DOCKER_PULL) \
		-t $(WINDOWS_IMAGE):latest \
		--build-arg GIT_VERSION=$(GIT_VERSION) \
		--build-arg=WINDOWS_VERSION=$* \
		-f Dockerfile-windows .

.PHONY: image-windows release-windows release-windows-with-tag
image-windows: setup-windows-builder var-require-all-WINDOWS_VERSIONS
	for version in $(WINDOWS_VERSIONS); do \
		$(MAKE) windows-sub-image-$${version}; \
	done;

release-windows-with-tag: var-require-one-of-CONFIRM-DRYRUN var-require-all-IMAGETAG-DEV_REGISTRIES image-windows docker-credential-gcr-binary bin/crane
	for registry in $(DEV_REGISTRIES); do \
		echo Pushing Windows images to $${registry}; \
		all_images=""; \
		manifest_image="$${registry}/$(WINDOWS_IMAGE):$(IMAGETAG)"; \
		for win_ver in $(WINDOWS_VERSIONS); do \
			image_tar="$(WINDOWS_DIST)/$(WINDOWS_IMAGE)-$(GIT_VERSION)-$${win_ver}.tar"; \
			image="$${registry}/$(WINDOWS_IMAGE):$(IMAGETAG)-windows-$${win_ver}"; \
			echo Pushing image $${image} ...; \
			$(CRANE) push $${image_tar} $${image} & \
			all_images="$${all_images} $${image}"; \
		done; \
		wait; \
		$(DOCKER_MANIFEST) create --amend $${manifest_image} $${all_images}; \
		for win_ver in $(WINDOWS_VERSIONS); do \
			version=$$(docker manifest inspect mcr.microsoft.com/windows/nanoserver:$${win_ver} | grep "os.version" | head -n 1 | awk -F\" '{print $$4}'); \
			image="$${registry}/$(WINDOWS_IMAGE):$(IMAGETAG)-windows-$${win_ver}"; \
			$(DOCKER_MANIFEST) annotate --os windows --arch amd64 --os-version $${version} $${manifest_image} $${image}; \
		done; \
		$(DOCKER_MANIFEST) push --purge $${manifest_image}; \
		$(RELEASE_PY3) $(QUAY_SET_EXPIRY_SCRIPT) add --expiry-days=$(QUAY_EXPIRE_DAYS) $${manifest_image} $${all_images} || true; \
	done;

release-windows: var-require-one-of-CONFIRM-DRYRUN var-require-all-DEV_REGISTRIES-WINDOWS_IMAGE var-require-one-of-VERSION-BRANCH_NAME bin/crane
	describe_tag=$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(shell git describe --tags --dirty --long --always --abbrev=12); \
	release_tag=$(if $(VERSION),$(VERSION),$(if $(IMAGETAG_PREFIX),$(IMAGETAG_PREFIX)-)$(BRANCH_NAME)); \
	$(MAKE) release-windows-with-tag IMAGETAG=$${describe_tag}; \
	for registry in $(DEV_REGISTRIES); do \
		$(CRANE) cp $${registry}/$(WINDOWS_IMAGE):$${describe_tag} $${registry}/$(WINDOWS_IMAGE):$${release_tag}; \
	done;

# Name of a test image that is used by both "node" and "calicoctl", so defined here.  This image is
# built by node/Makefile.
TEST_CONTAINER_NAME_VER?=latest
TEST_CONTAINER_NAME?=calico/test:$(TEST_CONTAINER_NAME_VER)-$(ARCH)
