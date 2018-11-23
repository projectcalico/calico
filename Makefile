# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut st

###############################################################################
# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=$(patsubst Dockerfile.%,%,$(wildcard Dockerfile.*))

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)

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

# Build mounts for running in "local build" mode. Mount in libcalico, but null out
# the vendor directory. This allows an easy build using local development code,
# assuming that there is a local checkout of libcalico in the same directory as this repo.
LOCAL_BUILD_MOUNTS ?=
ifeq ($(LOCAL_BUILD),true)
LOCAL_BUILD_MOUNTS = -v $(CURDIR)/../libcalico-go:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go:ro \
	-v $(CURDIR)/.empty:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go/vendor:ro
endif

# we want to be able to run the same recipe on multiple targets keyed on the image name
# to do that, we would use the entire image name, e.g. calico/node:abcdefg, as the stem, or '%', in the target
# however, make does **not** allow the usage of invalid filename characters - like / and : - in a stem, and thus errors out
# to get around that, we "escape" those characters by converting all : to --- and all / to ___ , so that we can use them
# in the target, we then unescape them back
escapefs = $(subst :,---,$(subst /,___,$(1)))
unescapefs = $(subst ---,:,$(subst ___,/,$(1)))

# these macros create a list of valid architectures for pushing manifests
space :=
space +=
comma := ,
prefix_linux = $(addprefix linux/,$(strip $1))
join_platforms = $(subst $(space),$(comma),$(call prefix_linux,$(strip $1)))

# list of arches *not* to build when doing *-all
#    until s390x works correctly
EXCLUDEARCH ?= s390x
VALIDARCHES = $(filter-out $(EXCLUDEARCH),$(ARCHES))

# Determine which OS.
OS := $(shell uname -s | tr A-Z a-z)

###############################################################################
GO_BUILD_VER?=v0.20
ETCD_VER?=v3.3.7

BUILD_IMAGE?=calico/ctl
PUSH_IMAGES?=$(BUILD_IMAGE) quay.io/calico/ctl
RELEASE_IMAGES?=

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGES+=$(RELEASE_IMAGES)
endif

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES ?= quay.io/
PUSH_MANIFEST_IMAGES=$(PUSH_IMAGES:$(EXCLUDE_MANIFEST_REGISTRIES)%=)
PUSH_NONMANIFEST_IMAGES=$(filter-out $(PUSH_MANIFEST_IMAGES),$(PUSH_IMAGES))

# location of docker credentials to push manifests
DOCKER_CONFIG ?= $(HOME)/.docker/config.json

CALICOCTL_DIR=calicoctl
CALICOCTL_FILES=$(shell find $(CALICOCTL_DIR) -name '*.go')
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created-$(ARCH)

TEST_CONTAINER_NAME ?= calico/test

CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)
GIT_VERSION?=$(shell git describe --tags --dirty --always)
ifeq ($(LOCAL_BUILD),true)
	GIT_VERSION = $(shell git describe --tags --dirty --always)-dev-build
endif

CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
LOCAL_USER_ID?=$(shell id -u $$USER)

PACKAGE_NAME?=github.com/projectcalico/calicoctl

LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/calicoctl/commands.VERSION=$(GIT_VERSION) \
	-X $(PACKAGE_NAME)/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) -s -w"

LIBCALICOGO_PATH?=none

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf bin build certs *.tar vendor
	docker rmi $(BUILD_IMAGE):latest-$(ARCH) || true
	docker rmi $(BUILD_IMAGE):$(VERSION)-$(ARCH) || true
ifeq ($(ARCH),amd64)
	docker rmi $(BUILD_IMAGE):latest || true
	docker rmi $(BUILD_IMAGE):$(VERSION) || true
endif

###############################################################################
# Building the binary
###############################################################################
.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/calicoctl-linux-,$(VALIDARCHES)) bin/calicoctl-windows-amd64.exe bin/calicoctl-darwin-amd64

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/calicoctl-$(OS)-$(ARCH)

## Create the vendor directory
vendor: glide.yaml
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide

	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
    docker run --rm -i \
      -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
      -v $(HOME)/.glide:/home/user/.glide:rw \
      -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
      $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
          glide install -strip-vendor'

# Default the libcalico repo and version but allow them to be overridden
LIBCALICO_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)
LIBCALICO_REPO?=github.com/projectcalico/libcalico-go
LIBCALICO_VERSION?=$(shell git ls-remote git@github.com:projectcalico/libcalico-go $(LIBCALICO_BRANCH) 2>/dev/null | cut -f 1)

## Update libcalico pin in glide.yaml
update-libcalico:
	docker run --rm -i \
      -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
      -v $(HOME)/.glide:/home/user/.glide:rw \
      -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
      $(CALICO_BUILD) /bin/sh -c ' \
        cd /go/src/$(PACKAGE_NAME); \
        echo "Updating libcalico to $(LIBCALICO_VERSION) from $(LIBCALICO_REPO)"; \
        export OLD_VER=$$(grep --after 50 libcalico-go glide.yaml |grep --max-count=1 --only-matching --perl-regexp "version:\s*\K[^\s]+") ;\
        echo "Old version: $$OLD_VER";\
        if [ $(LIBCALICO_VERSION) != $$OLD_VER ]; then \
            sed -i "s/$$OLD_VER/$(LIBCALICO_VERSION)/" glide.yaml && \
            if [ $(LIBCALICO_REPO) != "github.com/projectcalico/libcalico-go" ]; then \
              glide mirror set https://github.com/projectcalico/libcalico-go $(LIBCALICO_REPO) --vcs git; glide mirror list; \
            fi;\
          glide up --strip-vendor || glide up --strip-vendor; \
        fi'

# The supported different binary names. For each, ensure that an OS and ARCH is set
bin/calicoctl-%-amd64: ARCH=amd64
bin/calicoctl-%-arm64: ARCH=arm64
bin/calicoctl-%-ppc64le: ARCH=ppc64le
bin/calicoctl-%-s390x: ARCH=s390x
bin/calicoctl-darwin-amd64: OS=darwin
bin/calicoctl-windows-amd64: OS=windows
bin/calicoctl-linux-%: OS=linux

bin/calicoctl-%: $(CALICOCTL_FILES) vendor
	mkdir -p bin
	-mkdir -p .go-pkg-cache
	docker run --rm \
	  -e OS=$(OS) -e ARCH=$(ARCH) \
	  -e GOOS=$(OS) -e GOARCH=$(ARCH) \
	  -e CALICOCTL_GIT_REVISION=$(CALICOCTL_GIT_REVISION) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
	  $(LOCAL_BUILD_MOUNTS) \
	  -e GOCACHE=/go-cache \
	  -w /go/src/$(PACKAGE_NAME) \
	  $(CALICO_BUILD) \
	  go build -v -o bin/calicoctl-$(OS)-$(ARCH) $(LDFLAGS) "./calicoctl/calicoctl.go"

# Overrides for the binaries that need different output names
bin/calicoctl: bin/calicoctl-linux-amd64
	cp $< $@
bin/calicoctl-windows-amd64.exe: bin/calicoctl-windows-amd64
	mv $< $@

###############################################################################
# Building the image
###############################################################################
.PHONY: image $(BUILD_IMAGE)
image: $(BUILD_IMAGE)
$(BUILD_IMAGE): $(CTL_CONTAINER_CREATED)
$(CTL_CONTAINER_CREATED): Dockerfile.$(ARCH) bin/calicoctl-linux-$(ARCH)
	docker build -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif
	touch $@

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGES)))

sub-single-push-%:
	docker push $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

push-all: imagetag $(addprefix sub-push-,$(VALIDARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## push multi-arch manifest where supported
push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using $(DOCKER_CONFIG) holds the docker login credentials
	# path to credentials based on manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(VALIDARCHES)) --template $(call unescapefs,$*:$(IMAGETAG))-ARCH --target $(call unescapefs,$*:$(IMAGETAG))"

	## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch
tag-images: imagetag $(addprefix sub-single-tag-images-arch-,$(call escapefs,$(PUSH_IMAGES))) $(addprefix sub-single-tag-images-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))

sub-single-tag-images-arch-%:
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

# because some still do not support multi-arch manifest
sub-single-tag-images-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(VALIDARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

###############################################################################
# Static checks
###############################################################################
## Perform static checks on the code.
.PHONY: static-checks
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			gometalinter --deadline=300s --disable-all --enable=goimports --vendor ./...'

.PHONY: fix
## Fix static checks
fix:
	goimports -w calicoctl/*

.PHONY: install-git-hooks
## Install Git hooks
install-git-hooks:
	./install-git-hooks

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev.
ut: bin/calicoctl-linux-amd64
	docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		$(LOCAL_BUILD_MOUNTS) \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -cover -r --skipPackage vendor calicoctl/* $(GINKGO_ARGS)'

###############################################################################
# STs
###############################################################################
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
ST_TO_RUN?=tests/st/calicoctl/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

.PHONY: st
## Run the STs in a container
st: bin/calicoctl-linux-amd64 run-etcd-host
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	docker run --net=host --privileged \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           --rm -t \
	           -v $(CURDIR):/code \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           $(TEST_CONTAINER_NAME) \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/report/nosetests.xml" --with-timer $(ST_OPTIONS)'

	$(MAKE) stop-etcd

## Etcd is used by the STs
# NOTE: https://quay.io/repository/coreos/etcd is available *only* for the following archs with the following tags:
# amd64: 3.3.7
# arm64: 3.3.7-arm64
# ppc64le: 3.3.7-ppc64le
# s390x is not available
COREOS_ETCD?=quay.io/coreos/etcd:$(ETCD_VER)-$(ARCH)
ifeq ($(ARCH),amd64)
COREOS_ETCD=quay.io/coreos/etcd:$(ETCD_VER)
endif
.PHONY: run-etcd-host
run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd \
	$(COREOS_ETCD) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379" \
	--listen-client-urls "http://0.0.0.0:2379"

.PHONY: stop-etcd
stop-etcd:
	@-docker rm -f calico-etcd

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean build-all static-checks ut st image-all

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=${BRANCH_NAME} EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(shell git describe --tags --dirty --always --long) EXCLUDEARCH="$(EXCLUDEARCH)"

###############################################################################
# Release
###############################################################################
PREVIOUS_RELEASE=$(shell git describe --tags --abbrev=0)

## Tags and builds a release from start to finish.
release: release-prereqs
	$(MAKE) VERSION=$(VERSION) release-tag
	$(MAKE) VERSION=$(VERSION) release-build
	$(MAKE) VERSION=$(VERSION) release-verify

	@echo ""
	@echo "Release build complete. Next, push the produced images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish"
	@echo ""

## Produces a git tag for the release.
release-tag: release-prereqs release-notes
	git tag $(VERSION) -F release-notes-$(VERSION)
	@echo ""
	@echo "Now you can build the release:"
	@echo ""
	@echo "  make VERSION=$(VERSION) release-build"
	@echo ""

## Produces a clean build of release artifacts at the specified version.
release-build: release-prereqs clean
# Check that the correct code is checked out.
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif

	$(MAKE) build-all image-all
	$(MAKE) tag-images-all IMAGETAG=$(VERSION)
	$(MAKE) tag-images-all IMAGETAG=latest

	# Copy the amd64 variant to calicoctl - for now various downstream projects
	# expect this naming convention. Until they can be swapped over, we still need to
	# publish a binary called calicoctl.
	$(MAKE) bin/calicoctl

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

## Generates release notes based on commits in this version.
release-notes: release-prereqs
	mkdir -p dist
	echo "# Changelog" > release-notes-$(VERSION)
	sh -c "git cherry -v $(PREVIOUS_RELEASE) | cut '-d ' -f 2- | sed 's/^/- /' >> release-notes-$(VERSION)"

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	# Push images.
	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=$(VERSION)

	# Push binaries to GitHub release.
	# Requires ghr: https://github.com/tcnksm/ghr
	# Requires GITHUB_TOKEN environment variable set.
	ghr -r calicoctl \
		-b "Release notes can be found at https://docs.projectcalico.org" \
		-n $(VERSION) \
		$(VERSION) ./bin/

	@echo "Confirm that the release was published at the following URL."
	@echo ""
	@echo "  https://$(PACKAGE_NAME)/releases/tag/$(VERSION)"
	@echo ""
	@echo "If this is the latest stable release, then run the following to push 'latest' images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish-latest"
	@echo ""

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run $(BUILD_IMAGE):latest-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(BUILD_IMAGE):latest-$(ARCH) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN must be set for a release)
endif
ifeq (, $(shell which ghr))
	$(error Unable to find `ghr` in PATH, run this: go get -u github.com/tcnksm/ghr)
endif

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: help
## Display this help text
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	@echo "calicoctl Makefile"
	@echo
	@echo "Dependencies: docker 1.12+; go 1.8+"
	@echo
	@echo "For some target, set ARCH=<target> OS=<os> to build for a given target architecture and OS."
	@awk '/^[a-zA-Z\-\_0-9\/]+:/ {                                      \
		nb = sub( /^## /, "", helpMsg );                                \
		if(nb == 0) {                                                   \
			helpMsg = $$0;                                              \
			nb = sub( /^[^:]*:.* ## /, "", helpMsg );                   \
		}                                                               \
		if (nb)                                                         \
			printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg;  \
	}                                                                   \
	{ helpMsg = $$0 }'                                                  \
	width=20                                                            \
	$(MAKEFILE_LIST)
	@echo
	@echo "-----------------------------------------"
	@echo "Building for $(OS)-$(ARCH) INSTALL_FLAG=$(INSTALL_FLAG)"
	@echo
	@echo "ARCH (target):          $(ARCH)"
	@echo "OS (target):            $(OS)"
	@echo "BUILDARCH (host):       $(BUILDARCH)"
	@echo "CALICO_BUILD:     $(CALICO_BUILD)"
	@echo "-----------------------------------------"
