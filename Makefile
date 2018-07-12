# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut fv

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

# Determine which OS.
OS?=$(shell uname -s | tr A-Z a-z)
###############################################################################
GO_BUILD_VER?=v0.16

K8S_VERSION?=v1.10.4
HYPERKUBE_IMAGE?=gcr.io/google_containers/hyperkube-$(ARCH):$(K8S_VERSION)
ETCD_VERSION?=v3.3.7
ETCD_IMAGE?=quay.io/coreos/etcd:$(ETCD_VERSION)-$(BUILDARCH)
# If building on amd64 omit the arch in the container name.
ifeq ($(BUILDARCH),amd64)
        ETCD_IMAGE=quay.io/coreos/etcd:$(ETCD_VERSION)
endif

# Makefile configuration options
CONTAINER_NAME=calico/kube-controllers
PACKAGE_NAME?=github.com/projectcalico/kube-controllers
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
LIBCALICOGO_PATH?=none
LOCAL_USER_ID?=$(shell id -u $$USER)

# Get version from git.
GIT_VERSION?=$(shell git describe --tags --dirty)

DOCKER_GO_BUILD := mkdir -p .go-pkg-cache && \
                   docker run --rm \
                              --net=host \
                              -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
                              -v $${PWD}:/go/src/$(PACKAGE_NAME):rw \
                              -v $${PWD}/.go-pkg-cache:/go/pkg:rw \
                              -w /go/src/$(PACKAGE_NAME) \
                              $(CALICO_BUILD)
SRCFILES=cmd/kube-controllers/main.go $(shell find pkg -name '*.go')

## Removes all build artifacts.
clean:
	rm -rf bin image.created-$(ARCH)
	-docker rmi $(CONTAINER_NAME)
	rm -f tests/fv/fv.test

###############################################################################
# Building the binary
###############################################################################
build: bin/kube-controllers-linux-$(ARCH) bin/check-status-linux-$(ARCH)
build-all: $(addprefix sub-build-,$(ARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

# Populates the vendor directory.
vendor: glide.lock
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide

	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \

	docker run --rm \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
		-v $(HOME)/.glide:/home/user/.glide:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		$(CALICO_BUILD) \
		/bin/sh -c 'cd /go/src/$(PACKAGE_NAME) && glide install -strip-vendor'

bin/kube-controllers-linux-$(ARCH): vendor $(SRCFILES)
	mkdir -p bin
	-mkdir -p .go-pkg-cache
	docker run --rm \
	  -e GOOS=$(OS) -e GOARCH=$(ARCH) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  -w /go/src/$(PACKAGE_NAME) \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
      -e GOCACHE=/go-cache \
	  $(CALICO_BUILD) go build -v -o bin/kube-controllers-$(OS)-$(ARCH) -ldflags "-X main.VERSION=$(GIT_VERSION)" ./cmd/kube-controllers/ 

bin/check-status-linux-$(ARCH): vendor $(SRCFILES)
	mkdir -p bin
	-mkdir -p .go-pkg-cache
	docker run --rm \
	  -e GOOS=$(OS) -e GOARCH=$(ARCH) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  -w /go/src/$(PACKAGE_NAME) \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
      -e GOCACHE=/go-cache \
	  $(CALICO_BUILD) go build -v -o bin/check-status-$(OS)-$(ARCH) -ldflags "-X main.VERSION=$(GIT_VERSION)" ./cmd/check-status/

###############################################################################
# Building the image
###############################################################################
## Builds the controller binary and docker image.
image: image.created-$(ARCH)
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

image.created-$(ARCH): bin/kube-controllers-linux-$(ARCH) bin/check-status-linux-$(ARCH)
	# Build the docker image for the policy controller.
	docker build -t $(CONTAINER_NAME):latest-$(ARCH) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	# Need amd64 builds tagged as :latest because Semaphore depends on that
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):latest
endif
	touch $@

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag
	docker push $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker push $(CONTAINER_NAME):$(IMAGETAG)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## tag images of one arch
tag-images: imagetag
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(ARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)


###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
static-checks: vendor check-copyright
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) sh -c '\
			cd  /go/src/$(PACKAGE_NAME) && \
			gometalinter --deadline=300s --disable-all --enable=goimports --enable=vet --enable=errcheck --vendor -s test_utils ./...'

.PHONY: fix
## Fix static checks
fix goimports:
	goimports -l -w ./pkg
	goimports -l -w ./cmd/kube-controllers/main.go
	goimports -l -w ./cmd/check-status/main.go

.PHONY: install-git-hooks
## Install Git hooks
install-git-hooks:
	./install-git-hooks

# Make sure that a copyright statement exists on all go files.
check-copyright:
	./check-copyrights.sh
###############################################################################
# Tests
###############################################################################
## Run the unit tests in a container.
ut: vendor
	-mkdir -p .go-pkg-cache
	docker run --rm --privileged --net=host \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && WHAT=$(WHAT) SKIP=$(SKIP) ./run-uts'

.PHONY: fv
## Build and run the FV tests.
GINKGO_FOCUS?=.*
fv: tests/fv/fv.test image
	@echo Running Go FVs.
	cd tests/fv && ETCD_IMAGE=$(ETCD_IMAGE) HYPERKUBE_IMAGE=$(HYPERKUBE_IMAGE) CONTAINER_NAME=$(CONTAINER_NAME):latest-$(ARCH) PRIVATE_KEY=`pwd`/private.key ./fv.test -ginkgo.slowSpecThreshold 30 -ginkgo.focus $(GINKGO_FOCUS)

tests/fv/fv.test: $(shell find ./tests -type f -name '*.go' -print)
	# We pre-build the test binary so that we can run it outside a container and allow it
	# to interact with docker.
	$(DOCKER_GO_BUILD) go test ./tests/fv -c --tags fvtests -o tests/fv/fv.test

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean image static-checks ut fv

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
	$(MAKE) tag-images push IMAGETAG=${BRANCH_NAME}
	$(MAKE) tag-images push IMAGETAG=$(shell git describe --tags --dirty --always --long)

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

	$(MAKE) image
	$(MAKE) tag-images IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(CONTAINER_NAME):$(VERSION) -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(CONTAINER_NAME):$(VERSION) -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(CONTAINER_NAME):$(VERSION) -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(CONTAINER_NAME):$(VERSION) -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	# Run FV tests against the produced image. We only run the subset tagged as release tests.
	$(MAKE) CONTAINER_NAME=$(CONTAINER_NAME):$(VERSION) GINKGO_FOCUS="Release" fv

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
	$(MAKE) push IMAGETAG=$(VERSION) ARCH=$(ARCH)

	@echo "Finalize the GitHub release based on the pushed tag."
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
	if ! docker run $(CONTAINER_NAME):latest -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(CONTAINER_NAME):latest -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(CONTAINER_NAME):latest -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(CONTAINER_NAME):latest -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push IMAGETAG=latest ARCH=$(ARCH)

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif


###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: help
## Display this help text.
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	$(info Available targets)
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
