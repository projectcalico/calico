include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/kube-controllers

# Name of the images.
# e.g., <registry>/<name>:<tag>
KUBE_CONTROLLERS_IMAGE  ?=kube-controllers
FLANNEL_MIGRATION_IMAGE ?=flannel-migration-controller

BUILD_IMAGES            ?=$(KUBE_CONTROLLERS_IMAGE) $(FLANNEL_MIGRATION_IMAGE)

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

include ../lib.Makefile

SRC_FILES=$(shell find cmd -name '*.go') $(shell find pkg -name '*.go') $(shell find ../libcalico-go -name '*.go')
KUBE_CONTROLLER_CONTAINER_CREATED=.image.created-$(ARCH)
KUBE_CONTROLLER_CONTAINER_FIPS_CREATED=.image.created-$(ARCH)-fips

FIPS ?= false

ifeq ($(FIPS),true)
KUBE_CONTROLLER_CONTAINER_MARKER=$(KUBE_CONTROLLER_CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
else
KUBE_CONTROLLER_CONTAINER_MARKER=$(KUBE_CONTROLLER_CONTAINER_CREATED)
BINDIR=bin
endif

###############################################################################

## Removes all build artifacts.
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -f report/*.xml
	rm -f tests/fv/fv.test
	rm -rf bin image.created-$(ARCH) build report/*.xml release-notes-*
	-docker image rm -f $$(docker images $(FLANNEL_MIGRATION_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(KUBE_CONTROLLERS_IMAGE) -a -q)

###############################################################################
# Building the binary
###############################################################################
LDFLAGS = -X main.VERSION=$(GIT_VERSION)

build: $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH)
build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

$(BINDIR)/kube-controllers-linux-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/kube-controllers/, $@)
else
	$(call build_binary, ./cmd/kube-controllers/, $@)
endif

$(BINDIR)/wrapper-$(ARCH):
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/wrapper, $@)
else
	$(call build_binary, ./cmd/wrapper, $@)
endif

$(BINDIR)/check-status-linux-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/check-status, $@)

$(BINDIR)/kubectl-$(ARCH):
	curl -sSf -L --retry 5 -o $@ https://storage.googleapis.com/kubernetes-release/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl
	chmod +x $@

###############################################################################
# Building the image
###############################################################################
## Builds the controller binary and docker image.
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

image: $(KUBE_CONTROLLER_CONTAINER_MARKER)

$(KUBE_CONTROLLER_CONTAINER_CREATED): Dockerfile docker-image/flannel-migration/Dockerfile $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH) $(BINDIR)/kubectl-$(ARCH) register
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(KUBE_CONTROLLERS_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) -f docker-image/flannel-migration/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(KUBE_CONTROLLER_CONTAINER_FIPS_CREATED): Dockerfile docker-image/flannel-migration/Dockerfile $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH) $(BINDIR)/kubectl-$(ARCH) register
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(KUBE_CONTROLLERS_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(FLANNEL_MIGRATION_IMAGE):latest-fips-$(ARCH) -f docker-image/flannel-migration/Dockerfile .
	$(MAKE) FIPS=true retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

###############################################################################
# Static checks
###############################################################################
# Make sure that a copyright statement exists on all go files.
check-copyright:
	./check-copyrights.sh

###############################################################################
# Tests
###############################################################################
ifeq ($(SEMAPHORE_GIT_REF_TYPE), pull-request)
# Determine the tests to run using the test spider tool, which emits a list of impacted packages.
MAYBE_WHAT=$(shell $(DOCKER_GO_BUILD) sh -c 'go run ../hack/test/spider -commit-range=${SEMAPHORE_GIT_COMMIT_RANGE} -filter-dir kube-controllers/')
else
# By default, run all tests.
MAYBE_WHAT=.
endif

# Filter the list of directories to only those that have tests.
ifneq ("$(MAYBE_WHAT)","")
WHAT=$(shell find $(MAYBE_WHAT) -name "*_test.go" | xargs dirname | sort -u)
endif

# The list of test binaries to build.
# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
TEST_BINARIES=$(addsuffix /ut.test,$(WHAT))

## Run the unit tests in a container.
test: ut
ut fv: $(TEST_BINARIES)
	KUBE_IMAGE=$(CALICO_BUILD) \
		   ETCD_IMAGE=$(ETCD_IMAGE) \
		   CONTAINER_NAME=$(KUBE_CONTROLLERS_IMAGE):latest-$(ARCH) \
		   MIGRATION_CONTAINER_NAME=$(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) \
		   CRDS=$(CURDIR)/../libcalico-go/config/crd \
		   CERTS_PATH=$(CERTS_PATH) \
		   ./run-uts $(WHAT)

# Produce test binaries for each package that needs them.
# ginkgo doesn't let you produce a single test binary with multiple packages.
# Only do this if there are .go files in the path.
%/ut.test: $(SRC_FILES)
	if [ $$(find ./$* -name '*.go' | wc -l) -gt 0 ]; then \
		$(DOCKER_RUN) $(CALICO_BUILD) go test ./$* -c --tags fvtests -o $@; \
	else \
		echo "Skipping $* as it has no .go files in it"; \
	fi

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download image-all static-checks ut

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	$(MAKE) FIPS=true retag-build-images-with-registries IMAGETAG=$(VERSION)-fips RELEASE=true LATEST_IMAGE_TAG=latest-fips
	# Generate the `latest` images.
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@


# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	touch $@

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@


# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run $(KUBE_CONTROLLERS_IMAGE):latest --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(KUBE_CONTROLLERS_IMAGE):latest --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):latest --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):latest --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
