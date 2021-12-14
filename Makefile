PACKAGE_NAME?=github.com/projectcalico/pod2daemon
GO_BUILD_VER?=v0.58

ORGANIZATION=projectcalico
SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_POD2DAEMON_PROJECT_ID)

# Used so semaphore can trigger the update pin pipelines in projects that have this project as a dependency.
SEMAPHORE_AUTO_PIN_UPDATE_PROJECT_IDS=$(SEMAPHORE_NODE_PRIVATE_PROJECT_ID)

RELEASE_REGISTRIES    ?= gcr.io/projectcalico-org eu.gcr.io/projectcalico-org asia.gcr.io/projectcalico-org us.gcr.io/projectcalico-org
RELEASE_BRANCH_PREFIX ?= release
DEV_TAG_SUFFIX        ?= 0.dev

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
FLEXVOL_IMAGE  ?=pod2daemon-flexvol
DEV_REGISTRIES ?=quay.io/calico calico $(RELEASE_REGISTRIES)
else
FLEXVOL_IMAGE  ?=calico/pod2daemon-flexvol
DEV_REGISTRIES ?=quay.io docker.io
endif

BUILD_IMAGES ?=$(FLEXVOL_IMAGE)

###############################################################################
# Download and include Makefile.common before anything else
###############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

Makefile.common: Makefile.common.$(MAKE_BRANCH)
	cp "$<" "$@"
Makefile.common.$(MAKE_BRANCH):
	# Clean up any files downloaded from other branches so they don't accumulate.
	rm -f Makefile.common.*
	curl --fail $(MAKE_REPO)/Makefile.common -o "$@"

include Makefile.common

###############################################################################

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
else
CGO_ENABLED=0
endif

SRC_FILES=$(shell find -name '*.go')

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf report/
	rm -rf bin/flexvol-$(ARCH)

	docker rmi $(FLEXVOL_IMAGE):latest-$(ARCH) || true
	docker rmi $(FLEXVOL_IMAGE):$(VERSION)-$(ARCH) || true
ifeq ($(ARCH),amd64)
	docker rmi $(FLEXVOL_IMAGE):latest || true
	docker rmi $(FLEXVOL_IMAGE):$(VERSION) || true
endif

###############################################################################
# Building the binary
###############################################################################
.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/flexvol-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/flexvol-$(ARCH)

bin/flexvol-amd64: ARCH=amd64
bin/flexvol-arm64: ARCH=arm64
bin/flexvol-armv7: ARCH=armv7
bin/flexvol-ppc64le: ARCH=ppc64le
bin/flexvol-s390x: ARCH=s390x
bin/flexvol-%: $(SRC_FILES)
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) go build -v -o bin/flexvol-$(ARCH) flexvol/flexvoldriver.go

###############################################################################
# Building the image
###############################################################################
CONTAINER_CREATED=.pod2daemon-flexvol.created-$(ARCH)
.PHONY: image calico/pod2daemon-flexvol
image: $(FLEXVOL_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(FLEXVOL_IMAGE): $(CONTAINER_CREATED)
$(CONTAINER_CREATED): Dockerfile.$(ARCH) bin/flexvol-$(ARCH)
	docker build -t $(FLEXVOL_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) --build-arg GIT_VERSION=$(GIT_VERSION) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(FLEXVOL_IMAGE):latest-$(ARCH) $(FLEXVOL_IMAGE):latest
endif
	touch $@

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: $(SRC_FILES)
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) /bin/bash -c "go test -v ./... | go-junit-report > ./report/tests.xml"

fv st:
	@echo "No FVs or STs available"

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download build-all static-checks ut

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all cd-common

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
	$(MAKE) image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# TODO: Check the reported version is correct for each release artifact. Uncomment when binary supports version command.
	# if ! docker run $(FLEXVOL_IMAGE):$(VERSION)-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	#  echo "Reported version:" `docker run --rm $(FLEXVOL_IMAGE):$(VERSION)-$(ARCH) version` "\nExpected version: $(VERSION)"; \
	#  false; \
	# else \
	#   echo "Version check passed\n"; \
	# fi

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
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=true CONFIRM=true

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
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=true CONFIRM=true

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
