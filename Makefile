PACKAGE_NAME?=github.com/projectcalico/pod2daemon
GO_BUILD_VER?=v0.49

SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_POD2DAEMON_PROJECT_ID)

# Used so semaphore can trigger the update pin pipelines in projects that have this project as a dependency.
SEMAPHORE_AUTO_PIN_UPDATE_PROJECT_IDS=$(SEMAPHORE_NODE_PRIVATE_PROJECT_ID)

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

BUILD_IMAGE?=calico/pod2daemon-flexvol
PUSH_IMAGES?=$(BUILD_IMAGE) quay.io/calico/pod2daemon-flexvol
RELEASE_IMAGES?=

SRC_FILES=$(shell find -name '*.go')

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf report/
	rm -rf bin/flexvol-$(ARCH)

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
build-all: $(addprefix bin/flexvol-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/flexvol-$(ARCH)

bin/flexvol-amd64: ARCH=amd64
bin/flexvol-arm64: ARCH=arm64
bin/flexvol-ppc64le: ARCH=ppc64le
bin/flexvol-s390x: ARCH=s390x
bin/flexvol-%: $(SRC_FILES)
	$(DOCKER_RUN) $(CALICO_BUILD) go build -v -o bin/flexvol-$(ARCH) flexvol/flexvoldriver.go

###############################################################################
# Building the image
###############################################################################
CONTAINER_CREATED=.pod2daemon-flexvol.created-$(ARCH)
.PHONY: image calico/pod2daemon-flexvol
image: $(BUILD_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(BUILD_IMAGE): $(CONTAINER_CREATED)
$(CONTAINER_CREATED): Dockerfile.$(ARCH) bin/flexvol-$(ARCH)
	docker build -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) --build-arg GIT_VERSION=$(GIT_VERSION) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif
	touch $@

###############################################################################
# Image build/push
###############################################################################
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

imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGES)))

sub-single-push-%:
	docker push $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

## push all arches
push-all: imagetag $(addprefix sub-push-,$(VALIDARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## push multi-arch manifest where supported
push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using
	# $(DOCKER_CONFIG) holds the docker login credentials path to credentials based on
	# manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(VALIDARCHES)) --template $(call unescapefs,$*:$(IMAGETAG))-ARCH --target $(call unescapefs,$*:$(IMAGETAG))"

 ## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch for all supported registries
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
cd: image-all
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=${BRANCH_NAME} EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=${GIT_VERSION} EXCLUDEARCH="$(EXCLUDEARCH)"

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
	$(MAKE) image-all
	$(MAKE) tag-images-all IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images-all IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# TODO: Check the reported version is correct for each release artifact. Uncomment when binary supports version command.
	# if ! docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	#  echo "Reported version:" `docker run --rm $(BUILD_IMAGE):$(VERSION)-$(ARCH) version` "\nExpected version: $(VERSION)"; \
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
	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=$(VERSION)

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
	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
