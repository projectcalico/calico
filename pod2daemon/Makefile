include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/pod2daemon

# Name of the images.
# e.g., <registry>/<name>:<tag>
FLEXVOL_IMAGE  ?=pod2daemon-flexvol
BUILD_IMAGES ?=$(FLEXVOL_IMAGE)

###############################################################################
# Download and include ../lib.Makefile before anything else
###############################################################################

include ../lib.Makefile

###############################################################################

# We need CGO to leverage Boring SSL.  However, pod2daemon doesn't perform any crypto,
# so we can disable it across the board.
CGO_ENABLED=0

SRC_FILES=$(shell find -name '*.go')

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
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
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
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
release-build: .release-$(VERSION).created 
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
