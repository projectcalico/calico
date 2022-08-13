include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/pod2daemon

# Name of the images.
# e.g., <registry>/<name>:<tag>
FLEXVOL_IMAGE   ?=pod2daemon-flexvol
CSI_IMAGE       ?=csi
REGISTRAR_IMAGE ?=node-driver-registrar
BUILD_IMAGES    ?=$(FLEXVOL_IMAGE) $(CSI_IMAGE) $(REGISTRAR_IMAGE)

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
	find . -name '.*.published*' -type f -delete
	rm -rf report/
	rm -rf bin/flexvol-$(ARCH)
	rm -rf bin/$(CSI_IMAGE)-$(ARCH)
	rm -rf bin/$(REGISTRAR_IMAGE)-$(ARCH)

	docker rmi $(FLEXVOL_IMAGE):latest-$(ARCH) || true
	docker rmi $(FLEXVOL_IMAGE):$(VERSION)-$(ARCH) || true
	$(MAKE) clean-registrar
ifeq ($(ARCH),amd64)
	docker rmi $(FLEXVOL_IMAGE):latest || true
	docker rmi $(FLEXVOL_IMAGE):$(VERSION) || true
endif

###############################################################################
# Building the binary
###############################################################################
.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/flexvol-,$(VALIDARCHES)) $(addprefix bin/csi-driver-,$(VALIDARCHES)) $(addprefix bin/node-driver-registrar-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/node-driver-registrar-$(ARCH) bin/flexvol-$(ARCH) bin/csi-driver-$(ARCH)

bin/flexvol-amd64: ARCH=amd64
bin/flexvol-arm64: ARCH=arm64
bin/flexvol-armv7: ARCH=armv7
bin/flexvol-ppc64le: ARCH=ppc64le
bin/flexvol-s390x: ARCH=s390x
bin/flexvol-%: $(SRC_FILES)
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) go build -v -o bin/flexvol-$(ARCH) flexvol/flexvoldriver.go

bin/csi-driver-amd64: ARCH=amd64
bin/csi-driver-arm64: ARCH=arm64
bin/csi-driver-armv7: ARCH=armv7
bin/csi-driver-ppc64le: ARCH=ppc64le
bin/csi-driver-s390x: ARCH=s390x
bin/csi-driver-%: $(SRC_FILES)
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) go build -v -o bin/csi-driver-$(ARCH) csidriver/main.go

UPSTREAM_REGISTRAR_PROJECT ?= kubernetes-csi/$(REGISTRAR_IMAGE)
UPSTREAM_REGISTRAR_TAG     ?= v2.5.1

REGISTRAR_TIGERA_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && \
                    			  go build -v -o bin/csi-node-driver-registrar cmd/csi-node-driver-registrar/*.go"
REGISTRAR_UPSTREAM_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && \
							      make build BUILD_PLATFORMS=$(BUILD_PLATFORMS)"

ifeq ($(ARCH), $(filter $(ARCH),amd64))
# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
CGO_ENABLED=1

REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),arm64))
CGO_ENABLED=0
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),armv7))
CGO_ENABLED=0
GOARCH=arm -e GOARM=7
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),ppc64le))
BUILD_PLATFORMS="linux ppc64le -ppc64le"
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),s390x))
BUILD_PLATFORMS="linux s390x -s390x"
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),win64))
BUILD_PLATFORMS="windows amd64 .exe"
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
endif

bin/node-driver-registrar-%: clone-registrar-upstream
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) \
			-v $(REPO_ROOT)/pod2daemon/$(REGISTRAR_IMAGE):/go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT):rw \
			$(CALICO_BUILD) \
			/bin/bash -c $(REGISTRAR_BUILD_CMD)
			mv $(REGISTRAR_IMAGE)/bin/csi-node-driver-registrar $@

clone-registrar-upstream:
ifeq ("$(wildcard ./$(REGISTRAR_IMAGE))", "")
	@echo "Directory does not exist."
	git clone --depth 1 --branch $(UPSTREAM_REGISTRAR_TAG) --single-branch git@github.com:$(UPSTREAM_REGISTRAR_PROJECT).git
else
	@echo "Upstream repo already cloned."
endif

clean-registrar:
	rm -rf node-driver-registrar

###############################################################################
# Building the image
###############################################################################
FLEXVOL_CONTAINER_CREATED=.pod2daemon-flexvol.created-$(ARCH)
CSI_CONTAINER_CREATED=.calico-csi.created-$(ARCH)
REGISTRAR_CONTAINER_CREATED=.csi-registrar.created-$(ARCH)
.PHONY: image calico/pod2daemon-flexvol
image: $(FLEXVOL_IMAGE) $(CSI_IMAGE) $(REGISTRAR_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(FLEXVOL_IMAGE): $(FLEXVOL_CONTAINER_CREATED)
$(FLEXVOL_CONTAINER_CREATED): Dockerfile.$(ARCH) bin/flexvol-$(ARCH)
	$(DOCKER_BUILD) -t $(FLEXVOL_IMAGE):latest-$(ARCH) -f Dockerfile.$(ARCH) . --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(FLEXVOL_IMAGE)
	touch $@

$(CSI_IMAGE): $(CSI_CONTAINER_CREATED)
$(CSI_CONTAINER_CREATED): csidriver/Dockerfile.$(ARCH) bin/csi-driver-$(ARCH)
	$(DOCKER_BUILD) -t $(CSI_IMAGE):latest-$(ARCH) -f csidriver/Dockerfile.$(ARCH) . --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(CSI_IMAGE)
	touch $@

$(REGISTRAR_IMAGE): $(REGISTRAR_CONTAINER_CREATED)
$(REGISTRAR_CONTAINER_CREATED): node-driver-registrar-docker/Dockerfile.$(ARCH) bin/node-driver-registrar-$(ARCH)
	$(DOCKER_BUILD) -t $(REGISTRAR_IMAGE):latest-$(ARCH) -f node-driver-registrar-docker/Dockerfile.$(ARCH) . --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(REGISTRAR_IMAGE)
	touch $@

node-driver-registrar/%:

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
ci: clean mod-download build-all clean-registrar static-checks ut

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
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
