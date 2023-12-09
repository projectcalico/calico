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
	rm -rf bin

	-docker image rm -f $$(docker images $(CSI_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(FLEXVOL_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(REGISTRAR_IMAGE) -a -q)
	$(MAKE) clean-registrar

###############################################################################
# Building the binary
###############################################################################
FIPS ?= false

FLEXVOL_CONTAINER_MARKER=$(FLEXVOL_CONTAINER_CREATED)
ifeq ($(FIPS),true)
CSI_CONTAINER_MARKER=$(CSI_CONTAINER_FIPS_CREATED)
REGISTRAR_CONTAINER_MARKER=$(REGISTRAR_CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
else
CSI_CONTAINER_MARKER=$(CSI_CONTAINER_CREATED)
REGISTRAR_CONTAINER_MARKER=$(REGISTRAR_CONTAINER_CREATED)
BINDIR=bin
endif

.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/flexvol-,$(VALIDARCHES)) $(addprefix $(BINDIR)/csi-driver-,$(VALIDARCHES)) $(addprefix $(BINDIR)/node-driver-registrar-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: $(BINDIR)/node-driver-registrar-$(ARCH) bin/flexvol-$(ARCH) $(BINDIR)/csi-driver-$(ARCH)

# We need CGO to leverage Boring SSL.  However, pod2daemon doesn't perform any crypto,
# so we can disable it across the board.
bin/flexvol-amd64: ARCH=amd64
bin/flexvol-arm64: ARCH=arm64
bin/flexvol-ppc64le: ARCH=ppc64le
bin/flexvol-s390x: ARCH=s390x
bin/flexvol-%: $(SRC_FILES)
	$(call build_binary, flexvol/flexvoldriver.go, $@)

$(BINDIR)/csi-driver-arm64: ARCH=arm64
$(BINDIR)/csi-driver-ppc64le: ARCH=ppc64le
$(BINDIR)/csi-driver-s390x: ARCH=s390x
$(BINDIR)/csi-driver-%: $(SRC_FILES)
	$(call build_binary, csidriver/main.go, $@)

UPSTREAM_REGISTRAR_PROJECT ?= kubernetes-csi/$(REGISTRAR_IMAGE)
UPSTREAM_REGISTRAR_TAG     ?= v2.9.1

REGISTRAR_TIGERA_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && \
	go build -tags $(TAGS) -buildvcs=false -v -o $(BINDIR)/csi-node-driver-registrar cmd/csi-node-driver-registrar/*.go"
REGISTRAR_UPSTREAM_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && \
	make build BUILD_PLATFORMS=$(BUILD_PLATFORMS)"

ifeq ($(ARCH), $(filter $(ARCH),amd64))
# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
CGO_ENABLED=1
ifeq ($(FIPS),true)
TAGS=fipsstrict
GOEXPERIMENT=boringcrypto
else
GOEXPERIMENT=""
endif
else ifeq ($(ARCH), $(filter $(ARCH),arm64))
CGO_ENABLED=0
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),ppc64le))
BUILD_PLATFORMS="linux ppc64le ppc64le"
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),s390x))
BUILD_PLATFORMS="linux s390x s390x"
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),win64))
BUILD_PLATFORMS="windows amd64 amd64"
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
endif

$(BINDIR)/node-driver-registrar-%: clone-registrar-upstream
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) -e GOEXPERIMENT=$(GOEXPERIMENT) \
			-v $(REPO_ROOT)/pod2daemon/$(REGISTRAR_IMAGE):/go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT):rw \
			$(CALICO_BUILD) \
			/bin/bash -c $(REGISTRAR_BUILD_CMD)
			mv $(REGISTRAR_IMAGE)/$(BINDIR)/csi-node-driver-registrar $@
clone-registrar-upstream:
ifeq ("$(wildcard ./$(REGISTRAR_IMAGE))", "")
	@echo "Directory does not exist."
	git clone --depth 1 --branch $(UPSTREAM_REGISTRAR_TAG) --single-branch https://github.com/$(UPSTREAM_REGISTRAR_PROJECT).git
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
CSI_CONTAINER_FIPS_CREATED=.calico-csi.created-$(ARCH)-fips
REGISTRAR_CONTAINER_FIPS_CREATED=.csi-registrar.created-$(ARCH)-fips

.PHONY: image calico/pod2daemon-flexvol
image: $(FLEXVOL_IMAGE) $(CSI_IMAGE) $(REGISTRAR_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

$(FLEXVOL_IMAGE): $(FLEXVOL_CONTAINER_MARKER)
$(FLEXVOL_CONTAINER_CREATED): flexvol/docker-image/Dockerfile bin/flexvol-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=bin -t $(FLEXVOL_IMAGE):latest-$(ARCH) -f flexvol/docker-image/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(FLEXVOL_IMAGE)
	touch $@

$(CSI_IMAGE): $(CSI_CONTAINER_MARKER)
$(CSI_CONTAINER_CREATED): csidriver/Dockerfile $(BINDIR)/csi-driver-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(CSI_IMAGE):latest-$(ARCH) -f csidriver/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(CSI_IMAGE)
	touch $@

$(CSI_CONTAINER_FIPS_CREATED): csidriver/Dockerfile $(BINDIR)/csi-driver-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(CSI_IMAGE):latest-fips-$(ARCH) -f csidriver/Dockerfile .
	$(MAKE) FIPS=true retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips BUILD_IMAGES=$(CSI_IMAGE) LATEST_IMAGE_TAG=latest-fips
	touch $@

$(REGISTRAR_IMAGE): $(REGISTRAR_CONTAINER_MARKER)
$(REGISTRAR_CONTAINER_CREATED): node-driver-registrar-docker/Dockerfile $(BINDIR)/node-driver-registrar-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(REGISTRAR_IMAGE):latest-$(ARCH) -f node-driver-registrar-docker/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(REGISTRAR_IMAGE)
	touch $@

$(REGISTRAR_CONTAINER_FIPS_CREATED): node-driver-registrar-docker/Dockerfile $(BINDIR)/node-driver-registrar-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(REGISTRAR_IMAGE):latest-fips-$(ARCH) -f node-driver-registrar-docker/Dockerfile .
	$(MAKE) FIPS=true retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips BUILD_IMAGES=$(REGISTRAR_IMAGE) LATEST_IMAGE_TAG=latest-fips
	touch $@
node-driver-registrar/release-tools/filter-junit.go:

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
	$(MAKE) FIPS=true BUILD_IMAGES='$(CSI_IMAGE) $(REGISTRAR_IMAGE)' retag-build-images-with-registries IMAGETAG=$(VERSION)-fips RELEASE=true LATEST_IMAGE_TAG=latest-fips
	$(MAKE) FIPS=true BUILD_IMAGES='$(CSI_IMAGE) $(REGISTRAR_IMAGE)' retag-build-images-with-registries RELEASE=true IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true BUILD_IMAGES='$(CSI_IMAGE) $(REGISTRAR_IMAGE)' push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true BUILD_IMAGES='$(CSI_IMAGE) $(REGISTRAR_IMAGE)' push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
