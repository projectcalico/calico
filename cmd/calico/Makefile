include ../../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/cmd/calico

CALICO_IMAGE ?= calico
BUILD_IMAGES ?= $(CALICO_IMAGE)

###############################################################################
# Include ../../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

BINDIR ?= bin

BINARIES = $(BINDIR)/calico-$(ARCH)

.PHONY: build
build: $(BINARIES)

$(BINDIR)/calico-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, $(PACKAGE_NAME), $@)
else
	$(call build_binary, $(PACKAGE_NAME), $@)
endif

$(BINDIR)/LICENSE: ../../LICENSE.md
	mkdir -p $(BINDIR)
	cp ../../LICENSE.md $@

###############################################################################
# Docker Image
###############################################################################
CALICO_CONTAINER_CREATED = .calico.created-$(ARCH)
CALICO_CONTAINER_FIPS_CREATED = .calico.created-$(ARCH)-fips

ifeq ($(FIPS),true)
CONTAINER_MARKER = $(CALICO_CONTAINER_FIPS_CREATED)
VALIDARCHES = amd64
BINDIR = bin/$(ARCH)-fips
else
CONTAINER_MARKER = $(CALICO_CONTAINER_CREATED)
endif

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

.PHONY: image
image: $(CALICO_IMAGE)

$(CALICO_IMAGE): $(CONTAINER_MARKER)
IMAGE_DEPS = docker/Dockerfile

REGISTRAR_BIN = ../../pod2daemon/bin/node-driver-registrar-$(ARCH)
$(REGISTRAR_BIN):
	$(MAKE) -C ../../pod2daemon bin/node-driver-registrar-$(ARCH)

$(CONTAINER_MARKER): $(IMAGE_DEPS) $(BINARIES) $(BINDIR)/LICENSE $(REGISTRAR_BIN)
	$(DOCKER_BUILD) --build-arg BIN_DIR=cmd/calico/$(BINDIR) --build-arg TARGETARCH=$(ARCH) -t $(CALICO_IMAGE):latest-$(ARCH) -f docker/Dockerfile ../..
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(CALICO_IMAGE)
	touch $@

.PHONY: clean
clean:
	rm -rf bin
	rm -f $(CALICO_CONTAINER_CREATED) $(CALICO_CONTAINER_FIPS_CREATED)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd

ci: static-checks

cd: image-all cd-common

release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@
