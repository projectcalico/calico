###############################################################################
# Istio Component Makefile
# Builds the Istio install-cni and pilot-discovery components
###############################################################################
include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/istio

# Image names matching the prior tigera/istio repository convention
ISTIO_CNI_IMAGE ?= istio-install-cni
ISTIO_PILOT_IMAGE ?= istio-pilot
ISTIO_ZTUNNEL_IMAGE ?= istio-ztunnel

BUILD_IMAGES ?= $(ISTIO_CNI_IMAGE) $(ISTIO_PILOT_IMAGE) $(ISTIO_ZTUNNEL_IMAGE)

# Upstream version (configurable)
ISTIO_VERSION ?= 1.27.3
ISTIO_ZTUNNEL_VERSION ?= $(shell grep -E '^ZTUNNEL_VERSION[[:space:]]*=' $(REPO_ROOT)/third_party/istio-ztunnel/Makefile | cut -d '=' -f2 | tr -d ' ')

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

###############################################################################
# Source Download and Patching
###############################################################################
ISTIO_DOWNLOADED = .istio.downloaded

.PHONY: init-source
init-source: $(ISTIO_DOWNLOADED)

$(ISTIO_DOWNLOADED):
	mkdir -p istio
	curl -sfL https://github.com/istio/istio/archive/refs/tags/$(ISTIO_VERSION).tar.gz | tar xz --strip-components=1 -C istio
	patch -d istio -p1 < patches/0001-dscp-magic-mark-for-transparent-policies.patch
	touch $@

###############################################################################
# Build
###############################################################################
.PHONY: build
build: bin/pilot-discovery-$(ARCH) bin/install-cni-$(ARCH)

bin/install-cni-$(ARCH): BUILD_TAGS=agent,disable_pgv,grpcnotrace,retrynotrace
bin/pilot-discovery-$(ARCH): BUILD_TAGS=disable_pgv,vtprotobuf

bin/pilot-discovery-$(ARCH): $(ISTIO_DOWNLOADED)
	$(call build_binary_dir,istio,./pilot/cmd/pilot-discovery,../$@)

bin/install-cni-$(ARCH): $(ISTIO_DOWNLOADED)
	$(call build_binary_dir,istio,./cni/cmd/install-cni,../$@)

###############################################################################
# Image
###############################################################################
ISTIO_CNI_IMAGE_CREATED = .istio-cni.created-$(ARCH)
ISTIO_PILOT_IMAGE_CREATED = .istio-pilot.created-$(ARCH)
ISTIO_ZTUNNEL_IMAGE_CREATED = .istio-ztunnel.created-$(ARCH)

# Build images for all architectures
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))

sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

# istio-install-cni image
$(ISTIO_CNI_IMAGE): $(ISTIO_CNI_IMAGE_CREATED)
$(ISTIO_CNI_IMAGE_CREATED): Dockerfile-cni bin/install-cni-$(ARCH)
	$(DOCKER_BUILD) -t $(ISTIO_CNI_IMAGE):latest-$(ARCH) -f Dockerfile-cni .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_CNI_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-pilot image
$(ISTIO_PILOT_IMAGE): $(ISTIO_PILOT_IMAGE_CREATED)
$(ISTIO_PILOT_IMAGE_CREATED): Dockerfile-pilot bin/pilot-discovery-$(ARCH)
	$(DOCKER_BUILD) -t $(ISTIO_PILOT_IMAGE):latest-$(ARCH) -f Dockerfile-pilot .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_PILOT_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-ztunnel image
$(ISTIO_ZTUNNEL_IMAGE): $(ISTIO_ZTUNNEL_IMAGE_CREATED)
$(ISTIO_ZTUNNEL_IMAGE_CREATED): Dockerfile-ztunnel
	$(DOCKER_BUILD_THIRD_PARTY) --build-arg ISTIO_ZTUNNEL_VERSION=$(ISTIO_ZTUNNEL_VERSION) -t $(ISTIO_ZTUNNEL_IMAGE):latest-$(ARCH) -f Dockerfile-ztunnel .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_ZTUNNEL_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# Clean
###############################################################################
.PHONY: clean
clean:
	rm -fr bin/ istio/
	rm -f $(ISTIO_DOWNLOADED)
	rm -f $(ISTIO_CNI_IMAGE_CREATED) $(ISTIO_PILOT_IMAGE_CREATED) $(ISTIO_ZTUNNEL_IMAGE_CREATED)
	rm -f .release-*
	-docker image rm -f $$(docker images $(ISTIO_CNI_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_PILOT_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_ZTUNNEL_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean image

.PHONY: cd
cd: image var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) retag-build-images-with-registries push-images-to-registries \
		IMAGETAG=$(LATEST_IMAGE_TAG) EXCLUDEARCH="$(EXCLUDEARCH)" VALIDARCHES=$(ARCH)

.PHONY: push-manifest
push-manifest:
	$(MAKE) push-manifests IMAGETAG=$(LATEST_IMAGE_TAG)

###############################################################################
# Release
###############################################################################
.PHONY: release-build
release-build: .release-$(VERSION).created

.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

.PHONY: release-publish
release-publish: release-prereqs .release-$(VERSION).published

.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@
