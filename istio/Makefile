###############################################################################
# Istio Component Makefile
# Builds the Istio install-cni and pilot-discovery components
###############################################################################
include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/istio

# Image names matching the prior tigera/istio repository convention
ISTIO_CNI_IMAGE ?= istio-install-cni
ISTIO_PILOT_IMAGE ?= istio-pilot
ISTIO_PROXYV2_IMAGE ?= istio-proxyv2
ISTIO_ZTUNNEL_IMAGE ?= istio-ztunnel

BUILD_IMAGES ?= $(ISTIO_CNI_IMAGE) $(ISTIO_PILOT_IMAGE) $(ISTIO_PROXYV2_IMAGE) $(ISTIO_ZTUNNEL_IMAGE)

# Upstream version (configurable)
ISTIO_VERSION ?= 1.28.1
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
	patch -d istio -p1 < patches/0001-feat-cni-DSCP-magic-mark-support-for-transparent-net.patch
	patch -d istio -p1 < patches/0002-chore-deps-update-golang.org-x-crypto-and-quic-go.patch
	touch $@

###############################################################################
# Build
###############################################################################
.PHONY: build
build: bin/pilot-discovery-$(ARCH) bin/install-cni-$(ARCH) bin/istio-cni-$(ARCH) bin/pilot-agent-$(ARCH)

bin/install-cni-$(ARCH): BUILD_TAGS=agent,disable_pgv,grpcnotrace,retrynotrace
bin/istio-cni-$(ARCH): BUILD_TAGS=agent,disable_pgv,grpcnotrace,retrynotrace
bin/pilot-agent-$(ARCH): BUILD_TAGS=agent,disable_pgv,grpcnotrace,retrynotrace
bin/pilot-discovery-$(ARCH): BUILD_TAGS=disable_pgv,vtprotobuf

bin/install-cni-$(ARCH): $(ISTIO_DOWNLOADED)
	$(call build_binary_dir,istio,./cni/cmd/install-cni,../$@)

bin/istio-cni-$(ARCH): $(ISTIO_DOWNLOADED)
	$(call build_binary_dir,istio,./cni/cmd/istio-cni,../$@)

bin/pilot-agent-$(ARCH): $(ISTIO_DOWNLOADED)
	$(call build_binary_dir,istio,./pilot/cmd/pilot-agent,../$@)

bin/pilot-discovery-$(ARCH): $(ISTIO_DOWNLOADED)
	$(call build_binary_dir,istio,./pilot/cmd/pilot-discovery,../$@)

###############################################################################
# Image
###############################################################################
ISTIO_CNI_IMAGE_CREATED = .istio-cni.created-$(ARCH)
ISTIO_PILOT_IMAGE_CREATED = .istio-pilot.created-$(ARCH)
ISTIO_PROXYV2_IMAGE_CREATED = .istio-proxyv2.created-$(ARCH)
ISTIO_ZTUNNEL_IMAGE_CREATED = .istio-ztunnel.created-$(ARCH)

bin/LICENSE: ../LICENSE.md
	mkdir -p bin
	cp ../LICENSE.md $@

# Build images for all architectures
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))

sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

# istio-install-cni image
$(ISTIO_CNI_IMAGE): $(ISTIO_CNI_IMAGE_CREATED)
$(ISTIO_CNI_IMAGE_CREATED): register Dockerfile-install-cni bin/install-cni-$(ARCH) bin/istio-cni-$(ARCH) bin/LICENSE
	$(DOCKER_BUILD) -t $(ISTIO_CNI_IMAGE):latest-$(ARCH) -f Dockerfile-install-cni .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_CNI_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-pilot image
$(ISTIO_PILOT_IMAGE): $(ISTIO_PILOT_IMAGE_CREATED)
$(ISTIO_PILOT_IMAGE_CREATED): Dockerfile-pilot bin/pilot-discovery-$(ARCH) bin/LICENSE
	$(DOCKER_BUILD) -t $(ISTIO_PILOT_IMAGE):latest-$(ARCH) -f Dockerfile-pilot .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_PILOT_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-proxyv2 image
$(ISTIO_PROXYV2_IMAGE): $(ISTIO_PROXYV2_IMAGE_CREATED)
$(ISTIO_PROXYV2_IMAGE_CREATED): Dockerfile-proxyv2 bin/pilot-agent-$(ARCH) bin/LICENSE
	$(DOCKER_BUILD_THIRD_PARTY) --build-arg ISTIO_VERSION=$(ISTIO_VERSION) -t $(ISTIO_PROXYV2_IMAGE):latest-$(ARCH) -f Dockerfile-proxyv2 .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_PROXYV2_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-ztunnel image
$(ISTIO_ZTUNNEL_IMAGE): $(ISTIO_ZTUNNEL_IMAGE_CREATED)
$(ISTIO_ZTUNNEL_IMAGE_CREATED): Dockerfile-ztunnel bin/LICENSE
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
	rm -f $(ISTIO_CNI_IMAGE_CREATED) $(ISTIO_PILOT_IMAGE_CREATED) $(ISTIO_PROXYV2_IMAGE_CREATED) $(ISTIO_ZTUNNEL_IMAGE_CREATED)
	rm -f .release-*
	-docker image rm -f $$(docker images $(ISTIO_CNI_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_PILOT_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_PROXYV2_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_ZTUNNEL_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean image

.PHONY: cd
cd: image-all cd-common

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
