###############################################################################
# Istio Component Makefile
# Builds the Istio install-cni and pilot-discovery components
###############################################################################
include ../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/istio

ISTIO_CNI_IMAGE ?= istio-install-cni
ISTIO_PILOT_IMAGE ?= istio-pilot
ISTIO_PROXYV2_IMAGE ?= istio-proxyv2
ISTIO_ZTUNNEL_IMAGE ?= istio-ztunnel

BUILD_IMAGES ?= $(ISTIO_CNI_IMAGE) $(ISTIO_PILOT_IMAGE) $(ISTIO_PROXYV2_IMAGE) $(ISTIO_ZTUNNEL_IMAGE)

# Only amd64 and arm64 are supported. `=` (not `?=`) so env-provided ARCHES
# from the release manager doesn't override the allowlist.
ARCHES = amd64 arm64

# Upstream version (configurable)
ISTIO_VERSION ?= 1.29.2

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
ZTUNNEL_DOWNLOADED = .ztunnel.downloaded

.PHONY: init-istio-source init-ztunnel-source init-sources
init-istio-source: $(ISTIO_DOWNLOADED)
init-ztunnel-source: $(ZTUNNEL_DOWNLOADED)

# init-sources is a barrier: all upstream sources must be downloaded and
# patched before any per-arch image build runs. Without it, parallel sub-makes
# race on creating the shared stamp files.
init-sources: $(ISTIO_DOWNLOADED) $(ZTUNNEL_DOWNLOADED)

$(ISTIO_DOWNLOADED):
	mkdir -p istio
	curl -sfL https://github.com/istio/istio/archive/refs/tags/$(ISTIO_VERSION).tar.gz | tar xz --strip-components=1 -C istio
	patch -d istio -p1 < patches/0001-feat-cni-DSCP-magic-mark-support-for-transparent-net.patch
	patch -d istio -p1 < patches/0003-Update-deps-for-CVE-fixes.patch
	touch $@

$(ZTUNNEL_DOWNLOADED):
	mkdir -p ztunnel
	curl -sfL https://github.com/istio/ztunnel/archive/refs/tags/$(ISTIO_VERSION).tar.gz | tar xz --strip-components=1 -C ztunnel
	patch -d ztunnel -p1 < patches/0002-transparent-policies.patch
	touch $@

###############################################################################
# Build
###############################################################################
.PHONY: build build-istio build-ztunnel
build: build-istio build-ztunnel

build-istio: bin/pilot-discovery-$(ARCH) bin/install-cni-$(ARCH) bin/istio-cni-$(ARCH) bin/pilot-agent-$(ARCH)
build-ztunnel: bin/ztunnel-$(ARCH)

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

bin/ztunnel-$(ARCH): $(ZTUNNEL_DOWNLOADED) | register
	$(DOCKER_RUST_BUILD) \
		sh -c 'cd ztunnel && cargo build --release'
	cp ztunnel/out/rust/release/ztunnel bin/ztunnel-$(ARCH)

###############################################################################
# Image
###############################################################################
ISTIO_CNI_IMAGE_CREATED = .istio-cni.created-$(ARCH)
ISTIO_PILOT_IMAGE_CREATED = .istio-pilot.created-$(ARCH)
ISTIO_PROXYV2_IMAGE_CREATED = .istio-proxyv2.created-$(ARCH)
ISTIO_ZTUNNEL_IMAGE_CREATED = .istio-ztunnel.created-$(ARCH)

# Build images for all architectures.
#
# Sources are downloaded once via the init-sources barrier, then per-arch
# sub-makes run in parallel; each sub-image-% sub-make also builds its four
# istio images concurrently via the inherited jobserver.
#
# DOCKER_RUN in lib.Makefile is :=-expanded (so GOARCH is baked at include
# time), which is why per-arch parallelism has to be a sub-make per arch
# rather than a flat target matrix in a single process.
ISTIO_PARALLEL_JOBS ?= 4

.PHONY: image-all
image-all:
	$(MAKE) init-sources
	$(MAKE) -j$(ISTIO_PARALLEL_JOBS) $(addprefix sub-image-,$(VALIDARCHES))

sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

# Producer image carrying the patched nftables + libnftnl RPMs that the
# install-cni image installs in its almalinux build stage. Tag is
# content-addressed; see hack/rpms/nftables/Makefile.
include ../hack/rpms/nftables/image.mk

.PHONY: nft-rpms-image
nft-rpms-image:
	$(MAKE) -C ../hack/rpms/nftables image ARCH=$(ARCH)

# istio-install-cni image
$(ISTIO_CNI_IMAGE): $(ISTIO_CNI_IMAGE_CREATED)
# Drop --pull from DOCKER_BUILD: with --pull=always, buildkit treats the
# nft-rpms build context (docker-image://calico/nftables-rpms:<sha>-<arch>)
# as a registry pull and fails when that tag hasn't been pushed yet (PR
# builds, fresh local builds). Other base images are pinned by tag so cache
# freshness is fine without --pull.
$(ISTIO_CNI_IMAGE_CREATED): DOCKER_PULL :=
$(ISTIO_CNI_IMAGE_CREATED): Dockerfile-install-cni bin/install-cni-$(ARCH) bin/istio-cni-$(ARCH) | register nft-rpms-image
	$(DOCKER_BUILD) --build-context nft-rpms=docker-image://$(NFT_RPMS_IMAGE) -t $(ISTIO_CNI_IMAGE):latest-$(ARCH) -f Dockerfile-install-cni .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_CNI_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-pilot image
$(ISTIO_PILOT_IMAGE): $(ISTIO_PILOT_IMAGE_CREATED)
$(ISTIO_PILOT_IMAGE_CREATED): Dockerfile-pilot bin/pilot-discovery-$(ARCH)
	$(DOCKER_BUILD) -t $(ISTIO_PILOT_IMAGE):latest-$(ARCH) -f Dockerfile-pilot .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_PILOT_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-proxyv2 image
$(ISTIO_PROXYV2_IMAGE): $(ISTIO_PROXYV2_IMAGE_CREATED)
$(ISTIO_PROXYV2_IMAGE_CREATED): Dockerfile-proxyv2 bin/pilot-agent-$(ARCH)
	$(DOCKER_BUILD) --build-arg ISTIO_VERSION=$(ISTIO_VERSION) -t $(ISTIO_PROXYV2_IMAGE):latest-$(ARCH) -f Dockerfile-proxyv2 .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_PROXYV2_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# istio-ztunnel image
$(ISTIO_ZTUNNEL_IMAGE): $(ISTIO_ZTUNNEL_IMAGE_CREATED)
$(ISTIO_ZTUNNEL_IMAGE_CREATED): Dockerfile-ztunnel bin/ztunnel-$(ARCH)
	$(DOCKER_BUILD) -t $(ISTIO_ZTUNNEL_IMAGE):latest-$(ARCH) -f Dockerfile-ztunnel .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(ISTIO_ZTUNNEL_IMAGE) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# Clean
###############################################################################
.PHONY: clean
clean:
	rm -fr bin/ istio/ ztunnel/
	rm -f $(ISTIO_DOWNLOADED) $(ZTUNNEL_DOWNLOADED)
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
