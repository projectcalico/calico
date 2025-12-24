###############################################################################
# Ztunnel Component Makefile
# Builds the Istio ztunnel proxy component
###############################################################################
include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/istio-ztunnel

ZTUNNEL_IMAGE ?= istio-ztunnel-base
BUILD_IMAGES ?= $(ZTUNNEL_IMAGE)

ZTUNNEL_VERSION = 1.28.1

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

###############################################################################
# Source Download and Patching
###############################################################################
ZTUNNEL_DOWNLOADED = .ztunnel.downloaded

.PHONY: init-source
init-source: $(ZTUNNEL_DOWNLOADED)

$(ZTUNNEL_DOWNLOADED):
	mkdir -p ztunnel
	curl -sfL https://github.com/istio/ztunnel/archive/refs/tags/$(ZTUNNEL_VERSION).tar.gz | tar xz --strip-components=1 -C ztunnel
	patch -d ztunnel -p1 < patches/0001-transparent-policies.patch
	touch $@

###############################################################################
# Build
###############################################################################

.PHONY: build
build: bin/ztunnel-$(ARCH)

bin/ztunnel-$(ARCH): $(ZTUNNEL_DOWNLOADED)
	$(DOCKER_RUST_BUILD) \
		sh -c 'cd ztunnel && cargo build --release'
	cp ztunnel/out/rust/release/ztunnel bin/ztunnel-$(ARCH)

###############################################################################
# Image
###############################################################################
ZTUNNEL_IMAGE_CREATED = .ztunnel.created-$(ARCH)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))

sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(ZTUNNEL_IMAGE): $(ZTUNNEL_IMAGE_CREATED)

$(ZTUNNEL_IMAGE_CREATED): Dockerfile bin/ztunnel-$(ARCH)
	$(DOCKER_BUILD) -t $(ZTUNNEL_IMAGE):$(LATEST_IMAGE_TAG)-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(LATEST_IMAGE_TAG)
	touch $@

###############################################################################
# Clean
###############################################################################
.PHONY: clean
clean:
	rm -f $(ZTUNNEL_DOWNLOADED)
	rm -f $(ZTUNNEL_IMAGE_CREATED)
	rm -fr bin/ ztunnel/
	rm -f .release-*
	-docker image rm -f $$(docker images $(ZTUNNEL_IMAGE) -a -q)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean image

.PHONY: cd
cd: image-all var-require-one-of-CONFIRM-DRYRUN var-require-all-BRANCH_NAME
	$(MAKE) retag-build-images-with-registries push-images-to-registries IMAGETAG=$(LATEST_IMAGE_TAG) EXCLUDEARCH="$(EXCLUDEARCH)"

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
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

.PHONY: release-publish
release-publish: release-prereqs .release-$(VERSION).published

.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@
