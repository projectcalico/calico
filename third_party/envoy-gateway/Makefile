include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/envoy-gateway

ENVOY_GATEWAY_IMAGE ?= envoy-gateway
BUILD_IMAGES ?= $(ENVOY_GATEWAY_IMAGE)

# For updating this version please see
# https://github.com/tigera/operator/blob/master/docs/common_tasks.md#updating-the-bundled-version-of-envoy-gateway
ENVOY_GATEWAY_VERSION=v1.8.2

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

##############################################################################
# Build
##############################################################################
ENVOY_GATEWAY_DOWNLOADED=.envoy-gateway.downloaded

.PHONY: init-source
init-source: $(ENVOY_GATEWAY_DOWNLOADED)
$(ENVOY_GATEWAY_DOWNLOADED):
	mkdir -p envoy-gateway
	curl -sSfL --retry 5 -o /tmp/envoy-gateway.tar.gz https://github.com/envoyproxy/gateway/archive/refs/tags/$(ENVOY_GATEWAY_VERSION).tar.gz
	tar xz --strip-components 1 -C envoy-gateway -f /tmp/envoy-gateway.tar.gz && rm -f /tmp/envoy-gateway.tar.gz

# 	Patches live in two directories, applied in this order:
# 	  patches/     - functional changes to upstream source. Written and
# 	                 reviewed by hand; only ever verified to still apply.
# 	  dep-patches/ - dependency pins for CVE remediation, touching go.mod and
# 	                 go.sum only. Derived from the pinned versions, so these
# 	                 are regenerated rather than edited.
# 	-F0 disables patch's default fuzz factor: a patch whose context no longer
# 	matches must fail rather than land somewhere approximate.
	for patch in patches/*.patch dep-patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d envoy-gateway -p1 -F0 < "$$patch" || exit 1; \
		fi; \
	done
	touch $@

.PHONY: build
build: bin/envoy-gateway-$(ARCH)

LD_FLAGS = \
	-X github.com/envoyproxy/gateway/internal/cmd/version.envoyGatewayVersion=$(ENVOY_GATEWAY_VERSION) \
	-X github.com/envoyproxy/gateway/internal/cmd/version.gitCommitID=$(GIT_COMMIT)

bin/envoy-gateway-$(ARCH): init-source
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C envoy-gateway -buildvcs=false -o ../$@ -v -tags=$(TAGS) -ldflags="$(LD_FLAGS) -s -w" github.com/envoyproxy/gateway/cmd/envoy-gateway'

.PHONY: clean
clean:
	rm -f .envoy-gateway.* .*.created* .*.published* .release.*
	rm -fr bin/ envoy-gateway/
	-docker image rm -f $$(docker images $(ENVOY_GATEWAY_IMAGE) -a -q)

##############################################################################
# Image
##############################################################################
ENVOY_GATEWAY_IMAGE_CREATED=.envoy-gateway.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(ENVOY_GATEWAY_IMAGE): $(ENVOY_GATEWAY_IMAGE_CREATED)
# register is order-only (|) so binfmt setup doesn't trigger unnecessary rebuilds.
$(ENVOY_GATEWAY_IMAGE_CREATED): Dockerfile build | register
	$(DOCKER_BUILD) -t $(ENVOY_GATEWAY_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

##############################################################################
# CI/CD
##############################################################################
ci: image

cd: image-all cd-common

.PHONY: release-build
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@
