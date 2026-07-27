include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/envoy-gateway

ENVOY_GATEWAY_IMAGE ?= envoy-gateway
BUILD_IMAGES ?= $(ENVOY_GATEWAY_IMAGE)

# For updating this version please see
# https://github.com/tigera/operator/blob/master/docs/common_tasks.md#updating-the-bundled-version-of-envoy-gateway
ENVOY_GATEWAY_VERSION=v1.8.0

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

# 	Apply patches for the specified Envoy Gateway version if patches directory exists.
# 	This code checks for the presence of a patches directory corresponding to ENVOY_GATEWAY_VERSION.
# 	If the directory exists, it iterates over all .patch files within it.
# 	For each valid patch file, it applies the patch to the envoy-gateway directory using patch -p1.
	for patch in patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d envoy-gateway -p1 < "$$patch"; \
		fi; \
	done; \

	touch $@

.PHONY: build
build: bin/envoy-gateway-$(ARCH)

LD_FLAGS = \
	-X github.com/envoyproxy/gateway/internal/cmd/version.envoyGatewayVersion=$(ENVOY_GATEWAY_VERSION) \
	-X github.com/envoyproxy/gateway/internal/cmd/version.gitCommitID=$(GIT_COMMIT)

# Upstream envoy-gateway at v1.8.0 requires Go >= 1.26.3 in its go.mod `go`
# directive. release-v3.32 still pins GO_VERSION=1.25.x for the rest of the
# tree, so we need GOTOOLCHAIN here to let Go auto-download a newer toolchain
# inside the build container.
#
# Pin minimum 1.26.4 (not bare `auto`) for defensive parity: plain `auto`
# resolves to upstream's exact `go` directive (today 1.26.3), so pinning a
# floor protects us if a future v1.8.x/v1.9.x cut regresses that directive.
# The `+auto` suffix still lets a higher go.mod directive win without editing
# this line.
#
# Remove this override once release-v3.32 picks up GO_VERSION >= 1.26.4.
bin/envoy-gateway-$(ARCH): init-source
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 GOTOOLCHAIN=go1.26.4+auto go build -C envoy-gateway -buildvcs=false -o ../$@ -v -tags=$(TAGS) -ldflags="$(LD_FLAGS) -s -w" github.com/envoyproxy/gateway/cmd/envoy-gateway'

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
