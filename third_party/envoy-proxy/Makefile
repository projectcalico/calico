PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/envoy-proxy

ENVOY_PROXY_IMAGE ?= envoy-proxy
BUILD_IMAGES ?= $(ENVOY_PROXY_IMAGE)

# For updating this version please see
# https://github.com/tigera/operator/blob/master/docs/common_tasks.md#updating-the-bundled-version-of-envoy-gateway
# See https://gateway.envoyproxy.io/news/releases/matrix/ for version compatibility.
ENVOYBINARY_IMAGE ?= $(call _read_default,.versions.envoy_binary_image)

# Envoy proxy artifacts are only supported for amd64 and arm64.
ARCHES ?= $(call _read_default_list,.architectures.envoy_proxy)

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

##############################################################################
# Build
##############################################################################
.PHONY: build
build: ;

.PHONY: clean
clean:
	rm -f .envoy-proxy.* .*.created* .*.published* .release.*
	rm -fr bin/ envoy-proxy/
	-docker image rm -f $$(docker images $(ENVOY_PROXY_IMAGE) -a -q)

##############################################################################
# Image
##############################################################################
ENVOY_PROXY_IMAGE_CREATED=.envoy-proxy.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(ENVOY_PROXY_IMAGE): $(ENVOY_PROXY_IMAGE_CREATED)
$(ENVOY_PROXY_IMAGE_CREATED): Dockerfile | register
	$(DOCKER_BUILD) --build-arg ENVOYBINARY_IMAGE=$(ENVOYBINARY_IMAGE) \
		-t $(ENVOY_PROXY_IMAGE):latest-$(ARCH) -f Dockerfile .
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
