include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/envoy-proxy

ENVOY_PROXY_IMAGE ?= envoy-proxy
BUILD_IMAGES ?= $(ENVOY_PROXY_IMAGE)

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
	rm -f .envoy-proxy.*
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
$(ENVOY_PROXY_IMAGE_CREATED): Dockerfile
	$(DOCKER_BUILD) --build-arg THIRD_PARTY_REGISTRY=$(THIRD_PARTY_REGISTRY) \
		-t $(ENVOY_PROXY_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

##############################################################################
# CI/CD
##############################################################################
ci: image

cd: image-all cd-common
