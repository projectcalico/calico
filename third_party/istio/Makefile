include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/istio

ISTIO_PILOT_IMAGE ?= istio-pilot
ISTIO_CNI_IMAGE ?= istio-install-cni
ISTIO_ZTUNNEL_IMAGE ?= istio-ztunnel
ISTIO_PROXYV2_IMAGE ?= istio-proxyv2
BUILD_IMAGES ?= $(ISTIO_PILOT_IMAGE) $(ISTIO_CNI_IMAGE) $(ISTIO_ZTUNNEL_IMAGE) $(ISTIO_PROXYV2_IMAGE)

# For updating this version please see
# https://github.com/tigera/operator/blob/master/docs/common_tasks.md#updating-the-bundled-version-of-envoy-gateway
TIGERA_ISTIO_PILOT_IMAGE ?= quay.io/tigera/istio-pilot:1.27.1-ac46ccf35d
TIGERA_ISTIO_CNI_IMAGE ?= quay.io/tigera/istio-install-cni:1.27.1-ac46ccf35d
TIGERA_ISTIO_ZTUNNEL_IMAGE ?= quay.io/tigera/istio-ztunnel:1.27.1-ac46ccf35d
TIGERA_ISTIO_PROXYV2_IMAGE ?= quay.io/tigera/istio-proxyv2:1.27.1-ac46ccf35d

EXCLUDEARCH ?= ppc64le s390x

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
	rm -f .istio-*.* .*.created* .*.published* .release.*
	-docker image rm -f $$(docker images $(ISTIO_PILOT_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_CNI_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_ZTUNNEL_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(ISTIO_PROXYV2_IMAGE) -a -q)

##############################################################################
# Image
##############################################################################
ISTIO_PILOT_IMAGE_CREATED=.istio-pilot.created-$(ARCH)
ISTIO_CNI_IMAGE_CREATED=.istio-cni.created-$(ARCH)
ISTIO_ZTUNNEL_IMAGE_CREATED=.istio-ztunnel.created-$(ARCH)
ISTIO_PROXYV2_IMAGE_CREATED=.istio-proxyv2.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest

$(ISTIO_PILOT_IMAGE): $(ISTIO_PILOT_IMAGE_CREATED)
$(ISTIO_PILOT_IMAGE_CREATED): Dockerfile.pilot
	$(DOCKER_BUILD) --build-arg ISTIO_PILOT_IMAGE=$(TIGERA_ISTIO_PILOT_IMAGE) \
		-t $(ISTIO_PILOT_IMAGE):latest-$(ARCH) -f Dockerfile.pilot .
	touch $@

$(ISTIO_CNI_IMAGE): $(ISTIO_CNI_IMAGE_CREATED)
$(ISTIO_CNI_IMAGE_CREATED): Dockerfile.install-cni
	$(DOCKER_BUILD) --build-arg ISTIO_CNI_IMAGE=$(TIGERA_ISTIO_CNI_IMAGE) \
		-t $(ISTIO_CNI_IMAGE):latest-$(ARCH) -f Dockerfile.install-cni .
	touch $@

$(ISTIO_ZTUNNEL_IMAGE): $(ISTIO_ZTUNNEL_IMAGE_CREATED)
$(ISTIO_ZTUNNEL_IMAGE_CREATED): Dockerfile.ztunnel
	$(DOCKER_BUILD) --build-arg ISTIO_ZTUNNEL_IMAGE=$(TIGERA_ISTIO_ZTUNNEL_IMAGE) \
		-t $(ISTIO_ZTUNNEL_IMAGE):latest-$(ARCH) -f Dockerfile.ztunnel .
	touch $@

$(ISTIO_PROXYV2_IMAGE): $(ISTIO_PROXYV2_IMAGE_CREATED)
$(ISTIO_PROXYV2_IMAGE_CREATED): Dockerfile.proxyv2
	$(DOCKER_BUILD) --build-arg ISTIO_PROXYV2_IMAGE=$(TIGERA_ISTIO_PROXYV2_IMAGE) \
		-t $(ISTIO_PROXYV2_IMAGE):latest-$(ARCH) -f Dockerfile.proxyv2 .
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
