include ../../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/test-tools/policyscale

# The policyscale CLI renders a generated policy set for a cluster, and flowgen sends traffic at
# it from the same fixture; scale tests run both from this image. Nothing publishes it.
IMAGE_NAME  ?=policyscale
BUILD_IMAGES          ?=$(IMAGE_NAME)

###############################################################################
# Shortcut targets
###############################################################################
default: build image

###############################################################################
# Variables controlling the image
###############################################################################
CONTAINER_CREATED=.container.created-$(ARCH)
BINARIES=./bin/test-tools/policyscale-$(ARCH) ./bin/test-tools/flowgen-$(ARCH)
SRC_FILES=$(shell find ../../hack/cmd/policyscale ../../hack/cmd/flowgen ../../app-policy -name '*.go')

###############################################################################
# Include ../../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../../lib.Makefile

###############################################################################
## Clean enough that a new release build will be clean
###############################################################################
.PHONY: clean
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf .go-pkg-cache bin
	-docker rmi $(IMAGE_NAME):latest-$(ARCH)

###############################################################################
# Building the binaries
###############################################################################
.PHONY: build
## Build the binaries for the current architecture
build: $(BINARIES)
bin/test-tools/policyscale-%: $(SRC_FILES)
	$(call build_binary, ../../hack/cmd/policyscale, $@)
bin/test-tools/flowgen-%: $(SRC_FILES)
	$(call build_binary, ../../hack/cmd/flowgen, $@)

###############################################################################
# Building the image
###############################################################################
## Create the image for the current ARCH
image: $(IMAGE_NAME)

$(IMAGE_NAME): $(CONTAINER_CREATED)
$(CONTAINER_CREATED): Dockerfile $(BINARIES)
	$(DOCKER_BUILD) -t $(IMAGE_NAME):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@
