include ../../metadata.mk

PACKAGE_NAME?=github.com/projectcalico/calico/test-tools/mocknode

IMAGE_NAME  ?=mock-node
BUILD_IMAGES          ?=$(IMAGE_NAME)

###############################################################################
# Shortcut targets
###############################################################################
default: build image
test: ut ## Run the tests for the current platform/architecture

###############################################################################
# Variables controlling the image
###############################################################################
CONTAINER_CREATED=.container.created-$(ARCH)
# Files that go into the image
BINARY=./bin/test-tools/mocknode-$(ARCH)
# Files to be built
SRC_FILES=$(shell find . -name '*.go' | grep -v vendor) \
          $(shell find ../../libcalico-go -name '*.go' | grep -v vendor)\
          $(shell find ../../typha -name '*.go' | grep -v vendor)

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
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf .go-pkg-cache bin
	# Delete images that we built in this repo
	-docker rmi $(IMAGE_NAME):latest-$(ARCH)

###############################################################################
# Building the binary
###############################################################################

LDFLAGS = -X main.VERSION=$(GIT_VERSION)

.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/mocknode-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: $(BINARY)
bin/test-tools/mocknode-amd64: ARCH=amd64
bin/test-tools/mocknode-%: $(SRC_FILES)
	$(call build_binary, ./cmd/mocknode, $@)

###############################################################################
# Building the image
###############################################################################
## Create the image for the current ARCH
image: $(IMAGE_NAME)

## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(IMAGE_NAME): $(CONTAINER_CREATED)
$(CONTAINER_CREATED): Dockerfile $(BINARY)
	$(DOCKER_BUILD) -t $(IMAGE_NAME):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

## Run the tests in a container. Useful for CI, Mac dev
ut:
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) /bin/bash -c "$(GIT_CONFIG_SSH) go test -v $(GOTEST_ARGS) ./..."

fv:
	echo "Currently has no FV tests."

st:
	echo "Currently has no STs."

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean image test static-checks
## Deploys images to registry
cd: image-all cd-common
