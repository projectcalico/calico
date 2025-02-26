include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/whisker
IMAGE_BUILD_MARKER = whisker_container-$(ARCH).created
ARCHES             ?=amd64 arm64
###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

# Configure variables used by ci/cd common targets from lib.Makefile.
BUILD_IMAGES=whisker

BUILD_IMAGE_NAME=node:20.17

DOCKER_RUN_RM:=docker run --rm \
	--env CYPRESS_CACHE_FOLDER=/code/.cache/Cypress \
	--env NPM_TOKEN=${NPM_TOKEN} \
	--user $(shell id -u):$(shell id -g) \
	-v $${PWD}:/code \
	-w /code

$(IMAGE_BUILD_MARKER): register build
	$(DOCKER_BUILD) -t whisker:latest-$(ARCH) -f docker-image/Dockerfile .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(BUILD_IMAGES) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: image build
image: $(IMAGE_BUILD_MARKER)

build:
	$(DOCKER_RUN_RM) $(BUILD_IMAGE_NAME) yarn install -g
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn build

image: $(IMAGE_BUILD_MARKER)

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

install:
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn install -g

yarn-test: install
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn test:cov --silent

format: install
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn format

lint: install
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn lint --quiet

ci: install format lint yarn-test

###############################################################################
# Release
###############################################################################
## Deploys images to registry
cd: image-all cd-common

release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	touch $@

release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@
