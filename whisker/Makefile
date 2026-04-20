include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/whisker
IMAGE_BUILD_MARKER = whisker_container-$(ARCH).created
# Only amd64 and arm64 are supported. `=` (not `?=`) so env-provided ARCHES
# from the release manager doesn't override the allowlist.
ARCHES             = amd64 arm64

# Configure variables used by ci/cd common targets from lib.Makefile.
BUILD_IMAGES=whisker
BUILD_IMAGE_NAME=node:22.15

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

DOCKER_RUN_RM:=docker run --rm \
	--env CYPRESS_CACHE_FOLDER=/code/.cache/Cypress \
	--env NPM_TOKEN=${NPM_TOKEN} \
	--user $(shell id -u):$(shell id -g) \
	-v $${PWD}:/code \
	-w /code

# Downstream CI jobs that docker-load a pre-built image from the GCS cache set
# IMAGE_PREBUILT=true so the marker rule skips the yarn build and image build.
ifeq ($(IMAGE_PREBUILT),true)
$(IMAGE_BUILD_MARKER):
	@docker image inspect whisker:latest-$(ARCH) >/dev/null 2>&1 || \
		{ echo "ERROR: IMAGE_PREBUILT=true but whisker:latest-$(ARCH) is not loaded" >&2; exit 1; }
	@touch $@
else
# register is order-only (|) so binfmt setup doesn't trigger unnecessary rebuilds.
$(IMAGE_BUILD_MARKER): build bin/LICENSE | register
	$(DOCKER_BUILD) --build-arg BIN_DIR=bin -t whisker:latest-$(ARCH) -f docker-image/Dockerfile .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(BUILD_IMAGES) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@
endif

bin/LICENSE: ../LICENSE.md
	@mkdir -p bin
	cp ../LICENSE.md $@

.PHONY: image build
image: $(IMAGE_BUILD_MARKER)

build:
	$(DOCKER_RUN_RM) $(BUILD_IMAGE_NAME) yarn install -g
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn build

image-nginx-test: $(IMAGE_BUILD_MARKER)
	docker run --rm whisker:latest-$(ARCH) test

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*
	$(MAKE) image-nginx-test ARCH=$*

install:
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn install -g

yarn-test: install
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn test:cov --silent

format: install
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn format

lint: install
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn lint --quiet

ci: ut install format lint yarn-test

ut: image-nginx-test

.PHONY: clean
clean:
	rm -rf bin dist node_modules *.created *.published

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
