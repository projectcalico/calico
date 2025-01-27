include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/oss-ui
IMAGE_BUILD_MARKER = oss_ui_container-$(ARCH).created

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

# Configure variables used by ci/cd common targets from lib.Makefile.
BUILD_IMAGES=goldmane

BUILD_IMAGE_NAME=tigera/yarn-build
QEMU_IMAGE ?= calico/qemu-user-static:latest

DOCKER_RUN_RM:=docker run --rm \
	--env CYPRESS_CACHE_FOLDER=/code/.cache/Cypress \
	--env NPM_TOKEN=${NPM_TOKEN} \
	--user $(shell id -u):$(shell id -g) \
	-v $${PWD}:/code \
	-w /code

$(IMAGE_BUILD_MARKER): build
	touch $@

.PHONY: image build
image: $(IMAGE_BUILD_MARKER)

build-container:
	docker buildx build --load --pull -t $(BUILD_IMAGE_NAME) -f docker-image/Dockerfile.build .

build: build-container
	$(DOCKER_RUN_RM) $(BUILD_IMAGE_NAME) yarn install -g
	$(DOCKER_RUN_RM) -e NODE_OPTIONS=--max_old_space_size=8192 -e CNX_APP_VERSION=$(GIT_VERSION) $(BUILD_IMAGE_NAME) yarn build

image: $(IMAGE_BUILD_MARKER)
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		--build-arg QEMU_IMAGE=$(QEMU_IMAGE) \
		-t calico/whisker:latest \
		-f docker-image/Dockerfile.nginx .

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*