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

# register is order-only (|) so binfmt setup doesn't trigger unnecessary rebuilds.
$(IMAGE_BUILD_MARKER): build bin/LICENSE | register
	$(DOCKER_BUILD) --build-arg BIN_DIR=bin -t whisker:latest-$(ARCH) -f docker-image/Dockerfile .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(BUILD_IMAGES) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

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

###############################################################################
# Browser-level tests (see e2e/README.md)
#
#   make e2e                on the host, for the dev loop
#   make e2e-ci             in the pinned Playwright container, as CI does
#   make e2e-snapshots-ci   regenerate the Linux screenshot baselines
#
# These do not go through DOCKER_RUN_RM: Playwright needs a browser plus its
# system libraries, which the node build image does not carry and cannot install
# as the invoking, non-root user. The Playwright image ships both.
###############################################################################

.PHONY: e2e e2e-install e2e-ci e2e-snapshots-ci
e2e-install:
	yarn install
	yarn e2e:install

e2e: e2e-install
	yarn e2e

# Kept in step with the pinned @playwright/test: the image carries only the
# browser build matching its own version, and Playwright refuses to launch
# against a mismatched one.
E2E_PLAYWRIGHT_VERSION := $(shell sed -n 's/.*"@playwright\/test": *"[^0-9]*\([0-9.]*\)".*/\1/p' package.json)
E2E_IMAGE ?= mcr.microsoft.com/playwright:v$(E2E_PLAYWRIGHT_VERSION)-noble

# node_modules lives in a named volume rather than the bind mount, so a laptop's
# darwin install is not clobbered by the container's linux one (and vice versa).
# The container runs as root -- the image's default, and the only way to write to
# a freshly created named volume -- so whatever it leaves in the repo is handed
# back to the caller before it exits.
E2E_OWNER := $(shell id -u):$(shell id -g)

# Semaphore agents are x86_64, and baselines are per-architecture, so the default
# targets amd64 even on an arm64 laptop (emulated, hence slower). Override with
# E2E_PLATFORM=linux/arm64 for a faster native run when you only want to iterate
# -- but the amd64 set is the one CI compares against.
E2E_PLATFORM ?= linux/amd64

E2E_DOCKER_RUN = docker run --rm \
	--platform $(E2E_PLATFORM) \
	-v $${PWD}:/code \
	-v whisker-e2e-node-modules:/code/node_modules \
	-w /code \
	-e HOME=/tmp \
	-e YARN_CACHE_FOLDER=/tmp/.yarn \
	-e CI=true \
	$(E2E_IMAGE) sh -c

# $(1) is the yarn script to run inside the container.
define e2e_in_container
	$(E2E_DOCKER_RUN) 'set -e; \
		corepack enable || npm i -g yarn@1.22.22; \
		yarn install --frozen-lockfile; \
		set +e; \
		yarn $(1); \
		status=$$?; \
		chown -R $(E2E_OWNER) e2e e2e-results e2e-report 2>/dev/null; \
		exit $$status'
endef

e2e-ci:
	$(call e2e_in_container,e2e); status=$$?; $(MAKE) e2e-stage-artifacts; exit $$status

# Regenerates the Linux baselines, which have to be committed: font
# rasterisation differs between macOS and Linux, so a laptop-generated PNG will
# not match in CI. Also staged as a job artifact, so the set can be produced by
# a CI run and downloaded rather than needing Docker locally.
e2e-snapshots-ci:
	$(call e2e_in_container,e2e:snapshots); status=$$?; $(MAKE) e2e-stage-artifacts; exit $$status

# Semaphore's epilogue publishes everything under <repo>/artifacts, so copying
# traces, diff images and baselines there makes them downloadable from the job.
# A no-op outside CI, where that directory does not exist.
.PHONY: e2e-stage-artifacts
e2e-stage-artifacts:
	@if [ -d ../artifacts ]; then \
		mkdir -p ../artifacts/whisker-e2e; \
		cp -R e2e-results ../artifacts/whisker-e2e/ 2>/dev/null || true; \
		cp -R e2e-report ../artifacts/whisker-e2e/ 2>/dev/null || true; \
		cp -R e2e/tests/__screenshots__ ../artifacts/whisker-e2e/ 2>/dev/null || true; \
		echo "staged whisker e2e artifacts"; \
	fi

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
