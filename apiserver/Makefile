include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/apiserver
LOCAL_CHECKS     = lint-cache-dir

# Used so semaphore commits generated files when pins are updated
EXTRA_FILES_TO_COMMIT=*_generated.go *_generated.*.go

# Name of the images.
# e.g., <registry>/<name>:<tag>
API_SERVER_IMAGE      ?=apiserver
BUILD_IMAGES          ?=$(API_SERVER_IMAGE)

EXTRA_DOCKER_ARGS += -v $(CURDIR)/../hack/boilerplate:/go/src/k8s.io/kubernetes/hack/boilerplate:rw

###############################################################################
BINDIR ?= bin
BUILD_DIR ?= build

TOP_SRC_DIRS = pkg cmd
SRC_DIRS = $(shell sh -c "find $(TOP_SRC_DIRS) -name \\*.go \
                   -exec dirname {} \\; | sort | uniq")
TEST_DIRS ?= $(shell sh -c "find $(TOP_SRC_DIRS) -name \\*_test.go \
                    -exec dirname {} \\; | sort | uniq")

ifeq ($(shell uname -s),Darwin)
	STAT = stat -f '%c %N'
else
	STAT = stat -c '%Y %n'
endif

K8SAPISERVER_GO_FILES = $(shell find $(SRC_DIRS) -name \*.go -exec $(STAT) {} \; \
                   | sort -r | head -n 1 | sed "s/.* //")

ifdef UNIT_TESTS
UNIT_TEST_FLAGS = -run $(UNIT_TESTS) -v
endif

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################

include ../lib.Makefile

FIPS ?= false

ifeq ($(FIPS),true)
CONTAINER_MARKER=$(CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
else
CONTAINER_MARKER=$(CONTAINER_CREATED)
BINDIR=bin
endif

###############################################################################
# This section builds the output binaries.
# Some will have dedicated targets to make it easier to type, for example
# "apiserver" instead of "$(BINDIR)/apiserver".
###############################################################################
$(BINDIR)/apiserver-$(ARCH): $(K8SAPISERVER_GO_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, $(PACKAGE_NAME)/cmd/apiserver, $@)
else
	$(call build_binary, $(PACKAGE_NAME)/cmd/apiserver, $@)
endif

###############################################################################
# Building the image
###############################################################################
.PHONY: build
build: $(BINDIR)/apiserver-$(ARCH)

bin/LICENSE: ../LICENSE.md
	cp ../LICENSE.md $@

CONTAINER_CREATED=.apiserver.created-$(ARCH)
CONTAINER_FIPS_CREATED=.apiserver.created-$(ARCH)-fips

.PHONY: image $(API_SERVER_IMAGE)
image: $(API_SERVER_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

$(API_SERVER_IMAGE): $(CONTAINER_MARKER)
$(CONTAINER_CREATED): Dockerfile $(BINDIR)/apiserver-$(ARCH) bin/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(API_SERVER_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(CONTAINER_FIPS_CREATED): Dockerfile $(BINDIR)/apiserver-$(ARCH) bin/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(API_SERVER_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(MAKE) FIPS=true retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

.PHONY: lint-cache-dir
lint-cache-dir:
	mkdir -p $(CURDIR)/.lint-cache

.PHONY: ut
ut: lint-cache-dir run-etcd
	$(DOCKER_RUN) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) ETCD_ENDPOINTS="http://127.0.0.1:2379" DATASTORE_TYPE="etcdv3" go test $(UNIT_TEST_FLAGS) \
			$(addprefix $(PACKAGE_NAME)/,$(TEST_DIRS))'

.PHONY: st
st:
	@echo "Nothing to do for $@"

.PHONY: check-copyright
check-copyright:
	@../hack/check-copyright.sh

GITHUB_TEST_INTEGRATION_URI := https://raw.githubusercontent.com/kubernetes/kubernetes/$(K8S_VERSION)/hack/lib

hack-lib:
	mkdir -p hack/lib/
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/init.sh -o hack/lib/init.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/util.sh -o hack/lib/util.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/logging.sh -o hack/lib/logging.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/version.sh -o hack/lib/version.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/golang.sh -o hack/lib/golang.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/etcd.sh -o hack/lib/etcd.sh

## Run a local kubernetes server with API in a container.
run-kubernetes-server: run-k8s-controller-manager
	# Create a Node in the API for the tests to use.
	docker run \
		--net=host \
		--rm \
		-v  $(CURDIR):/manifests \
		-v $(CERTS_PATH):/home/user/certs \
		rancher/kubectl:$(K8S_VERSION) \
		--kubeconfig=/home/user/certs/kubeconfig \
		apply -f /manifests/test/mock-node.yaml

	# Create Namespaces required by namespaced Calico `NetworkPolicy`
	# tests from the manifests namespaces.yaml.
	docker run \
		--net=host \
		--rm \
		-v  $(CURDIR):/manifests \
		-v $(CERTS_PATH):/home/user/certs \
		rancher/kubectl:$(K8S_VERSION) \
		--kubeconfig=/home/user/certs/kubeconfig \
		apply -f /manifests/test/namespaces.yaml

## Stop the local kubernetes server
stop-kubernetes-server: stop-k8s-controller-manager

# TODO(doublek): Add fv-etcd back to fv. It is currently disabled because profiles behavior is broken.
# Profiles should be disallowed from being created for both etcd and kdd mode. However we are allowing
# profiles to be created in etcd and disallow in kdd. This has the test incorrect for etcd and running
# for kdd.
.PHONY: fv
fv: fv-kdd

.PHONY: fv-etcd
fv-etcd: run-kubernetes-server hack-lib
	$(DOCKER_RUN) \
		-v $(CERTS_PATH):/home/user/certs \
		-e KUBECONFIG=/home/user/certs/kubeconfig \
		$(CALICO_BUILD) \
		sh -c 'ETCD_ENDPOINTS="http://127.0.0.1:2379" DATASTORE_TYPE="etcdv3" test/integration.sh'

.PHONY: fv-kdd
fv-kdd: run-kubernetes-server hack-lib
	$(DOCKER_RUN) \
		-v $(CERTS_PATH):/home/user/certs \
		-e KUBECONFIG=/home/user/certs/kubeconfig \
		$(CALICO_BUILD) \
		sh -c 'DATASTORE_TYPE="kubernetes" test/integration.sh'

.PHONY: clean
clean: clean-bin clean-hack-lib
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf .lint-cache
	-docker image rm -f $$(docker images $(API_SERVER_IMAGE) -a -q)

clean-bin:
	rm -rf $(BINDIR) \
	    docker-image/bin

clean-hack-lib:
	rm -rf hack/lib/

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks image ut fv

## Deploys images to registry
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	$(MAKE) FIPS=true retag-build-images-with-registries IMAGETAG=$(VERSION)-fips RELEASE=true LATEST_IMAGE_TAG=latest-fips
	$(MAKE) FIPS=true retag-build-images-with-registries IMAGETAG=latest-fips RELEASE=true LATEST_IMAGE_TAG=latest-fips
	touch $@

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

###############################################################################
# Utils
###############################################################################
# this is not a linked target, available for convenience.
.PHONY: tidy
## 'tidy' mods.
tidy:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go mod tidy'
