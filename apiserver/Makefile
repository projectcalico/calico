include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/apiserver
LOCAL_CHECKS     = lint-cache-dir goimports check-boring-ssl

# Used so semaphore commits generated files when pins are updated
EXTRA_FILES_TO_COMMIT=*_generated.go *_generated.*.go

# Name of the images.
# e.g., <registry>/<name>:<tag>
API_SERVER_IMAGE      ?=apiserver
BUILD_IMAGES          ?=$(API_SERVER_IMAGE)

EXTRA_DOCKER_ARGS += -e GOLANGCI_LINT_CACHE=/lint-cache -v $(CURDIR)/.lint-cache:/lint-cache:rw \
				 -v $(CURDIR)/hack/boilerplate:/go/src/k8s.io/kubernetes/hack/boilerplate:rw

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

APISERVER_VERSION?=$(shell git describe --tags --dirty --always --abbrev=12)
APISERVER_BUILD_DATE?=$(shell date -u +'%FT%T%z')
APISERVER_GIT_REVISION?=$(shell git rev-parse --short HEAD)
APISERVER_GIT_DESCRIPTION?=$(shell git describe --tags)

VERSION_FLAGS = -X $(PACKAGE_NAME)/cmd/apiserver/server.VERSION=$(APISERVER_VERSION) \
	-X $(PACKAGE_NAME)/cmd/apiserver/server.BUILD_DATE=$(APISERVER_BUILD_DATE) \
	-X $(PACKAGE_NAME)/cmd/apiserver/server.GIT_DESCRIPTION=$(APISERVER_GIT_DESCRIPTION) \
	-X $(PACKAGE_NAME)/cmd/apiserver/server.GIT_REVISION=$(APISERVER_GIT_REVISION)

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################

include ../lib.Makefile

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
else
CGO_ENABLED=0
endif

ifeq ($(ARCH),arm64)
# Forces ARM64 build image to be used in a crosscompilation run.
CALICO_BUILD:=$(CALICO_BUILD)-$(ARCH)
endif

###############################################################################
# Static checks
###############################################################################
## Perform static checks on the code.
# TODO: re-enable these linters !
LINT_ARGS := --disable gosimple,govet,structcheck,errcheck,goimports,unused,ineffassign,staticcheck,deadcode,typecheck --timeout 5m

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks image-all fv ut

## Deploys images to registry
cd: image-all cd-common

# This section builds the output binaries.
# Some will have dedicated targets to make it easier to type, for example
# "apiserver" instead of "$(BINDIR)/apiserver".
#########################################################################
$(BINDIR)/apiserver-$(ARCH): $(K8SAPISERVER_GO_FILES)
	mkdir -p $(BINDIR)
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -v -o $@ -ldflags "$(VERSION_FLAGS)" $(PACKAGE_NAME)/cmd/apiserver'

$(BINDIR)/filecheck-$(ARCH): $(K8SAPISERVER_GO_FILES)
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -v -o $@ -ldflags "$(VERSION_FLAGS)" $(PACKAGE_NAME)/cmd/filecheck'

###############################################################################
# Building the image
###############################################################################
build: image

CONTAINER_CREATED=.apiserver.created-$(ARCH)
.PHONY: image $(API_SERVER_IMAGE)
image: $(API_SERVER_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(API_SERVER_IMAGE): register $(CONTAINER_CREATED)
$(CONTAINER_CREATED): docker-image/Dockerfile.$(ARCH) $(BINDIR)/apiserver-$(ARCH) $(BINDIR)/filecheck-$(ARCH)
ifeq ($(ARCH),s390x)
	$(DOCKER_BUILD) -t $(API_SERVER_IMAGE):latest-$(ARCH) -f docker-image/Dockerfile.$(ARCH) .
else
	$(DOCKER_BUILD) -t $(API_SERVER_IMAGE):latest-$(ARCH) -f docker-image/Dockerfile.$(ARCH) . --load
endif
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

.PHONY: lint-cache-dir
lint-cache-dir:
	mkdir -p $(CURDIR)/.lint-cache

check-boring-ssl: $(BINDIR)/apiserver-$(ARCH)
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		go tool nm $(BINDIR)/apiserver-$(ARCH) > $(BINDIR)/tags.txt && grep '_Cfunc__goboringcrypto_' $(BINDIR)/tags.txt 1> /dev/null
	-rm -f $(BINDIR)/tags.txt

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
	@hack/check-copyright.sh

GITHUB_TEST_INTEGRATION_URI := https://raw.githubusercontent.com/kubernetes/kubernetes/v1.16.4/hack/lib

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
	#Create a Node in the API for the tests to use.
	docker run \
		--net=host \
		--rm \
		-v  $(CURDIR):/manifests \
		-v $(CERTS_PATH):/home/user/certs \
		lachlanevenson/k8s-kubectl:${KUBECTL_VERSION} \
		--kubeconfig=/home/user/certs/kubeconfig \
		apply -f /manifests/test/mock-node.yaml

	# Create Namespaces required by namespaced Calico `NetworkPolicy`
	# tests from the manifests namespaces.yaml.
	docker run \
		--net=host \
		--rm \
		-v  $(CURDIR):/manifests \
		-v $(CERTS_PATH):/home/user/certs \
		lachlanevenson/k8s-kubectl:${KUBECTL_VERSION} \
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

clean-bin:
	rm -rf $(BINDIR) \
	    docker-image/bin

clean-hack-lib:
	rm -rf hack/lib/

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
	touch $@

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run calico/apiserver | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run calico/apiserver` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
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
