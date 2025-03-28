include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/cni-plugin

# Name of the images.
# e.g., <registry>/<name>:<tag>
CNI_PLUGIN_IMAGE ?=cni
WINDOWS_IMAGE ?=cni-windows
BUILD_IMAGES   ?=$(CNI_PLUGIN_IMAGE)

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
LDFLAGS = -X main.VERSION=$(GIT_VERSION)

SRC_FILES=$(shell find pkg cmd internal -name '*.go') $(shell find ../libcalico-go -name '*.go')
TEST_SRC_FILES=$(shell find tests -name '*.go')
WINFV_SRCFILES=$(shell find win_tests -name '*.go')

# fail if unable to download
CURL=curl -C - -sSf

CNI_ARTIFACTS_URL=https://github.com/projectcalico/containernetworking-plugins/releases/download
FLANNEL_ARTIFACTS_URL=https://github.com/projectcalico/flannel-cni-plugin/releases/download

# By default set the CNI_SPEC_VERSION to 0.3.1 for tests.
CNI_SPEC_VERSION?=0.3.1

# Markers for various images we produce.
DEPLOY_CONTAINER_STATIC_MARKER=cni_deploy_container-$(ARCH).created
DEPLOY_CONTAINER_FIPS_MARKER=cni_deploy_container-$(ARCH)-fips.created

# Set FIPS to true to enable a FIPS compliant build using BoringSSL and CGO.
# Note that this produces binaries that are dynamically linked, and so have dependencies
# on the host machine.
FIPS ?= false

ifeq ($(FIPS),true)
BIN=bin/$(ARCH)-fips
DEPLOY_CONTAINER_MARKER=$(DEPLOY_CONTAINER_FIPS_MARKER)
VALIDARCHES=amd64
else
BIN=bin/$(ARCH)
DEPLOY_CONTAINER_MARKER=$(DEPLOY_CONTAINER_STATIC_MARKER)
endif

.PHONY: clean clean-windows
clean: clean-windows
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -f *.created
	rm -rf bin $(DEPLOY_CONTAINER_MARKER) pkg/install/install.test
	rm -rf config/ dist/
	-docker image rm -f $$(docker images $(CNI_PLUGIN_IMAGE) -a -q)
	rm -rf containernetworking-plugins .containernetworking-plugins-*
	rm -rf flannel-cni-plugin .flannel-cni-plugin-*

clean-windows: clean-windows-builder
	rm -rf $(WINDOWS_BIN) $(WINDOWS_DIST)

###############################################################################
# Building the binary
###############################################################################
.PHONY: build
build: $(BIN)/install $(BIN)/calico $(BIN)/calico-ipam
ifeq ($(ARCH),amd64)
# Go only supports amd64 for Windows builds.
WINDOWS_BIN=bin/windows
build: $(WINDOWS_BIN)/install.exe $(WINDOWS_BIN)/calico.exe $(WINDOWS_BIN)/calico-ipam.exe
endif

build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

## Build the Calico installation binary for the network and ipam plugins
$(BIN)/install binary: $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, $(PACKAGE_NAME)/cmd/install, $@)
else
	$(call build_binary, $(PACKAGE_NAME)/cmd/install, $@)
endif

## Build the Calico network and ipam plugins
$(BIN)/calico: $(SRC_FILES)
ifeq ($(FIPS), true)
	$(call build_cgo_boring_binary, $(PACKAGE_NAME)/cmd/calico, $@)
else
	$(call build_binary, $(PACKAGE_NAME)/cmd/calico, $@)
endif

$(BIN)/calico-ipam: $(BIN)/calico
	cp "$<" "$@"

## Build the Calico network and ipam plugins for Windows
$(WINDOWS_BIN)/install.exe: $(SRC_FILES)
	mkdir -p $(WINDOWS_BIN)
	$(call build_windows_binary, $(PACKAGE_NAME)/cmd/install, $@)

$(WINDOWS_BIN)/calico.exe: $(SRC_FILES)
	mkdir -p $(WINDOWS_BIN)
	$(call build_windows_binary, $(PACKAGE_NAME)/cmd/calico, $@)

$(WINDOWS_BIN)/calico-ipam.exe: $(WINDOWS_BIN)/calico.exe
	cp "$<" "$@"

protobuf pkg/dataplane/grpc/proto/cnibackend.pb.go: pkg/dataplane/grpc/proto/cnibackend.proto
	$(DOCKER_RUN) -v $(CURDIR)/pkg/dataplane/grpc/proto:/proto:rw \
		$(CALICO_BUILD) sh -c 'protoc --proto_path=/proto --go_out=/proto --go-grpc_out=/ --go_opt=paths=source_relative cnibackend.proto'
	$(MAKE) fix-changed

# NOTE: WINDOWS_IMAGE_REQS must be defined with the requirements to build the windows
# image. These must be added as reqs to 'image-windows' (originally defined in
# lib.Makefile) on the specific package Makefile otherwise they are not correctly
# recognized.
WINDOWS_IMAGE_REQS := Dockerfile-windows build build-win-cni-bins
image-windows: $(WINDOWS_IMAGE_REQS)

###############################################################################
# Building the image
###############################################################################
image: $(DEPLOY_CONTAINER_MARKER)
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

# Builds the statically compiled binaries into a container.
$(DEPLOY_CONTAINER_STATIC_MARKER): Dockerfile build build-cni-bins
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BIN) -t $(CNI_PLUGIN_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# Builds the FIPS binaries into a container.
$(DEPLOY_CONTAINER_FIPS_MARKER): Dockerfile build build-cni-bins
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BIN) -t $(CNI_PLUGIN_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

# These are the files that we need to copy from the containernetworking-plugins project to our image.
CN_FILES := host-local portmap loopback tuning

CONTAINERNETWORKING_PLUGINS_CLONED=.containernetworking-plugins-$(CNI_VERSION).cloned

$(CONTAINERNETWORKING_PLUGINS_CLONED):
	rm -rf containernetworking-plugins .containernetworking-plugins-*.cloned
	@$(foreach file,$(CN_FILES),find bin -name $(file) -type f -delete;)
	git clone --single-branch --branch $(CNI_VERSION) https://github.com/projectcalico/containernetworking-plugins.git
	touch $@

CN_FLAGS=-ldflags "-X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=$(GIT_VERSION)"

$(BIN)/host-local $(BIN)/loopback $(BIN)/portmap $(BIN)/tuning  &: $(CONTAINERNETWORKING_PLUGINS_CLONED)
	docker run \
		$(EXTRA_DOCKER_ARGS) \
		-v $(CURDIR)/containernetworking-plugins:/go/src/github.com/containernetworking/plugins:z \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) -w /go/src/github.com/containernetworking/plugins --rm $(CALICO_BUILD) \
		/bin/sh -xe -c ' \
			GOFLAGS='-buildvcs=false' CGO_ENABLED=0 GOARCH=$(ARCH) ./build_linux.sh $(CN_FLAGS)'
	-mkdir -p $(BIN)
	@$(foreach file,$(CN_FILES),cp containernetworking-plugins/bin/$(file) $(BIN);)

FLANNEL_CNI_PLUGIN_CLONED=.flannel-cni-plugin-$(FLANNEL_VERSION).cloned

$(FLANNEL_CNI_PLUGIN_CLONED):
	rm -rf flannel-cni-plugin .flannel-cni-plugin-*.cloned
	-rm -rf $(BIN)/flannel $(WINDOWS_BIN)/flannel.exe
	git clone --single-branch --branch $(FLANNEL_VERSION) https://github.com/projectcalico/flannel-cni-plugin.git
	touch $@

$(BIN)/flannel: $(FLANNEL_CNI_PLUGIN_CLONED)
	docker run \
		$(EXTRA_DOCKER_ARGS) \
		-v $(CURDIR)/flannel-cni-plugin:/go/src/github.com/flannel-io/cni-plugin:z \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) -w /go/src/github.com/flannel-io/cni-plugin --rm $(CALICO_BUILD) \
		/bin/sh -xe -c ' \
			ARCH=$(ARCH) VERSION=$(FLANNEL_VERSION) make build_linux'
	-mkdir -p $(BIN)
	cp flannel-cni-plugin/dist/flannel-$(ARCH) $(BIN)/flannel

$(WINDOWS_BIN)/flannel.exe: $(FLANNEL_CNI_PLUGIN_CLONED)
	docker run \
		-v $(CURDIR)/flannel-cni-plugin:/go/src/github.com/flannel-io/cni-plugin:z \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) -w /go/src/github.com/flannel-io/cni-plugin --rm $(CALICO_BUILD) \
		/bin/sh -xe -c ' \
			ARCH=$(ARCH) VERSION=$(FLANNEL_VERSION) make build_windows'
	-mkdir -p $(WINDOWS_BIN)
	cp flannel-cni-plugin/dist/flannel-$(ARCH).exe $(WINDOWS_BIN)/flannel.exe

.PHONY: build-cni-bins build-win-cni-bins
build-cni-bins: $(BIN)/flannel $(BIN)/loopback $(BIN)/host-local $(BIN)/portmap $(BIN)/tuning
build-win-cni-bins: $(WINDOWS_BIN)/flannel.exe

###############################################################################
# Unit Tests
###############################################################################
## Run the unit tests.
ut: run-k8s-controller-manager $(BIN)/install $(BIN)/host-local $(BIN)/calico-ipam $(BIN)/calico
	$(MAKE) ut-datastore DATASTORE_TYPE=etcdv3
	$(MAKE) ut-datastore DATASTORE_TYPE=kubernetes

ut-datastore:
	# The tests need to run as root
	docker run --rm -t --privileged --net=host \
	$(EXTRA_DOCKER_ARGS) \
	-e ETCD_IP=$(LOCAL_IP_ENV) \
	-e RUN_AS_ROOT=true \
	-e ARCH=$(ARCH) \
	-e PLUGIN=calico \
	-e BIN=/go/src/$(PACKAGE_NAME)/$(BIN) \
	-e CNI_SPEC_VERSION=$(CNI_SPEC_VERSION) \
	-e DATASTORE_TYPE=$(DATASTORE_TYPE) \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	-e KUBECONFIG=/home/user/certs/kubeconfig \
	-v $(CURDIR)/../:/go/src/github.com/projectcalico/calico:rw \
	-v $(CERTS_PATH):/home/user/certs \
	$(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
			cd  /go/src/$(PACKAGE_NAME) && \
			ginkgo -cover -r -skipPackage pkg/install,containernetworking-plugins,flannel-cni-plugin $(GINKGO_ARGS)'

ut-etcd: run-k8s-controller-manager build $(BIN)/host-local
	$(MAKE) ut-datastore DATASTORE_TYPE=etcdv3
	make stop-etcd
	make stop-k8s-controller

ut-kdd: run-k8s-controller-manager build $(BIN)/host-local
	$(MAKE) ut-datastore DATASTORE_TYPE=kubernetes
	make stop-etcd
	make stop-k8s-controller

## Run the tests in a container (as root) for different CNI spec versions
## to make sure we don't break backwards compatibility.
.PHONY: test-cni-versions
test-cni-versions:
	for cniversion in "0.2.0" "0.3.1" ; do \
		if make ut CNI_SPEC_VERSION=$$cniversion; then \
			echo "CNI version $$cniversion PASSED"; \
		else \
			echo "CNI version $$cniversion FAILED"; \
			exit 1; \
		fi; \
	done

###############################################################################
# Install test
###############################################################################
# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
pkg/install/install.test: pkg/install/*.go
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
			cd /go/src/$(PACKAGE_NAME) && \
			go test ./pkg/install -c --tags install_test -o ./pkg/install/install.test'

.PHONY: test-install-cni
## Test the install
test-install-cni: run-k8s-apiserver image pkg/install/install.test
	cd pkg/install && CONTAINER_NAME=$(CNI_PLUGIN_IMAGE):latest-$(ARCH) CERTS_PATH=$(CERTS_PATH) ./install.test

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: clean mod-download build static-checks test-cni-versions image-all test-install-cni

## Deploys images to registry
cd: image-all cd-common

## Build fv binary for Windows
$(WINDOWS_BIN)/win-fv.exe: $(WINFV_SRCFILES)
	$(DOCKER_RUN) -e GOOS=windows $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./win_tests -c -o $(WINDOWS_BIN)/win-fv.exe'

###############################################################################
# Release
###############################################################################
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)-fips LATEST_IMAGE_TAG=latest-fips
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

	# Push Windows images.
	$(MAKE) release-windows IMAGETAG=$(VERSION) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run $(CNI_PLUGIN_IMAGE):latest-$(ARCH) calico -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(CNI_PLUGIN_IMAGE):latest-$(ARCH) calico -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(CNI_PLUGIN_IMAGE):latest-$(ARCH) calico -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(CNI_PLUGIN_IMAGE):latest-$(ARCH) calico -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push-images-to-registries push-manifests RELEASE=true IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

	# Push Windows images.
	$(MAKE) release-windows IMAGETAG=latest CONFIRM=$(CONFIRM)

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: test-watch
## Run the unit tests, watching for changes.
test-watch: $(BIN)/install run-etcd run-k8s-apiserver
	# The tests need to run as root
	CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo) watch -skipPackage pkg/install
