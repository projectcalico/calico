include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/cni-plugin

# The Linux cni-plugin is bundled into the calico/calico image. Only the
# Windows image is built standalone from this component.
WINDOWS_IMAGE ?= cni-windows
BUILD_IMAGES  ?= $(WINDOWS_IMAGE)

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.
WINFV_SRCFILES=$(shell find win_tests -name '*.go')

# fail if unable to download
CURL=curl -C - -sSf

CNI_ARTIFACTS_URL=https://github.com/projectcalico/containernetworking-plugins/releases/download
FLANNEL_ARTIFACTS_URL=https://github.com/projectcalico/flannel-cni-plugin/releases/download

# By default set the CNI_SPEC_VERSION to 0.3.1 for tests.
CNI_SPEC_VERSION?=0.3.1

BIN=bin/$(ARCH)

.PHONY: clean clean-windows
clean: clean-windows
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -f *.created
	rm -rf bin pkg/install/install.test
	rm -rf config/ dist/
	rm -rf containernetworking-plugins .containernetworking-plugins-*
	rm -rf flannel-cni-plugin .flannel-cni-plugin-*

clean-windows: clean-windows-builder
	rm -rf $(WINDOWS_BIN) $(WINDOWS_DIST)

###############################################################################
# Building the binary
###############################################################################
# Only the Windows image is built standalone here; Linux ships in calico/calico.
.PHONY: build
build:
ifeq ($(ARCH),amd64)
# Go only supports amd64 for Windows builds.
WINDOWS_BIN=bin/windows
# calico-ipam.exe is not built: install.exe copies calico.exe to both names on the host.
build: $(WINDOWS_BIN)/install.exe $(WINDOWS_BIN)/calico.exe
endif

## Build the Calico network and ipam plugins for Windows
$(WINDOWS_BIN)/install.exe: $(SRC_FILES)
	mkdir -p $(WINDOWS_BIN)
	$(call build_windows_binary, $(PACKAGE_NAME)/cmd/install, $@)

$(WINDOWS_BIN)/calico.exe: $(SRC_FILES)
	mkdir -p $(WINDOWS_BIN)
	$(call build_windows_binary, $(PACKAGE_NAME)/cmd/calico, $@)

protobuf pkg/dataplane/grpc/proto/cnibackend.pb.go: pkg/dataplane/grpc/proto/cnibackend.proto
	$(DOCKER_RUN) -v $(CURDIR)/pkg/dataplane/grpc/proto:/proto:rw \
		$(CALICO_BUILD) sh -c 'protoc --proto_path=/proto --go_out=/proto --go-grpc_out=/ --go_opt=paths=source_relative cnibackend.proto'
	$(MAKE) fix-changed

# NOTE: WINDOWS_IMAGE_REQS must be defined with the requirements to build the windows
# image. These must be added as reqs to 'image-windows' (originally defined in
# lib.Makefile) on the specific package Makefile otherwise they are not correctly
# recognized.
WINDOWS_IMAGE_REQS := Dockerfile-windows build build-win-cni-bins bin/LICENSE
image-windows: $(WINDOWS_IMAGE_REQS)

bin/LICENSE: ../LICENSE.md
	cp ../LICENSE.md bin/LICENSE

###############################################################################
# Supplementary CNI binaries required by unit tests and the Windows image.
###############################################################################
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

fv:
	@echo "No FV tests for CNI plugin"


## Install KubeVirt CRDs for testing (without operator/controllers)
.PHONY: install-kubevirt-crds
install-kubevirt-crds:
	@echo "Installing KubeVirt CRDs for testing..."
	@while ! docker exec calico-local-apiserver kubectl \
		apply -f /go/src/github.com/projectcalico/calico/cni-plugin/tests/kubevirt-test-crds.yaml; \
		do echo "Waiting to install KubeVirt CRDs..."; \
		sleep 1; \
		done
	@echo "KubeVirt CRDs installed successfully"

## Remove KubeVirt CRDs
.PHONY: remove-kubevirt-crds
remove-kubevirt-crds:
	@echo "Removing KubeVirt CRDs..."
	@docker exec calico-local-apiserver kubectl \
		delete -f /go/src/github.com/projectcalico/calico/cni-plugin/tests/kubevirt-test-crds.yaml 2>/dev/null || \
		echo "KubeVirt CRDs already removed or not present"


# Source the CNI plugin and IPAM binaries from the combined calico binary;
# argv[0] dispatch in cmd/calico/main.go picks the right entry point.
COMBINED_BINARY = $(REPO_ROOT)/cmd/calico/bin/calico-$(ARCH)

$(COMBINED_BINARY): $(call local-deps-go-files,cmd)
	$(MAKE) -C $(REPO_ROOT)/cmd/calico build

$(BIN)/calico: $(COMBINED_BINARY)
	mkdir -p $(BIN)
	cp $< $@

$(BIN)/calico-ipam: $(BIN)/calico
	ln -sf ./calico $@

UT_PREREQS = run-k8s-controller-manager $(BIN)/host-local $(BIN)/calico $(BIN)/calico-ipam

## Run all unit tests.
ut: $(UT_PREREQS)
	$(MAKE) ut-etcd
	$(MAKE) ut-kdd
	$(MAKE) ut-kubevirt

## Run unit tests against etcdv3 with CNI spec 0.3.1.
ut-etcd: $(UT_PREREQS)
	$(MAKE) ut-datastore DATASTORE_TYPE=etcdv3 CNI_SPEC_VERSION=0.3.1 JUNIT_REPORT_NAME=cni_plugin_ut_etcd.xml

## Run unit tests against KDD with CNI spec 1.0.0 (excludes KubeVirt tests).
ut-kdd: $(UT_PREREQS)
	$(MAKE) remove-kubevirt-crds
	$(MAKE) ut-datastore DATASTORE_TYPE=kubernetes CNI_SPEC_VERSION=1.0.0 JUNIT_REPORT_NAME=cni_plugin_ut_kdd.xml GINKGO_ARGS='--label-filter=!KubeVirt $(GINKGO_ARGS)'

## Run KubeVirt-specific unit tests against KDD with CNI spec 1.0.0.
ut-kubevirt: $(UT_PREREQS)
	$(MAKE) install-kubevirt-crds
	$(MAKE) ut-datastore DATASTORE_TYPE=kubernetes CNI_SPEC_VERSION=1.0.0 JUNIT_REPORT_NAME=cni_plugin_ut_kubevirt.xml GINKGO_ARGS='--label-filter=KubeVirt $(GINKGO_ARGS)'

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
	-e CALICO_API_GROUP=$(CALICO_API_GROUP) \
	-e KUBECONFIG=/home/user/certs/kubeconfig \
	-v $(CURDIR)/../:/go/src/github.com/projectcalico/calico:rw \
	-v $(CERTS_PATH):/home/user/certs \
	$(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
			cd  /go/src/$(PACKAGE_NAME) && \
			mkdir -p report && \
			ginkgo -cover -r --junit-report=$(JUNIT_REPORT_NAME) --output-dir=report/ -skip-package pkg/install,containernetworking-plugins,flannel-cni-plugin $(GINKGO_ARGS)'

###############################################################################
# Install test
###############################################################################
# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
pkg/install/install.test: pkg/install/*.go
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
			cd /go/src/$(PACKAGE_NAME) && \
			go test ./pkg/install -c --tags install_test -o ./pkg/install/install.test'

.PHONY: test-install-cni test-install-cni-prereqs test-install-cni-no-prereqs
## Test the install
# Uses the combined calico/calico image (loaded from the calico-image prerequisite
# job in CI, or built locally via the marker rule in lib.Makefile). The test
# invokes `calico component cni install` instead of the legacy
# `/opt/cni/bin/install`. CI invokes the *-no-prereqs target directly so a
# missing cached image fails loudly rather than triggering a silent rebuild.
test-install-cni: test-install-cni-prereqs
	$(MAKE) test-install-cni-no-prereqs

test-install-cni-prereqs: $(REPO_ROOT)/cmd/calico/.image.created-$(ARCH)

test-install-cni-no-prereqs: run-k8s-apiserver pkg/install/install.test
	cd pkg/install && CONTAINER_NAME=calico/calico:latest-$(ARCH) CERTS_PATH=$(CERTS_PATH) ./install.test

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci ci-no-prereqs
ci: clean mod-download build static-checks ut test-install-cni

# CI entry point: skips the calico image rebuild and runs the full test suite.
# The image must be preloaded from the GCS cache.
ci-no-prereqs: mod-download build static-checks ut test-install-cni-no-prereqs

## Build fv binary for Windows
$(WINDOWS_BIN)/win-fv.exe: $(WINFV_SRCFILES)
	$(DOCKER_RUN) -e GOOS=windows $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go test ./win_tests -c -o $(WINDOWS_BIN)/win-fv.exe'

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: test-watch
## Run the unit tests, watching for changes.
test-watch: run-etcd run-k8s-apiserver
	# The tests need to run as root
	CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) ginkgo watch -skip-package pkg/install
