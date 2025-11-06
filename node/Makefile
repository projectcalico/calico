include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/node

# Name of the images.
# e.g., <registry>/<name>:<tag>
NODE_IMAGE            ?=node
WINDOWS_IMAGE         ?=$(NODE_IMAGE)-windows

# We don't include the windows images here because we build them differently
# using targets within this makefile.
BUILD_IMAGES ?=$(NODE_IMAGE)

# Paths within the build container for BPF source.
LIBBPF_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/libbpf/src/
BPFGPL_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/
LIBBPF_FILE_CREATED=../felix/bpf-gpl/.libbpf-$(LIBBPF_VERSION)

LOCAL_CHECKS = LIBBPF_FILE_CREATED

# Paths within the repository for BPF source.
LIBBPF_A=../felix/bpf-gpl/libbpf/src/$(ARCH)/libbpf.a


# Complete list of files from other directories that we need to build calico/node.
REMOTE_DEPS = $(LIBBPF_A) \
	      filesystem/usr/lib/calico/bpf \
	      filesystem/etc/calico/confd/conf.d \
	      filesystem/etc/calico/confd/templates

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

FIPS ?= false

ifeq ($(FIPS),true)
NODE_CONTAINER_BIN_DIR=./dist/bin/$(ARCH)-fips
NODE_CONTAINER_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node-$(ARCH)
NODE_CONTAINER_MARKER=$(NODE_CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
else
NODE_CONTAINER_BIN_DIR=dist/bin
NODE_CONTAINER_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node-$(ARCH)
NODE_CONTAINER_MARKER=$(NODE_CONTAINER_CREATED)
endif

# Set the platform correctly for building docker images.
ifeq ($(ARCH),arm64)
# Required for eBPF support in ARM64.
# We need to force ARM64 build image to be used in a crosscompilation run.
CALICO_BUILD:=$(CALICO_BUILD)-$(ARCH)
endif

###############################################################################

# Our (public) GCP bucket where we mirror any third party files
# that are flaky to retrieve.
THIRD_PARTY_DEPS_MIRROR=https://storage.googleapis.com/public-calico-third-party-deps

# Versions and location of dependencies used in the build.
BIRD_IMAGE ?= calico/bird:$(BIRD_VERSION)-$(ARCH)
BIRD_SOURCE=filesystem/included-source/bird-$(BIRD_VERSION).tar.gz
FELIX_GPL_SOURCE=filesystem/included-source/felix-ebpf-gpl.tar.xz
INCLUDED_SOURCE=$(BIRD_SOURCE) $(FELIX_GPL_SOURCE)

# Versions and locations of dependencies used in tests.
TEST_CONTAINER_NAME_VER?=latest
TEST_CONTAINER_NAME?=calico/test:$(TEST_CONTAINER_NAME_VER)-$(ARCH)

TEST_CONTAINER_FILES=$(shell find tests/ -type f ! -name '*.created')

# Variables controlling the image
NODE_CONTAINER_CREATED=.calico_node.created-$(ARCH)
NODE_CONTAINER_FIPS_CREATED=.calico_node.created-$(ARCH)-fips
WINDOWS_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node.exe
TOOLS_MOUNTNS_BINARY = $(NODE_CONTAINER_BIN_DIR)/mountns-$(ARCH)

WINDOWS_INSTALL_SCRIPT := dist/install-calico-windows.ps1

# Variables for the Windows packaging.
# Name of the Windows release ZIP archive.
WINDOWS_PACKAGING_ROOT := windows-packaging
WINDOWS_ARCHIVE_ROOT := windows-packaging/CalicoWindows
WINDOWS_ARCHIVE_BINARY := $(WINDOWS_ARCHIVE_ROOT)/calico-node.exe
WINDOWS_ARCHIVE_TAG?=$(GIT_VERSION)
WINDOWS_ARCHIVE := dist/calico-windows-$(WINDOWS_ARCHIVE_TAG).zip
# Version of NSSM to download.
WINDOWS_NSSM_VERSION=2.24-103-gdee49fc
# Original source: https://nssm.cc/ci/nssm-$(WINDOWS_NSSM_VERSION).zip
WINDOWS_NSSM_URL=$(THIRD_PARTY_DEPS_MIRROR)/nssm/nssm-$(WINDOWS_NSSM_VERSION).zip
# Explicit list of files that we copy in from the mod cache.  This is required because the copying rules we use are pattern-based
# and they only work with an explicit rule of the form "$(WINDOWS_MOD_CACHED_FILES): <file path from project root>" (otherwise,
# make has no way to know that the mod cache target produces the files we need).
WINDOWS_MOD_CACHED_FILES := \
    windows-packaging/config-bgp.ps1 \
    windows-packaging/config-bgp.psm1 \
    windows-packaging/conf.d/blocks.toml \
    windows-packaging/conf.d/peerings.toml \
    windows-packaging/templates/blocks.ps1.template \
    windows-packaging/templates/peerings.ps1.template

# Files to include in the Windows ZIP archive.  We need to list some of these explicitly
# because we need to force them to be built/copied into place. We also have
# tests in windows-packaging that we don't want to include.
WINDOWS_ARCHIVE_FILES := \
    $(WINDOWS_ARCHIVE_BINARY) \
    $(WINDOWS_ARCHIVE_ROOT)/README.txt \
    $(WINDOWS_ARCHIVE_ROOT)/*.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/node/node-service.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/felix/felix-service.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/confd-service.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.ps1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.psm1 \
    $(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/blocks.toml \
    $(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/peerings.toml \
    $(WINDOWS_ARCHIVE_ROOT)/confd/templates/blocks.ps1.template \
    $(WINDOWS_ARCHIVE_ROOT)/confd/templates/peerings.ps1.template \
    $(WINDOWS_ARCHIVE_ROOT)/cni/calico.exe \
    $(WINDOWS_ARCHIVE_ROOT)/cni/calico-ipam.exe \
    $(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1 \
    $(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt \
    $(WINDOWS_ARCHIVE_ROOT)/libs/calico/calico.psm1

MICROSOFT_SDN_VERSION := 0d7593e5c8d4c2347079a7a6dbd9eb034ae19a44
MICROSOFT_SDN_GITHUB_RAW_URL := https://raw.githubusercontent.com/microsoft/SDN/$(MICROSOFT_SDN_VERSION)

# Variables used by the tests
ST_TO_RUN?=tests/st/
K8ST_TO_RUN?=tests/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

K8ST_REPORT_FILENAME ?= k8s-tests.xml

# Filesystem of the node container that is checked in to this repository.
NODE_CONTAINER_FILES=$(shell find ./filesystem -type f)

# Calculate a timestamp for any build artefacts.
DATE:=$(shell date -u +'%FT%T%z')

# Source golang files on which compiling the calico-node binary depends.
SRC_FILES=$(shell find ./pkg -name '*.go') \
	  $(shell find ./cmd -name '*.go') \
	  $(shell find ../felix -name '*.go') \
	  $(shell find ../app-policy -name '*.go') \
	  $(shell find ../typha -name '*.go') \
	  $(shell find ../felix -name '*.[ch]') \
	  $(shell find ../libcalico-go -name '*.go') \
	  $(shell find ../goldmane -name '*.go') \
	  $(shell find ../confd -name '*.go')

## Clean enough that a new release build will be clean
clean: clean-windows
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf certs *.tar $(NODE_CONTAINER_BIN_DIR)
	rm -rf $(REMOTE_DEPS)
	rm -rf filesystem/included-source
	rm -rf tests/k8st/infra/operator
	rm -rf dist
	rm -rf bin
	# We build these as part of the node build, so clean them as part of the clean.
	make -C ../felix clean
	# Delete images that we built in this repo
	-docker image rm -f $$(docker images $(NODE_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(NODE_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(TEST_CONTAINER_NAME) -a -q)

clean-windows: clean-windows-builder
	rm -f $(WINDOWS_ARCHIVE) $(WINDOWS_ARCHIVE_BINARY) $(WINDOWS_BINARY)
	rm -f $(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1
	rm -f $(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt
	rm -f $(WINDOWS_ARCHIVE_ROOT)/cni/*.exe
	rm -f $(WINDOWS_ARCHIVE_ROOT)/../nssm.zip
	rm -f $(WINDOWS_ARCHIVE_ROOT)/../nssm.exe
	rm -f $(WINDOWS_INSTALL_SCRIPT)
	rm -rf "$(WINDOWS_DIST)"
	-docker image rm -f $$(docker images $(WINDOWS_IMAGE) -a -q)

###############################################################################
# Building the binary
###############################################################################
build: $(NODE_CONTAINER_MARKER) $(TOOLS_MOUNTNS_BINARY)

# Pull in config from confd.
filesystem/etc/calico/confd/conf.d: $(shell find ../confd/etc/calico/confd/conf.d -type f)
	rm -rf $@ && cp -r ../confd/etc/calico/confd/conf.d $@
	chmod +w $@

filesystem/etc/calico/confd/templates: $(shell find ../confd/etc/calico/confd/templates -type f)
	rm -rf $@ && cp -r ../confd/etc/calico/confd/templates $@
	chmod +w $@

$(LIBBPF_A): $(shell find ../felix/bpf-gpl/libbpf -type f -name '*.[ch]')
	make -C ../felix libbpf ARCH=$(ARCH)

filesystem/usr/lib/calico/bpf: $(shell find ../felix/bpf-gpl -type f) $(shell find ../felix/bpf-apache -type f)
	rm -rf filesystem/usr/lib/calico/bpf/ && mkdir -p filesystem/usr/lib/calico/bpf/
	make -C ../felix build-bpf ARCH=$(ARCH)
	cp -r ../felix/bpf-gpl/bin/* $@
	cp -r ../felix/bpf-apache/bin/* $@

# We need CGO when compiling in Felix for BPF support.
# Currently CGO can be enabled in ARM64 and AMD64 builds.
ifeq ($(ARCH), $(filter $(ARCH),amd64 arm64))
CGO_ENABLED=1
CGO_LDFLAGS="-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) -lbpf -lelf -lz"
CGO_CFLAGS="-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH)"
else
CGO_ENABLED=0
CGO_LDFLAGS=""
CGO_CFLAGS=""
endif

$(NODE_CONTAINER_BINARY): filesystem/usr/lib/calico/bpf $(LIBBPF_A) $(SRC_FILES) ../go.mod
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/calico-node/main.go, $@)
else
ifeq ($(ARCH),$(filter $(ARCH),amd64 arm64))
	$(call build_cgo_binary, ./cmd/calico-node/main.go, $@)
else
	$(call build_binary, ./cmd/calico-node/main.go, $@)
endif
endif

LIBBPF_FILE_CREATED:
	make -C ../felix clone-libbpf

$(WINDOWS_BINARY): $(SRC_FILES)
	$(call build_windows_binary, ./cmd/calico-node/main.go, $@)

$(WINDOWS_ARCHIVE_ROOT)/cni/calico.exe:
	$(call build_windows_binary, ./cmd/calico, $@)

$(WINDOWS_ARCHIVE_ROOT)/cni/calico-ipam.exe:
	$(call build_windows_binary, ./cmd/calico-ipam, $@)

$(TOOLS_MOUNTNS_BINARY):
ifeq ($(CGO_ENABLED),1)
	$(call build_cgo_binary, ./cmd/mountns, $@)
else
	$(call build_binary, ./cmd/mountns, $@)
endif


###############################################################################
# Building the image
###############################################################################
## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

dist/LICENSE: ../LICENSE.md
	mkdir -p dist
	cp ../LICENSE.md $@

image $(NODE_IMAGE): register $(NODE_CONTAINER_MARKER)
$(NODE_CONTAINER_CREATED): $(REMOTE_DEPS) ./Dockerfile.$(ARCH) $(NODE_CONTAINER_BINARY) $(INCLUDED_SOURCE) $(NODE_CONTAINER_FILES) $(TOOLS_MOUNTNS_BINARY) dist/LICENSE
	$(DOCKER_BUILD) --network=host --build-arg BIN_DIR=$(NODE_CONTAINER_BIN_DIR) --build-arg BIRD_IMAGE=$(BIRD_IMAGE) --build-arg GIT_VERSION=$(GIT_VERSION) -t $(NODE_IMAGE):latest-$(ARCH) -f ./Dockerfile.$(ARCH) .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(NODE_CONTAINER_FIPS_CREATED): $(REMOTE_DEPS) ./Dockerfile.$(ARCH) $(NODE_CONTAINER_BINARY) $(INCLUDED_SOURCE) $(NODE_CONTAINER_FILES) $(TOOLS_MOUNTNS_BINARY) dist/LICENSE
	$(DOCKER_BUILD) --network=host --build-arg BIN_DIR=$(NODE_CONTAINER_BIN_DIR) --build-arg BIRD_IMAGE=$(BIRD_IMAGE) --build-arg GIT_VERSION=$(GIT_VERSION) -t $(NODE_IMAGE):latest-fips-$(ARCH) -f ./Dockerfile.$(ARCH) .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

# download BIRD source to include in image.
$(BIRD_SOURCE): .bird-source.created
.bird-source.created:
	rm -rf filesystem/included-source/bird*
	mkdir -p filesystem/included-source/
	curl -sSf -L --retry 5 -o $(BIRD_SOURCE) https://github.com/projectcalico/bird/tarball/$(BIRD_VERSION)
	touch $@

# include GPL felix code in the image.
$(FELIX_GPL_SOURCE): .felix-gpl-source.created
.felix-gpl-source.created: $(shell find ../felix/bpf-gpl -type f)
	rm -rf filesystem/included-source/felix*
	mkdir -p filesystem/included-source/
	tar cf $(FELIX_GPL_SOURCE) ../felix/bpf-gpl --use-compress-program="xz -T0"
	touch $@

###############################################################################
# FV Tests
###############################################################################
K8ST_IMAGE_TARS=calico-node.tar \
	calico-typha.tar \
	calico-apiserver.tar \
	calico-cni.tar \
	pod2daemon.tar \
	csi.tar \
	node-driver-registrar.tar \
	calicoctl.tar \
	kube-controllers.tar \
	operator.tar \
	whisker.tar \
	whisker-backend.tar \
	goldmane.tar

ifeq ($(SEMAPHORE_GIT_REF_TYPE), pull-request)
# Determine the tests to run using the test spider tool, which emits a list of impacted packages.
WHAT=$(shell $(DOCKER_GO_BUILD) sh -c 'go run ../hack/test/spider -commit-range=${SEMAPHORE_GIT_COMMIT_RANGE} -filter-dir node/')
else
# By default, run all tests.
WHAT=$(shell find . -name "*_test.go" | xargs dirname | sort -u)
endif

## Run the ginkgo tests.
ut fv: $(LIBBPF_A) run-k8s-apiserver
	$(DOCKER_RUN) \
	-v $(CERTS_PATH):/home/user/certs \
	-e KUBECONFIG=/go/src/github.com/projectcalico/calico/hack/test/certs/kubeconfig \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	-e GINKGO_ARGS="$(GINKGO_ARGS)" \
	$(CALICO_BUILD) ./run-uts $(WHAT)

###############################################################################
# System tests
###############################################################################
dist/calicoctl:
	mkdir -p dist
	make -C ../calicoctl build
	cp ../calicoctl/bin/calicoctl-linux-$(ARCH) $@

dist/calico dist/calico-ipam:
	mkdir -p dist
	make -C ../cni-plugin build
	cp ../cni-plugin/bin/$(ARCH)/calico dist/calico
	cp ../cni-plugin/bin/$(ARCH)/calico-ipam dist/calico-ipam

# Create images for containers used in the tests
busybox.tar:
	docker pull $(ARCH)/busybox:latest
	docker save --output busybox.tar $(ARCH)/busybox:latest

workload.tar: workload/Dockerfile
	$(DOCKER_BUILD) -t workload -f workload/Dockerfile workload
	docker save --output workload.tar workload

IPT_ALLOW_ETCD:=-A INPUT -i docker0 -p tcp --dport 2379 -m comment --comment "calico-st-allow-etcd" -j ACCEPT

# Create the calico/test image
test_image: .calico_test.created
.calico_test.created: calico_test/Dockerfile $(TEST_CONTAINER_FILES)
	$(DOCKER_BUILD) --build-arg ETCD_VERSION=$(ETCD_VERSION) -f calico_test/Dockerfile -t $(TEST_CONTAINER_NAME) calico_test
	touch $@

chart: ../bin/tigera-operator-$(GIT_VERSION).tgz
../bin/tigera-operator-$(GIT_VERSION).tgz:
	make -C ../ bin/tigera-operator-$(GIT_VERSION).tgz

# Tag to use for images built for e2e testing. This must match the image tag used in
# tests/k8st/infra/calico_versions.yml
TEST_BUILD_TAG=test-build

operator.tar: $(K8ST_IMAGE_TARS) tests/k8st/infra/calico_versions.yml
	cd tests/k8st/infra/ && BRANCH=$(OPERATOR_BRANCH) ./build-operator.sh
	docker save --output $@ docker.io/tigera/operator:$(TEST_BUILD_TAG)

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker tag $(NODE_IMAGE):latest-$(ARCH) calico/node:$(TEST_BUILD_TAG)
	docker save --output $@ calico/node:$(TEST_BUILD_TAG)

calico-typha.tar: ../go.mod $(shell find ../typha -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../typha image
	docker tag calico/typha:latest-$(ARCH) calico/typha:$(TEST_BUILD_TAG)
	docker save --output $@ calico/typha:$(TEST_BUILD_TAG)

calico-apiserver.tar: ../go.mod $(shell find ../apiserver -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../apiserver image
	docker tag calico/apiserver:latest-$(ARCH) calico/apiserver:$(TEST_BUILD_TAG)
	docker save --output $@ calico/apiserver:$(TEST_BUILD_TAG)

calico-cni.tar: ../go.mod $(shell find ../cni-plugin -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../cni-plugin image
	docker tag calico/cni:latest-$(ARCH) calico/cni:$(TEST_BUILD_TAG)
	docker save --output $@ calico/cni:$(TEST_BUILD_TAG)

csi.tar: ../go.mod $(shell find ../pod2daemon/ -name '*.go')
	make -C ../pod2daemon image
	docker tag calico/csi:latest-$(ARCH) calico/csi:$(TEST_BUILD_TAG)
	docker save --output $@ calico/csi:$(TEST_BUILD_TAG)

node-driver-registrar.tar: ../go.mod $(shell find ../pod2daemon/ -name '*.go')
	make -C ../pod2daemon image
	docker tag calico/node-driver-registrar:latest-$(ARCH) calico/node-driver-registrar:$(TEST_BUILD_TAG)
	docker save --output $@ calico/node-driver-registrar:$(TEST_BUILD_TAG)

pod2daemon.tar: ../go.mod $(shell find ../pod2daemon/ -name '*.go')
	make -C ../pod2daemon image
	docker tag calico/pod2daemon-flexvol:latest-$(ARCH) calico/pod2daemon-flexvol:$(TEST_BUILD_TAG)
	docker save --output $@ calico/pod2daemon-flexvol:$(TEST_BUILD_TAG)

calicoctl.tar: ../go.mod $(shell find ../calicoctl -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../calicoctl image
	docker tag calico/ctl:latest-$(ARCH) calico/ctl:$(TEST_BUILD_TAG)
	docker save --output $@ calico/ctl:$(TEST_BUILD_TAG)

kube-controllers.tar: ../go.mod $(shell find ../kube-controllers -name '*.go') $(shell find ../libcalico-go -name '*.go')
	make -C ../kube-controllers image
	docker tag calico/kube-controllers:latest-$(ARCH) calico/kube-controllers:$(TEST_BUILD_TAG)
	docker save --output $@ calico/kube-controllers:$(TEST_BUILD_TAG)

goldmane.tar: ../go.mod $(shell find ../goldmane -name '*.go')
	make -C ../goldmane image
	docker tag calico/goldmane:latest-$(ARCH) calico/goldmane:$(TEST_BUILD_TAG)
	docker save --output $@ calico/goldmane:$(TEST_BUILD_TAG)

whisker.tar: ../go.mod $(shell find ../whisker)
	make -C ../whisker image
	docker tag calico/whisker:latest-$(ARCH) calico/whisker:$(TEST_BUILD_TAG)
	docker save --output $@ calico/whisker:$(TEST_BUILD_TAG)

whisker-backend.tar: ../go.mod $(shell find ../whisker-backend -name '*.go')
	make -C ../whisker-backend image
	docker tag calico/whisker-backend:latest-$(ARCH) calico/whisker-backend:$(TEST_BUILD_TAG)
	docker save --output $@ calico/whisker-backend:$(TEST_BUILD_TAG)

load-container-images: $(K8ST_IMAGE_TARS) $(KUBECTL)
	# Load the latest tar files onto the currently running kind cluster.
	KUBECONFIG=$(KIND_KUBECONFIG) KIND=$(KIND) ./tests/k8st/load_images_on_kind_cluster.sh
	# Restart the Calico containers so they launch with the newly loaded code.
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) delete pods -n calico-system --all
	# calicoctl is deployed as a pod on the cluster and needs to be recreated.
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) apply -f tests/k8st/infra/calicoctl.yaml

.PHONY: k8s-test
## Run the k8s tests
k8s-test:
	$(MAKE) kind-k8st-setup
	$(MAKE) kind-k8st-run-test
	$(MAKE) kind-k8st-cleanup

.PHONY: kind-k8st-setup
kind-k8st-setup: $(K8ST_IMAGE_TARS) ../bin/tigera-operator-$(GIT_VERSION).tgz kind-cluster-create
	KUBECONFIG=$(KIND_KUBECONFIG) KIND=$(KIND) ARCH=$(ARCH) GIT_VERSION=$(GIT_VERSION) ./tests/k8st/deploy_resources_on_kind_cluster.sh

.PHONY: kind-k8st-run-test
kind-k8st-run-test: .calico_test.created $(KIND_KUBECONFIG)
	docker run -t --rm \
	    -v $(CURDIR):/code \
	    -v /var/run/docker.sock:/var/run/docker.sock \
	    -v $(KIND_KUBECONFIG):/root/.kube/config \
	    -v $(KUBECTL):/bin/kubectl \
	    -e ROUTER_IMAGE=$(BIRD_IMAGE) \
	    --privileged \
	    --net host \
	${TEST_CONTAINER_NAME} \
	    sh -c 'echo "container started.." && \
	     cd /code/tests/k8st && nosetests $(K8ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/$(K8ST_REPORT_FILENAME)" --with-timer'

.PHONY: kind-k8st-cleanup
kind-k8st-cleanup: kind-cluster-destroy

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks ut image image-windows

## Deploys images to registry
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	# Generate the `latest` node images.
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)-fips LATEST_IMAGE_TAG=latest-fips
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	# Generate the Windows zip archives.
	$(MAKE) release-windows-archive
	$(MAKE) $(WINDOWS_INSTALL_SCRIPT)
	touch $@

## Produces the Windows installation ZIP archive for the release.
release-windows-archive: release-prereqs
	$(MAKE) build-windows-archive WINDOWS_ARCHIVE_TAG=$(VERSION)

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	# Push node images.
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

	# Push Windows images.
	$(MAKE) release-windows IMAGETAG=$(VERSION) CONFIRM=$(CONFIRM)

	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	# Push Windows images.
	$(MAKE) release-windows IMAGETAG=latest CONFIRM=$(CONFIRM)

###############################################################################
# Windows packaging
###############################################################################
# Pull the BGP configuration scripts and templates from the confd repo.
$(WINDOWS_MOD_CACHED_FILES):

$(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp%: windows-packaging/config-bgp%
	$(DOCKER_RUN) $(CALICO_BUILD) sh -ec ' \
        $(GIT_CONFIG_SSH) \
        cp -r ../confd/$< $@'; \
        chmod +w $@

$(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/%: windows-packaging/conf.d/%
	$(DOCKER_RUN) $(CALICO_BUILD) sh -ec ' \
        $(GIT_CONFIG_SSH) \
        cp -r ../confd/$< $@'; \
        chmod +w $@

$(WINDOWS_ARCHIVE_ROOT)/confd/templates/%: windows-packaging/templates/%
	$(DOCKER_RUN) $(CALICO_BUILD) sh -ec ' \
        $(GIT_CONFIG_SSH) \
        cp -r ../confd/$< $@'; \
        chmod +w $@

$(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1:
	curl -sSf -L --retry 5 -o $@ $(MICROSOFT_SDN_GITHUB_RAW_URL)/Kubernetes/windows/hns.psm1

$(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt:
	curl -sSf -L --retry 5 -o $@  $(MICROSOFT_SDN_GITHUB_RAW_URL)/License.txt

## Download NSSM.
windows-packaging/nssm.zip:
	curl -sSf -L --retry 5 -o $@ $(WINDOWS_NSSM_URL)

windows-packaging/nssm.exe: windows-packaging/nssm.zip
	cd windows-packaging && \
	sha256sum --check nssm.sha256sum && \
	unzip -o nssm.zip 'nssm-$(WINDOWS_NSSM_VERSION)/win64/nssm.exe' && \
	mv nssm-$(WINDOWS_NSSM_VERSION)/win64/nssm.exe nssm.exe && \
	rm -rf nssm-$(WINDOWS_NSSM_VERSION)/

$(WINDOWS_ARCHIVE): build-windows-archive

.PHONY: build-windows-archive
build-windows-archive: $(WINDOWS_ARCHIVE_FILES) windows-packaging/nssm.zip
	# To be as atomic as possible, we re-do work like unpacking NSSM here.
	-rm -f "$(WINDOWS_ARCHIVE)"
	-rm -rf $(WINDOWS_ARCHIVE_ROOT)/nssm
	mkdir -p dist
	cd windows-packaging && \
	sha256sum --check nssm.sha256sum && \
	cd CalicoWindows && \
	unzip  ../nssm.zip \
	       -x 'nssm-$(WINDOWS_NSSM_VERSION)/src/*' && \
	mv nssm-$(WINDOWS_NSSM_VERSION) nssm && \
	cd .. && \
	zip -r "../$(WINDOWS_ARCHIVE)" CalicoWindows -x '*.git*'
	@echo
	@echo "Windows archive built at $(WINDOWS_ARCHIVE)"

$(WINDOWS_ARCHIVE_BINARY): $(WINDOWS_BINARY)
	cp $< $@

# Build the docs site and copy over the install-calico-windows.ps1 script.
$(WINDOWS_INSTALL_SCRIPT):
	-mkdir -p dist
	cp $(CURDIR)/windows-packaging/install-calico-windows.ps1 $@
	sed -i s/VERSION/$(GIT_VERSION)/g $@

# NOTE: WINDOWS_IMAGE_REQS must be defined with the requirements to build the windows
# image. These must be added as reqs to 'image-windows' (originally defined in
# lib.Makefile) on the specific package Makefile otherwise they are not correctly
# recognized.
WINDOWS_IMAGE_REQS := \
	Dockerfile-windows \
	dist/LICENSE \
	$(WINDOWS_BINARY) \
	$(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1 \
	$(WINDOWS_ARCHIVE_ROOT)/libs/calico/calico.psm1 \
	$(WINDOWS_ARCHIVE_ROOT)/config-hpc.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/felix/felix-service.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/node/node-service.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/uninstall-calico-hpc.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/confd-service.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.ps1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/config-bgp.psm1 \
	$(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/blocks.toml \
	$(WINDOWS_ARCHIVE_ROOT)/confd/conf.d/peerings.toml \
	$(WINDOWS_ARCHIVE_ROOT)/confd/templates/blocks.ps1.template \
	$(WINDOWS_ARCHIVE_ROOT)/confd/templates/peerings.ps1.template \
	windows-packaging/nssm.exe
image-windows: $(WINDOWS_IMAGE_REQS)
