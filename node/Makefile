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


## BUILD_DEPS are intermediate build artifacts needed by the image (also used by clean).
BUILD_DEPS = $(LIBBPF_A) \
	     filesystem/usr/lib/calico/bpf

## IMAGE_DEPS lists non-Go files the calico/node image depends on.
IMAGE_DEPS = ./Dockerfile $(BUILD_DEPS)

# Run these tests against the projectcalico.org/v3 API group by default.
CALICO_API_GROUP ?= projectcalico.org/v3

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

NODE_CONTAINER_BIN_DIR=dist/bin
NODE_CONTAINER_MARKER=$(NODE_CONTAINER_CREATED)

# The node image uses the combined calico binary built with CGO for BPF support.
NODE_CONTAINER_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-$(ARCH)

###############################################################################

# Our (public) GCP bucket where we mirror any third party files
# that are flaky to retrieve.
THIRD_PARTY_DEPS_MIRROR=https://storage.googleapis.com/public-calico-third-party-deps

# Versions and location of dependencies used in the build.
BIRD_IMAGE ?= calico/bird:$(BIRD_VERSION)-$(ARCH)
BIRD_SOURCE=filesystem/included-source/bird-$(BIRD_VERSION).tar.gz

# Producer image carrying the patched nftables + libnftnl RPMs we install in
# the runtime stage. The tag is content-addressed so any change to specs,
# patches, or version pins yields a new tag (see hack/rpms/nftables/Makefile).
include ../hack/rpms/nftables/image.mk
FELIX_GPL_SOURCE=filesystem/included-source/felix-ebpf-gpl.tar.xz
INCLUDED_SOURCE=$(BIRD_SOURCE) $(FELIX_GPL_SOURCE)

TEST_CONTAINER_FILES=$(shell find tests/ -type f ! -name '*.created')

# Variables controlling the image
NODE_CONTAINER_CREATED=.calico_node.created-$(ARCH)
WINDOWS_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico.exe
TOOLS_MOUNTNS_BINARY = $(NODE_CONTAINER_BIN_DIR)/mountns-$(ARCH)

WINDOWS_INSTALL_SCRIPT := dist/install-calico-windows.ps1

# Variables for the Windows packaging.
# Name of the Windows release ZIP archive.
WINDOWS_PACKAGING_ROOT := windows-packaging
WINDOWS_ARCHIVE_ROOT := windows-packaging/CalicoWindows
WINDOWS_ARCHIVE_BINARY := $(WINDOWS_ARCHIVE_ROOT)/calico.exe
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
    $(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1 \
    $(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt \
    $(WINDOWS_ARCHIVE_ROOT)/libs/calico/calico.psm1

MICROSOFT_SDN_VERSION := 0d7593e5c8d4c2347079a7a6dbd9eb034ae19a44
MICROSOFT_SDN_GITHUB_RAW_URL := https://raw.githubusercontent.com/microsoft/SDN/$(MICROSOFT_SDN_VERSION)

# Variables used by the tests
ST_TO_RUN?=tests/st/
K8ST_TO_RUN?=tests/
# Can exclude the slower tests with "-m 'not slow'"
ST_OPTIONS?=

K8ST_REPORT_FILENAME ?= k8s-tests.xml

# Filesystem of the node container that is checked in to this repository.
NODE_CONTAINER_FILES=$(shell find ./filesystem -type f -not -path './filesystem/usr/lib/calico/bpf/*')

# Calculate a timestamp for any build artefacts.
DATE:=$(shell date -u +'%FT%T%z')

## SRC_FILES is auto-populated from node/deps.txt by lib.Makefile.
## The node image ships the combined `calico` monobinary built from
## ../cmd/calico (see $(NODE_CONTAINER_BINARY) below). The monobinary's source
## closure (felix, confd, etc.) is NOT in node/deps.txt because node's own Go
## module doesn't import those packages directly — they're pulled in by the
## `make -C ../cmd/calico` recursion, which deps.txt generation can't see. Fold
## in the cmd module's local deps so a change to felix (or anything else in the
## monobinary) rebuilds the node image.
SRC_FILES += $(call local-deps-go-files,cmd)
## Append non-Go sources that also affect the build.
SRC_FILES += $(shell find ../felix -name '*.[ch]')

## Clean enough that a new release build will be clean
clean: clean-windows
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf certs *.tar $(NODE_CONTAINER_BIN_DIR)
	rm -rf $(BUILD_DEPS)
	rm -rf filesystem/included-source
	rm -rf $(REPO_ROOT)/hack/test/kind/infra/operator
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

$(LIBBPF_A): $(shell find ../felix/bpf-gpl/libbpf -type f -name '*.[ch]')
	make -C ../felix libbpf ARCH=$(ARCH)

filesystem/usr/lib/calico/bpf: $(shell find ../felix/bpf-gpl -type f) $(shell find ../felix/bpf-apache -type f)
	rm -rf filesystem/usr/lib/calico/bpf/ && mkdir -p filesystem/usr/lib/calico/bpf/
	# Clean stale build artifacts that may reference headers from a previous
	# build environment (e.g., Docker container with different clang version).
	make -C ../felix/bpf-gpl clean
	make -C ../felix/bpf-apache clean
	make -C ../felix build-bpf ARCH=$(ARCH)
	cp -r ../felix/bpf-gpl/bin/* $@
	cp -r ../felix/bpf-apache/bin/* $@

# Normalize userspace types to ensure consistency across architectures.
ARCH_CGO_CFLAGS=
ifeq ($(ARCH),ppc64le)
    ARCH_CGO_CFLAGS=-D__SANE_USERSPACE_TYPES__
endif
# When cross-compiling, force lld as the linker — GNU ld is single-target,
# while lld natively links the cross-arch ELF objects produced by clang.
# (The cross sysroot itself is already supplied via CC's --sysroot flag.)
CROSS_CGO_LDFLAGS=
ifneq ($(CROSS_SYSROOT),)
    CROSS_CGO_LDFLAGS=$(CROSS_LDFLAGS)
endif
CGO_LDFLAGS="-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) $(CROSS_CGO_LDFLAGS) -lbpf -lelf -lz"
CGO_CFLAGS="-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH) $(ARCH_CGO_CFLAGS)"

# The node image uses the combined calico binary built with CGO for BPF support.
CMD_CALICO_BINDIR = ../cmd/calico/bin

$(NODE_CONTAINER_BINARY): filesystem/usr/lib/calico/bpf $(LIBBPF_A) $(SRC_FILES) ../go.mod
	$(MAKE) -C ../cmd/calico build-cgo ARCH=$(ARCH)
	mkdir -p $(NODE_CONTAINER_BIN_DIR)
	cp $(CMD_CALICO_BINDIR)/calico-cgo-$(ARCH) $@

LIBBPF_FILE_CREATED:
	make -C ../felix clone-libbpf

$(WINDOWS_BINARY): $(SRC_FILES)
	$(call build_windows_binary, ../cmd/calico-windows, $@)

$(WINDOWS_ARCHIVE_ROOT)/cni/calico.exe: $(WINDOWS_BINARY)
	cp $(WINDOWS_BINARY) $@

$(TOOLS_MOUNTNS_BINARY):
	$(call build_cgo_binary, ./cmd/mountns, $@)

###############################################################################
# Building the image
###############################################################################
## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

dist/LICENSE: ../LICENSE.md
	mkdir -p dist
	cp ../LICENSE.md $@

image $(NODE_IMAGE): $(NODE_CONTAINER_MARKER)

# nft-rpms-image builds (or no-ops on cache hit) the per-arch producer image
# carrying our patched nftables + libnftnl RPMs. It's an order-only prereq;
# the consumer build wires it in via --build-context nft-rpms=docker-image://...
# so buildkit sources it from the local daemon (avoiding `--pull=always`
# trying to fetch it from a registry where it may not have been pushed yet).
.PHONY: nft-rpms-image
# `| register` so binfmt is set up before cross-arch buildx.
nft-rpms-image: | register
	$(MAKE) -C ../hack/rpms/nftables image ARCH=$(ARCH)

# Drop --pull from DOCKER_BUILD: with --pull=always, buildkit treats the
# nft-rpms build context (docker-image://calico/nftables-rpms:<sha>-<arch>)
# as a registry pull and fails when that tag hasn't been pushed yet (PR
# builds, fresh local builds). Other base images (UBI_IMAGE, BIRD_IMAGE,
# BPFTOOL_IMAGE) are pinned by tag so cache freshness is fine without --pull.
$(NODE_CONTAINER_CREATED): DOCKER_PULL :=

$(NODE_CONTAINER_CREATED): $(IMAGE_DEPS) $(NODE_CONTAINER_BINARY) $(INCLUDED_SOURCE) $(NODE_CONTAINER_FILES) $(TOOLS_MOUNTNS_BINARY) dist/LICENSE | register nft-rpms-image
	$(DOCKER_BUILD) \
		--build-arg BIN_DIR=$(NODE_CONTAINER_BIN_DIR) \
		--build-arg BIRD_IMAGE=$(BIRD_IMAGE) \
		--build-arg BPFTOOL_IMAGE=$(BPFTOOL_IMAGE) \
		--build-context nft-rpms=docker-image://$(NFT_RPMS_IMAGE) \
		--build-arg GIT_VERSION=$(GIT_VERSION) \
		-t $(NODE_IMAGE):latest-$(ARCH) -f ./Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# download BIRD source to include in image.
$(BIRD_SOURCE): .bird-source.created
.bird-source.created:
	rm -rf filesystem/included-source/bird*
	mkdir -p filesystem/included-source/
	curl -sSf -L --retry 5 --retry-all-errors --http1.1 -o $(BIRD_SOURCE) https://github.com/projectcalico/bird/tarball/$(BIRD_VERSION)
	touch $@

# include GPL felix code in the image.
# Order-only depend on filesystem/usr/lib/calico/bpf so that BPF compilation
# finishes before we tar up the source tree — otherwise tar races with the
# build and fails with "file changed as we read it". Order-only (|) so that
# bpf-apache changes don't trigger unnecessary re-tars.
$(FELIX_GPL_SOURCE): .felix-gpl-source.created
.felix-gpl-source.created: $(shell find ../felix/bpf-gpl -type f -not -name '*.ll' -not -name '*.o' -not -name '*.d' -not -path '*/libbpf/*') | filesystem/usr/lib/calico/bpf
	rm -rf filesystem/included-source/felix*
	mkdir -p filesystem/included-source/
	tar cf $(FELIX_GPL_SOURCE) \
		--exclude='*.ll' --exclude='*.o' --exclude='*.d' \
		--exclude='libbpf' \
		--use-compress-program="xz -T0" \
		../felix/bpf-gpl
	touch $@

###############################################################################
# FV Tests
###############################################################################
ifeq ($(SEMAPHORE_GIT_REF_TYPE), pull-request)
# Determine the tests to run using the test spider tool, which emits a list of impacted packages.
WHAT=$(shell $(DOCKER_GO_BUILD) sh -c 'go run ../hack/test/spider -commit-range=${SEMAPHORE_GIT_COMMIT_RANGE} -filter-dir node/')
else
# By default, run all tests.
WHAT=$(shell find . -name "*_test.go" | xargs dirname | sort -u)
endif

# Packages to exclude from the UT run. tests/k8st holds the Go k8st system
# tests, which need a live kind cluster (run via kind-k8st-run-test).
UT_PACKAGES_TO_SKIP?=tests/k8st

## Run the ginkgo tests.
ut fv: $(LIBBPF_A) run-k8s-apiserver
	mkdir -p report
	$(DOCKER_RUN) \
	-v $(CERTS_PATH):/home/user/certs \
	-e KUBECONFIG=/go/src/github.com/projectcalico/calico/hack/test/certs/kubeconfig \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	-e CALICO_API_GROUP=$(CALICO_API_GROUP) \
	$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r --skip-package $(UT_PACKAGES_TO_SKIP) --junit-report=node_ut.xml --output-dir=report/ $(GINKGO_ARGS) .'

###############################################################################
# System tests
###############################################################################
CHARTS=../bin/tigera-operator-$(GIT_VERSION).tgz \
			 ../bin/crd.projectcalico.org.v1-$(GIT_VERSION).tgz \
			 ../bin/projectcalico.org.v3-$(GIT_VERSION).tgz

dist/calicoctl:
	mkdir -p dist
	make -C ../calicoctl build
	cp ../calicoctl/bin/calicoctl-linux-$(ARCH) $@

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

chart: $(CHARTS)
../bin/tigera-operator-$(GIT_VERSION).tgz:
	make -C ../ bin/tigera-operator-$(GIT_VERSION).tgz
../bin/crd.projectcalico.org.v1-$(GIT_VERSION).tgz:
	make -C ../ bin/crd.projectcalico.org.v1-$(GIT_VERSION).tgz
../bin/projectcalico.org.v3-$(GIT_VERSION).tgz:
	make -C ../ bin/projectcalico.org.v3-$(GIT_VERSION).tgz

.PHONY: k8s-test
## Run the k8s tests
k8s-test:
	$(MAKE) -C $(REPO_ROOT) kind-up
	$(MAKE) kind-k8st-run-test
	$(MAKE) -C $(REPO_ROOT) kind-down

# Selector for Go-side k8st tests (e.g. K8ST_GO_TO_RUN='TestReadiness').
# Defaults to running every Go test in the suite.
K8ST_GO_TO_RUN?=.

# Build the Go k8st test binary. Static (CGO disabled) so it runs inside
# the Alpine-based calico/test container with no extra runtime deps. The
# .PHONY marker means `make` always reinvokes `go test -c` and relies on
# Go's own build cache for incremental rebuilds — matching the felix FV
# pattern (felix/fv/fv.test) and avoiding a brittle hand-maintained
# Makefile dependency list across libcalico-go / api / lib subtrees.
.PHONY: bin/k8st.test
bin/k8st.test:
	$(DOCKER_GO_BUILD) sh -c 'CGO_ENABLED=0 go test -c -o $@ ./tests/k8st/tests'

.PHONY: kind-k8st-run-test
kind-k8st-run-test: .calico_test.created $(KIND_KUBECONFIG) bin/k8st.test
	docker run -t --rm \
	    -v $(CURDIR):/code \
	    -v /var/run/docker.sock:/var/run/docker.sock \
	    -v $(KIND_KUBECONFIG):/root/.kube/config \
	    -v $(KUBECTL):/bin/kubectl \
	    -v $(REPO_ROOT)/cmd/calico/bin/calico-$(ARCH):/usr/local/bin/calico \
	    -e ROUTER_IMAGE=$(BIRD_IMAGE) \
	    -e KUBECONFIG=/root/.kube/config \
	    -e PYTHONDONTWRITEBYTECODE=1 \
	    --privileged \
	    --net host \
	${TEST_CONTAINER_NAME} \
	    sh -c 'echo "container started.." && \
	     cd /code/tests/k8st && \
	     go_rc=0; py_rc=0; \
	     /code/bin/k8st.test -test.v -test.run "$(K8ST_GO_TO_RUN)" || go_rc=$$?; \
	     pytest $(K8ST_TO_RUN) -v --junit-xml="/code/report/$(K8ST_REPORT_FILENAME)" || py_rc=$$?; \
	     echo "Go suite rc=$$go_rc, Python suite rc=$$py_rc"; \
	     [ $$go_rc -eq 0 ] && [ $$py_rc -eq 0 ]'

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
	curl -sSf -L --retry 5 --retry-all-errors --http1.1 -o $@ $(MICROSOFT_SDN_GITHUB_RAW_URL)/Kubernetes/windows/hns.psm1

$(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt:
	curl -sSf -L --retry 5 --retry-all-errors --http1.1 -o $@  $(MICROSOFT_SDN_GITHUB_RAW_URL)/License.txt

## Download NSSM.
windows-packaging/nssm.zip:
	curl -sSf -L --retry 5 --retry-all-errors --http1.1 -o $@ $(WINDOWS_NSSM_URL)

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
	Dockerfile.windows \
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
