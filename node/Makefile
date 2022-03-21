include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/node

RELEASE_BRANCH_PREFIX ?=release
DEV_TAG_SUFFIX        ?=0.dev

# Name of the images.
# e.g., <registry>/<name>:<tag>
NODE_IMAGE            ?=node
WINDOWS_UPGRADE_IMAGE ?=windows-upgrade

WINDOWS_VERSIONS?=1809 2004 20H2 ltsc2022
BUILD_IMAGES ?=$(NODE_IMAGE)

# Paths within the build container for BPF source.
LIBBPF_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/include/libbpf/src/
BPFGPL_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/

# Paths within the repository for BPF source.
LIBBPF_A=../felix/bpf-gpl/include/libbpf/src/$(ARCH)/libbpf.a

# Add in local static-checks
LOCAL_CHECKS=check-boring-ssl

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

# Set the platform correctly for building docker images.
ifeq ($(ARCH),arm64)
# Required for eBPF support in ARM64.
# We need to force ARM64 build image to be used in a crosscompilation run.
CALICO_BUILD:=$(CALICO_BUILD)-$(ARCH)
endif

###############################################################################

# Versions and location of dependencies used in the build.
BIRD_IMAGE ?= calico/bird:$(BIRD_VERSION)-$(ARCH)
BIRD_SOURCE=filesystem/included-source/bird-$(BIRD_VERSION).tar.gz
FELIX_GPL_SOURCE=filesystem/included-source/felix-ebpf-gpl.tar.gz
INCLUDED_SOURCE=$(BIRD_SOURCE) $(FELIX_GPL_SOURCE)

# Versions and locations of dependencies used in tests.
TEST_CONTAINER_NAME_VER?=latest
TEST_CONTAINER_NAME?=calico/test:$(TEST_CONTAINER_NAME_VER)-$(ARCH)

TEST_CONTAINER_FILES=$(shell find tests/ -type f ! -name '*.created')

# Variables controlling the image
NODE_CONTAINER_CREATED=.calico_node.created-$(ARCH)
NODE_CONTAINER_BIN_DIR=./dist/bin/
NODE_CONTAINER_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node-$(ARCH)
WINDOWS_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node.exe

WINDOWS_INSTALL_SCRIPT := dist/install-calico-windows.ps1

# Variables for the Windows packaging.
# Name of the Windows release ZIP archive.
WINDOWS_ARCHIVE_ROOT := windows-packaging/CalicoWindows
WINDOWS_ARCHIVE_BINARY := $(WINDOWS_ARCHIVE_ROOT)/calico-node.exe
WINDOWS_ARCHIVE_TAG?=$(GIT_VERSION)
WINDOWS_ARCHIVE := dist/calico-windows-$(WINDOWS_ARCHIVE_TAG).zip
# Version of NSSM to download.
WINDOWS_NSSM_VERSION=2.24
# Explicit list of files that we copy in from the mod cache.  This is required because the copying rules we use are pattern-based
# and they only work with an explicit rule of the form "$(WINDOWS_MOD_CACHED_FILES): <file path from project root>" (otherwise,
# make has no way to know that the mod cache target produces the files we need).
WINDOWS_MOD_CACHED_FILES := \
    windows-packaging/config-bgp.ps1 \
    windows-packaging/config-bgp.psm1 \
    windows-packaging/conf.d/blocks.toml \
    windows-packaging/conf.d/peerings.toml \
    windows-packaging/templates/blocks.ps1.template \
    windows-packaging/templates/peerings.ps1.template \

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

WINDOWS_UPGRADE_ROOT         ?= windows-upgrade
WINDOWS_UPGRADE_DIST          = dist/windows-upgrade

# The directory that holds temporary files used to build the windows upgrade zip
# archive.
WINDOWS_UPGRADE_DIST_STAGE    = $(WINDOWS_UPGRADE_DIST)/stage
WINDOWS_UPGRADE_INSTALL_FILE ?= $(WINDOWS_UPGRADE_DIST_STAGE)/install-calico-windows.ps1
WINDOWS_UPGRADE_INSTALL_ZIP  ?= $(WINDOWS_UPGRADE_DIST_STAGE)/calico-windows-$(WINDOWS_ARCHIVE_TAG).zip
WINDOWS_UPGRADE_SCRIPT       ?= $(WINDOWS_UPGRADE_DIST_STAGE)/calico-upgrade.ps1

# The directory used for the upgrade image docker build context.
WINDOWS_UPGRADE_BUILD        ?= $(WINDOWS_UPGRADE_ROOT)/build

# The final zip archive used in the upgrade image.
WINDOWS_UPGRADE_ARCHIVE      ?= $(WINDOWS_UPGRADE_BUILD)/calico-windows-upgrade.zip

# Variables used by the tests
ST_TO_RUN?=tests/st/
K8ST_TO_RUN?=tests/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

# Filesystem of the node container that is checked in to this repository.
NODE_CONTAINER_FILES=$(shell find ./filesystem -type f)

# Calculate a timestamp for any build artefacts.
DATE:=$(shell date -u +'%FT%T%z')

LDFLAGS=-ldflags "\
	-X $(PACKAGE_NAME)/pkg/lifecycle/startup.VERSION=$(GIT_VERSION) \
	-X $(PACKAGE_NAME)/buildinfo.GitVersion=$(GIT_DESCRIPTION) \
	-X $(PACKAGE_NAME)/buildinfo.BuildDate=$(DATE) \
	-X $(PACKAGE_NAME)/buildinfo.GitRevision=$(GIT_COMMIT)"

# Source golang files on which compiling the calico-node binary depends.
SRC_FILES=$(shell find ./pkg -name '*.go') \
	  $(shell find ../felix -name '*.go') \
	  $(shell find ../libcalico-go -name '*.go') \
	  $(shell find ../confd -name '*.go')

BINDIR?=bin

## Clean enough that a new release build will be clean
clean: clean-windows-upgrade
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf .go-pkg-cache
	rm -rf certs *.tar $(NODE_CONTAINER_BIN_DIR)
	rm -rf $(REMOTE_DEPS)
	rm -f $(WINDOWS_ARCHIVE_BINARY) $(WINDOWS_BINARY)
	rm -f $(WINDOWS_ARCHIVE_ROOT)/libs/hns/hns.psm1
	rm -f $(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt
	rm -f $(WINDOWS_ARCHIVE_ROOT)/cni/*.exe
	rm -f $(WINDOWS_INSTALL_SCRIPT)
	rm -f $(WINDOWS_UPGRADE_INSTALL_FILE)
	rm -f $(WINDOWS_UPGRADE_BUILD)/*.zip
	rm -rf filesystem/included-source
	rm -rf dist
	rm -rf bin
	# We build felix as part of the node build, so clean it as part of the clean.
	make -C ../felix clean
	# Delete images that we built in this repo
	docker rmi $(NODE_IMAGE):latest-$(ARCH) || true
	docker rmi $(TEST_CONTAINER_NAME) || true
	docker rmi $(addprefix $(WINDOWS_UPGRADE_IMAGE):latest-,$(WINDOWS_VERSIONS)) || true

clean-windows-upgrade:
	-rm -f "$(WINDOWS_UPGRADE_DIST_STAGE)"
	-rm -rf "$(WINDOWS_UPGRADE_BUILD)"

###############################################################################
# Building the binary
###############################################################################
build: $(NODE_CONTAINER_BINARY)

# Pull in config from confd.
filesystem/etc/calico/confd/conf.d: $(shell find ../confd/etc/calico/confd/conf.d -type f)
	rm -rf $@ && cp -r ../confd/etc/calico/confd/conf.d $@
	chmod +w $@

filesystem/etc/calico/confd/templates: $(shell find ../confd/etc/calico/confd/templates -type f)
	rm -rf $@ && cp -r ../confd/etc/calico/confd/templates $@
	chmod +w $@

$(LIBBPF_A): $(shell find ../felix/bpf-gpl/include/libbpf -type f)
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

DOCKER_GO_BUILD_CGO=$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) -e CGO_LDFLAGS=$(CGO_LDFLAGS) -e CGO_CFLAGS=$(CGO_CFLAGS) $(CALICO_BUILD)
DOCKER_GO_BUILD_CGO_WINDOWS=$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD)

$(NODE_CONTAINER_BINARY): filesystem/usr/lib/calico/bpf $(LIBBPF_A) $(SRC_FILES) ../go.mod
	$(DOCKER_GO_BUILD_CGO) sh -c '$(GIT_CONFIG_SSH) go build -v -o $@ $(BUILD_FLAGS) $(LDFLAGS) ./cmd/calico-node/main.go'

$(WINDOWS_BINARY):
	$(DOCKER_RUN) \
		-e GOOS=windows \
		$(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		go build -v -o $@ $(LDFLAGS) ./cmd/calico-node/main.go'

$(WINDOWS_ARCHIVE_ROOT)/cni/calico.exe:
	$(DOCKER_RUN) \
		-e GOOS=windows \
		$(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		go build -v -o $@ $(LDFLAGS) ./cmd/calico'

$(WINDOWS_ARCHIVE_ROOT)/cni/calico-ipam.exe:
	$(DOCKER_RUN) \
		-e GOOS=windows \
		$(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		go build -v -o $@ $(LDFLAGS) ./cmd/calico-ipam'

###############################################################################
# Building the image
###############################################################################
## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

image $(NODE_IMAGE): register $(NODE_CONTAINER_CREATED)
$(NODE_CONTAINER_CREATED): $(REMOTE_DEPS) ./Dockerfile.$(ARCH) $(NODE_CONTAINER_BINARY) $(INCLUDED_SOURCE) $(NODE_CONTAINER_FILES) 
	$(DOCKER_BUILD) --build-arg BIRD_IMAGE=$(BIRD_IMAGE) -t $(NODE_IMAGE):latest-$(ARCH) -f ./Dockerfile.$(ARCH) . --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# download BIRD source to include in image.
$(BIRD_SOURCE): .bird-source.created
.bird-source.created:
	rm -rf filesystem/included-source/bird*
	mkdir -p filesystem/included-source/
	wget -O $(BIRD_SOURCE) https://github.com/projectcalico/bird/tarball/$(BIRD_VERSION)
	touch $@

# include GPL felix code in the image.
$(FELIX_GPL_SOURCE):
.felix-gpl-source.created: $(shell find ../felix/bpf-gpl -type f)
	rm -rf filesystem/included-source/felix*
	mkdir -p filesystem/included-source/
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'tar cf $(FELIX_GPL_SOURCE) ../felix/bpf-gpl;'
	touch $@

###############################################################################
# FV Tests
###############################################################################
K8ST_IMAGE_TARS=calico-node.tar calico-apiserver.tar calico-cni.tar pod2daemon.tar calicoctl.tar kube-controllers.tar

## Run the ginkgo FVs
fv: run-k8s-apiserver
	$(DOCKER_RUN) \
	-v $(CERTS_PATH):/home/user/certs \
	-e KUBECONFIG=/go/src/github.com/projectcalico/calico/hack/test/certs/kubeconfig \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	$(CALICO_BUILD) ginkgo -cover -r -skipPackage vendor pkg/lifecycle/startup pkg/allocateip $(GINKGO_ARGS)

# Skip packages containing FV tests.
UT_PACKAGES_TO_SKIP?=pkg/lifecycle/startup,pkg/allocateip,pkg/status
.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) ginkgo -r -skipPackage=$(UT_PACKAGES_TO_SKIP) $(GINKGO_ARGS)'

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

workload.tar:
	cd workload && $(DOCKER_BUILD) -t workload -f Dockerfile.$(ARCH) . --load
	docker save --output workload.tar workload

IPT_ALLOW_ETCD:=-A INPUT -i docker0 -p tcp --dport 2379 -m comment --comment "calico-st-allow-etcd" -j ACCEPT

# Create the calico/test image
test_image: calico_test.created
calico_test.created: $(TEST_CONTAINER_FILES)
	cd calico_test && $(DOCKER_BUILD) -f Dockerfile.$(ARCH).calico_test -t $(TEST_CONTAINER_NAME) . --load
	touch calico_test.created

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker save --output $@ $(NODE_IMAGE):latest-$(ARCH)

calico-apiserver.tar: ../go.mod $(shell find ../apiserver -name '*.go')
	make -C ../apiserver image
	docker save --output $@ calico/apiserver:latest-$(ARCH)

calico-cni.tar: ../go.mod $(shell find ../cni-plugin -name '*.go')
	make -C ../cni-plugin image
	docker save --output $@ calico/cni:latest-$(ARCH)

pod2daemon.tar: ../go.mod $(shell find ../pod2daemon -name '*.go')
	make -C ../pod2daemon image
	docker save --output $@ calico/pod2daemon-flexvol:latest-$(ARCH)

calicoctl.tar: ../go.mod $(shell find ../calicoctl -name '*.go')
	make -C ../calicoctl image
	docker save --output $@ calico/ctl:latest-$(ARCH)

kube-controllers.tar: ../go.mod $(shell find ../kube-controllers -name '*.go')
	make -C ../kube-controllers image
	docker save --output $@ calico/kube-controllers:latest-$(ARCH)

load-container-images: $(K8ST_IMAGE_TARS) $(KUBECTL)
	# Load the latest tar files onto the currently running kind cluster.
	KUBECONFIG=$(KIND_KUBECONFIG) ./tests/k8st/load_images_on_kind_cluster.sh
	# Restart the Calico containers so they launch with the newly loaded code.
	# TODO: We should be able to do this without restarting everything in kube-system.
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) delete pods -n kube-system --all 
	# calicoctl is deployed as a pod on the cluster and needs to be recreated.
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) apply -f tests/k8st/infra/calicoctl.yaml

.PHONY: st-checks
st-checks:
	# Check that we're running as root.
	test `id -u` -eq '0' || { echo "STs must be run as root to allow writes to /proc"; false; }

	# Insert an iptables rule to allow access from our test containers to etcd
	# running on the host.
	iptables-save | grep -q 'calico-st-allow-etcd' || iptables $(IPT_ALLOW_ETCD)

.PHONY: k8s-test
## Run the k8s tests
k8s-test:
	$(MAKE) kind-k8st-setup
	$(MAKE) kind-k8st-run-test
	$(MAKE) kind-k8st-cleanup

.PHONY: kind-k8st-setup
kind-k8st-setup: $(K8ST_IMAGE_TARS) kind-cluster-create
	KUBECONFIG=$(KIND_KUBECONFIG) ./tests/k8st/deploy_resources_on_kind_cluster.sh

.PHONY: kind-k8st-run-test
kind-k8st-run-test: calico_test.created $(KIND_KUBECONFIG)
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
	     cd /code/tests/k8st && nosetests $(K8ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/k8s-tests.xml" --with-timer'

.PHONY: kind-k8st-cleanup
kind-k8st-cleanup: kind-cluster-destroy

# Needed for Semaphore CI (where disk space is a real issue during k8s-test)
.PHONY: remove-go-build-image
remove-go-build-image:
	@echo "Removing $(CALICO_BUILD) image to save space needed for testing ..."
	@-docker rmi $(CALICO_BUILD)

.PHONY: st
## Run the system tests
st: $(REMOTE_DEPS) image dist/calicoctl busybox.tar calico-node.tar workload.tar run-etcd calico_test.created dist/calico dist/calico-ipam
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	# $(MAKE) st-checks
	docker run --uts=host \
		   --pid=host \
		   --net=host \
		   --privileged \
		   -v $(CURDIR):/code \
		   -e HOST_CHECKOUT_DIR=$(CURDIR) \
		   -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
		   -e MY_IP=$(LOCAL_IP_ENV) \
		   -e NODE_CONTAINER_NAME=$(NODE_IMAGE):latest-$(ARCH) \
		   --rm -t \
		   -v /var/run/docker.sock:/var/run/docker.sock \
		   $(TEST_CONTAINER_NAME) \
		   sh -c 'nosetests $(ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks ut fv image build-windows-archive st

## Deploys images to registry
cd: cd-common cd-windows-upgrade

check-boring-ssl: $(NODE_CONTAINER_BIN_DIR)/calico-node-amd64
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		go tool nm $(NODE_CONTAINER_BIN_DIR)/calico-node-amd64 > $(NODE_CONTAINER_BIN_DIR)/tags.txt && grep '_Cfunc__goboringcrypto_' $(NODE_CONTAINER_BIN_DIR)/tags.txt 1> /dev/null
	-rm -f $(NODE_CONTAINER_BIN_DIR)/tags.txt

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
	$(MAKE) release-windows-upgrade-archive
	# Generate the Windows upgrade image tarballs (this must come after the
	# upgrade archive)
	$(MAKE) image-tar-windows-all
	touch $@

## Produces the Windows installation ZIP archive for the release.
release-windows-archive $(WINDOWS_ARCHIVE): release-prereqs
	$(MAKE) build-windows-archive WINDOWS_ARCHIVE_TAG=$(VERSION)

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(NODE_IMAGE):$(VERSION)-$(ARCH) versions | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(NODE_IMAGE):$(VERSION)-$(ARCH) versions` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	# Push node images.
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

	# Push Windows upgrade images.
	$(MAKE) cd-windows-upgrade RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

	# TODO: Update release tool to upload this to the correct location.
	# Update the release with the install-calico-windows.ps1 file too.
	# ghr -u projectcalico -r node \
	# 	-n $(VERSION) \
	# 	$(VERSION) $(WINDOWS_INSTALL_SCRIPT)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-verify
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

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
	wget -P $(WINDOWS_ARCHIVE_ROOT)/libs/hns/ $(MICROSOFT_SDN_GITHUB_RAW_URL)/Kubernetes/windows/hns.psm1

$(WINDOWS_ARCHIVE_ROOT)/libs/hns/License.txt:
	wget -P $(WINDOWS_ARCHIVE_ROOT)/libs/hns/ $(MICROSOFT_SDN_GITHUB_RAW_URL)/License.txt

## Download NSSM.
windows-packaging/nssm-$(WINDOWS_NSSM_VERSION).zip:
	wget -O windows-packaging/nssm-$(WINDOWS_NSSM_VERSION).zip https://nssm.cc/release/nssm-$(WINDOWS_NSSM_VERSION).zip

build-windows-archive: $(WINDOWS_ARCHIVE_FILES) windows-packaging/nssm-$(WINDOWS_NSSM_VERSION).zip
	# To be as atomic as possible, we re-do work like unpacking NSSM here.
	-rm -f "$(WINDOWS_ARCHIVE)"
	-rm -rf $(WINDOWS_ARCHIVE_ROOT)/nssm-$(WINDOWS_NSSM_VERSION)
	mkdir -p dist
	cd windows-packaging && \
	sha256sum --check nssm.sha256sum && \
	cd CalicoWindows && \
	unzip  ../nssm-$(WINDOWS_NSSM_VERSION).zip \
	       -x 'nssm-$(WINDOWS_NSSM_VERSION)/src/*' && \
	cd .. && \
	zip -r "../$(WINDOWS_ARCHIVE)" CalicoWindows -x '*.git*'
	@echo
	@echo "Windows archive built at $(WINDOWS_ARCHIVE)"

$(WINDOWS_ARCHIVE_BINARY): $(WINDOWS_BINARY)
	cp $< $@

# Ensure the upgrade image docker build folder exists.
$(WINDOWS_UPGRADE_BUILD):
	-mkdir -p $(WINDOWS_UPGRADE_BUILD)

# Ensure the directory for temporary files used to build the windows upgrade zip
# archive exists.
$(WINDOWS_UPGRADE_DIST_STAGE):
	-mkdir -p $(WINDOWS_UPGRADE_DIST_STAGE)

# Copy the upgrade script to the temporary directory where we build the windows
# upgrade zip file.
$(WINDOWS_UPGRADE_SCRIPT): $(WINDOWS_UPGRADE_DIST_STAGE)
	cp $(WINDOWS_UPGRADE_ROOT)/calico-upgrade.ps1 $@

# Copy the install zip archive to the temporary directory where we build the windows
# upgrade zip file.
$(WINDOWS_UPGRADE_INSTALL_ZIP): build-windows-archive $(WINDOWS_UPGRADE_DIST_STAGE)
	cp $(WINDOWS_ARCHIVE) $@

# Copy over the install-calico-windows.ps1 installation script.
$(WINDOWS_INSTALL_SCRIPT):
	-mkdir -p dist
	cp $(CURDIR)/../calico/scripts/install-calico-windows.ps1 $@

# Copy the install-calico-windows.ps1 script to the temporary directory where we
# build the windows upgrade zip file.
$(WINDOWS_UPGRADE_INSTALL_FILE): $(WINDOWS_UPGRADE_DIST_STAGE) $(WINDOWS_INSTALL_SCRIPT)
	cp $(WINDOWS_INSTALL_SCRIPT) $@

# Produces the Windows upgrade ZIP archive for the release.
release-windows-upgrade-archive: release-prereqs
	$(MAKE) build-windows-upgrade-archive WINDOWS_ARCHIVE_TAG=$(VERSION)

# Build the Windows upgrade zip archive.
build-windows-upgrade-archive: clean-windows-upgrade $(WINDOWS_UPGRADE_INSTALL_ZIP) $(WINDOWS_UPGRADE_INSTALL_FILE) $(WINDOWS_UPGRADE_SCRIPT) $(WINDOWS_UPGRADE_BUILD)
	rm $(WINDOWS_UPGRADE_ARCHIVE) || true
	cd $(WINDOWS_UPGRADE_DIST_STAGE) && zip -r "$(CURDIR)/$(WINDOWS_UPGRADE_ARCHIVE)" *.zip *.ps1

# Sets up the docker builder used to create Windows image tarballs.
setup-windows-builder:
	-docker buildx rm calico-windows-upgrade-builder
	docker buildx create --name=calico-windows-upgrade-builder --use --platform windows/amd64

# Builds all the Windows image tarballs for each version in WINDOWS_VERSIONS
image-tar-windows-all: setup-windows-builder $(addprefix sub-image-tar-windows-,$(WINDOWS_VERSIONS))

CRANE_BINDMOUNT_CMD := \
	docker run --rm \
		--net=host \
		--init \
		--entrypoint /bin/sh \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-v $(DOCKER_CONFIG):/root/.docker/config.json \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) -c $(double_quote)crane

DOCKER_MANIFEST_CMD := docker manifest

ifdef CONFIRM
CRANE_BINDMOUNT = $(CRANE_BINDMOUNT_CMD)
DOCKER_MANIFEST = $(DOCKER_MANIFEST_CMD)
else
CRANE_BINDMOUNT = echo [DRY RUN] $(CRANE_BINDMOUNT_CMD)
DOCKER_MANIFEST = echo [DRY RUN] $(DOCKER_MANIFEST_CMD)
endif

# Uses the docker builder to create a Windows image tarball for a single Windows
# version.
sub-image-tar-windows-%:
	-mkdir -p $(WINDOWS_UPGRADE_DIST)
	cd $(WINDOWS_UPGRADE_ROOT) && \
		docker buildx build \
			--platform windows/amd64 \
			--output=type=docker,dest=$(CURDIR)/$(WINDOWS_UPGRADE_DIST)/image-$(GIT_VERSION)-$*.tar \
			--pull \
			--no-cache \
			--build-arg=WINDOWS_VERSION=$* .

# The calico-windows-upgrade cd is different because we do not build docker images directly.
# Since the build machine is linux, we output the images to a tarball. (We can
# produce images but there will be no output because docker images
# built for Windows cannot be loaded on linux.)
#
# The resulting image tarball is then pushed to registries during cd/release.
# The image tarballs are located in dist/windows-upgrade and have files names
# with the format 'image-v3.21.0-2-abcdef-20H2.tar'.
#
# In addition to pushing the individual images, we also create the manifest
# directly using 'docker manifest'. This is possible because Semaphore is using
# a recent enough docker CLI version (20.10.0)
#
# - Create the manifest with 'docker manifest create' using the list of all images.
# - For each windows version, 'docker manifest annotate' its image with "os.image: <windows_version>".
#   <windows_version> is the version string that looks like, e.g. 10.0.19041.1288.
#   Setting os.image in the manifest is required for Windows hosts to load the
#   correct image in manifest.
# - Finally we push the manifest, "purging" the local manifest.
cd-windows-upgrade:
	for registry in $(DEV_REGISTRIES); do \
		echo Pushing Windows images to $${registry}; \
		all_images=""; \
		manifest_image="$${registry}/$(WINDOWS_UPGRADE_IMAGE):$(GIT_VERSION)"; \
		for win_ver in $(WINDOWS_VERSIONS); do \
			image_tar="$(WINDOWS_UPGRADE_DIST)/image-$(GIT_VERSION)-$${win_ver}.tar"; \
			image="$${registry}/$(WINDOWS_UPGRADE_IMAGE):$(GIT_VERSION)-windows-$${win_ver}"; \
			echo Pushing image $${image} ...; \
			$(CRANE_BINDMOUNT) push $${image_tar} $${image}$(double_quote) & \
			all_images="$${all_images} $${image}"; \
		done; \
		wait; \
		$(DOCKER_MANIFEST) create --amend $${manifest_image} $${all_images}; \
		for win_ver in $(WINDOWS_VERSIONS); do \
			version=$$(docker manifest inspect mcr.microsoft.com/windows/nanoserver:$${win_ver} | grep "os.version" | head -n 1 | awk -F\" '{print $$4}'); \
			image="$${registry}/$(WINDOWS_UPGRADE_IMAGE):$(GIT_VERSION)-windows-$${win_ver}"; \
			$(DOCKER_MANIFEST) annotate --os windows --arch amd64 --os-version $${version} $${manifest_image} $${image}; \
		done; \
		$(DOCKER_MANIFEST) push --purge $${manifest_image}; \
	done ;
