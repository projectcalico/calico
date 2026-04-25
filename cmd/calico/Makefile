include ../../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/cmd/calico

CALICO_IMAGE ?= calico
BUILD_IMAGES ?= $(CALICO_IMAGE)

include ../../lib.Makefile

# Source files for the combined binary, derived from cmd/deps.txt.
SRC_FILES := $(call local-deps-go-files,cmd)

# Paths within the build container for BPF source (needed for CGO builds).
LIBBPF_CONTAINER_PATH = /go/src/github.com/projectcalico/calico/felix/bpf-gpl/libbpf/src/
BPFGPL_CONTAINER_PATH = /go/src/github.com/projectcalico/calico/felix/bpf-gpl/
LIBBPF_A = $(REPO_ROOT)/felix/bpf-gpl/libbpf/src/$(ARCH)/libbpf.a

ifeq ($(ARCH), $(filter $(ARCH),amd64 arm64))
# When cross-compiling, force lld as the linker — GNU ld is single-target,
# while lld natively links the cross-arch ELF objects produced by clang.
# (The cross sysroot itself is already supplied via CC's --sysroot flag.)
CROSS_CGO_LDFLAGS=
ifneq ($(CROSS_SYSROOT),)
	CROSS_CGO_LDFLAGS=$(CROSS_LDFLAGS)
endif
CGO_LDFLAGS = "-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) $(CROSS_CGO_LDFLAGS) -lbpf -lelf -lz"
CGO_CFLAGS = "-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH)"
endif

FIPS ?= false
ifeq ($(FIPS),true)
BINDIR = bin/$(ARCH)-fips
CONTAINER_MARKER = .image.created-$(ARCH)-fips
IMAGE_TAG = latest-fips
VALIDARCHES=amd64
else
BINDIR = bin
CONTAINER_MARKER = .image.created-$(ARCH)
IMAGE_TAG = latest
endif

.PHONY: clean
clean:
	rm -rf bin .image.created-*
	-docker image rm -f $$(docker images $(CALICO_IMAGE) -a -q) 2>/dev/null

.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c "CGO_ENABLED=0 go test -cover -count=1 ."

.PHONY: build build-cgo build-race
build: $(BINDIR)/calico-$(ARCH)
build-cgo: $(BINDIR)/calico-cgo-$(ARCH)
build-race: $(BINDIR)/calico-race-$(ARCH)

ifeq ($(FIPS),true)
# The FIPS binary is cgo-linked via build_cgo_boring_binary, so it needs libbpf
# available in the build container for transitive felix/bpf/libbpf imports.
$(BINDIR)/calico-$(ARCH): $(LIBBPF_A) $(SRC_FILES)
	$(call build_cgo_boring_binary, ./, $@)
else
$(BINDIR)/calico-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./, $@)
endif

# Cross-platform calicoctl artifacts. The combined binary's in-cluster
# components (felix, CNI, dataplane) are gated behind //go:build linux, so on
# darwin and windows the binary ships only the user-facing CLI commands
# (ctl, health, version). Naming matches the historical calicoctl release
# artifacts so users can keep their existing download URLs and scripts.
.PHONY: build-calicoctl
build-calicoctl: $(addprefix bin/calicoctl-linux-,$(VALIDARCHES)) bin/calicoctl-darwin-amd64 bin/calicoctl-darwin-arm64 bin/calicoctl-windows-amd64.exe

# On Linux the calicoctl artifact is the same binary as the in-cluster image,
# dispatched to the ctl subcommand by argv[0] basename matching.
bin/calicoctl-linux-%: $(SRC_FILES)
	$(MAKE) build ARCH=$*
	mkdir -p bin
	cp bin/calico-$* $@

# Per-target BUILDOS/ARCH for the cross-built binaries. The recipe re-invokes
# make so that BUILDOS and ARCH propagate as command-line variables into the
# DOCKER_RUN env (GOOS, GOARCH); target-specific vars don't reach the macro
# expansion otherwise.
bin/calicoctl-%-amd64: ARCH=amd64
bin/calicoctl-%-arm64: ARCH=arm64
bin/calicoctl-darwin-%: BUILDOS=darwin
bin/calicoctl-windows-%: BUILDOS=windows

bin/calicoctl-darwin-%: $(SRC_FILES)
	$(MAKE) build-cross-binary BUILDOS=$(BUILDOS) ARCH=$(ARCH) OUTPUT=$@

bin/calicoctl-windows-%: $(SRC_FILES)
	$(MAKE) build-cross-binary BUILDOS=$(BUILDOS) ARCH=$(ARCH) OUTPUT=$@

build-cross-binary:
	mkdir -p $(dir $(OUTPUT))
	$(call build_binary, ./, $(OUTPUT))

bin/calicoctl-windows-amd64.exe: bin/calicoctl-windows-amd64
	mv $< $@

$(BINDIR)/calico-cgo-$(ARCH): $(LIBBPF_A) $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./, $@)
else ifeq ($(ARCH),$(filter $(ARCH),amd64 arm64))
	$(call build_cgo_binary, ./, $@)
else
	$(call build_binary, ./, $@)
endif

# Race-enabled combined binary for Felix FV runs. The race detector requires
# CGO so we always build with CGO_ENABLED=1 and pull in libbpf the same way
# the cgo variant does.
$(BINDIR)/calico-race-$(ARCH): $(LIBBPF_A) $(SRC_FILES)
	mkdir -p $(BINDIR)
	$(DOCKER_RUN) \
		-e CGO_ENABLED=1 \
		$(if $(CROSS_CC),-e CC="$(CROSS_CC)") \
		-e CGO_CFLAGS=$(CGO_CFLAGS) \
		-e CGO_LDFLAGS=$(CGO_LDFLAGS) \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -race -o $@ -v -buildvcs=false -ldflags "$(LDFLAGS)" ./'

$(LIBBPF_A):
	$(MAKE) -C $(REPO_ROOT)/felix libbpf ARCH=$(ARCH)

$(BINDIR)/LICENSE: $(REPO_ROOT)/LICENSE.md
	mkdir -p $(BINDIR)
	cp $(REPO_ROOT)/LICENSE.md $@

REGISTRAR_BIN = $(REPO_ROOT)/pod2daemon/bin/node-driver-registrar-$(ARCH)
$(REGISTRAR_BIN):
	$(MAKE) -C $(REPO_ROOT)/pod2daemon bin/node-driver-registrar-$(ARCH)

.PHONY: image image-all
image: $(CONTAINER_MARKER)

$(CONTAINER_MARKER): $(REPO_ROOT)/docker/calico/Dockerfile $(BINDIR)/calico-$(ARCH) $(BINDIR)/LICENSE $(REGISTRAR_BIN) | register
	$(DOCKER_BUILD) --build-arg BIN_DIR=cmd/calico/$(BINDIR) --build-arg TARGETARCH=$(ARCH) -t $(CALICO_IMAGE):$(IMAGE_TAG)-$(ARCH) -f $(REPO_ROOT)/docker/calico/Dockerfile $(REPO_ROOT)
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(IMAGE_TAG) LATEST_IMAGE_TAG=$(IMAGE_TAG)
	touch $@

image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

###############################################################################
# CI/CD
###############################################################################
## Deploys images to registry
.PHONY: cd
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of the combined calico image at the specified version.
.PHONY: release-build
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)-fips LATEST_IMAGE_TAG=latest-fips
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

## Pushes the combined calico image to the registries.
.PHONY: release-publish
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - set VERSION=vX.Y.Z)
endif
