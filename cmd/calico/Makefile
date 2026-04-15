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
CGO_LDFLAGS = "-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) -lbpf -lelf -lz"
CGO_CFLAGS = "-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH)"
endif

FIPS ?= false
ifeq ($(FIPS),true)
BINDIR = bin/$(ARCH)-fips
CONTAINER_MARKER = .image.created-$(ARCH)-fips
else
BINDIR = bin
CONTAINER_MARKER = .image.created-$(ARCH)
endif

.PHONY: clean
clean:
	rm -rf bin .image.created-*
	-docker image rm -f $$(docker images $(CALICO_IMAGE) -a -q) 2>/dev/null

.PHONY: build build-cgo
build: $(BINDIR)/calico-$(ARCH)
build-cgo: $(BINDIR)/calico-cgo-$(ARCH)

$(BINDIR)/calico-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./, $@)
else
	$(call build_binary, ./, $@)
endif

$(BINDIR)/calico-cgo-$(ARCH): $(LIBBPF_A) $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./, $@)
else ifeq ($(ARCH),$(filter $(ARCH),amd64 arm64))
	$(call build_cgo_binary, ./, $@)
else
	$(call build_binary, ./, $@)
endif

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

$(CONTAINER_MARKER): $(REPO_ROOT)/docker/calico/Dockerfile $(BINDIR)/calico-$(ARCH) $(BINDIR)/LICENSE $(REGISTRAR_BIN)
	$(DOCKER_BUILD) --build-arg BIN_DIR=cmd/calico/$(BINDIR) --build-arg TARGETARCH=$(ARCH) -t $(CALICO_IMAGE):latest-$(ARCH) -f $(REPO_ROOT)/docker/calico/Dockerfile $(REPO_ROOT)
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*
