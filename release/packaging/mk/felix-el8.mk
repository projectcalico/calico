# The calico-felix binary that every package ships, built against EL 8's glibc.
#
# calico/go-build links against glibc 2.34.  EL 8 has 2.28 and Ubuntu 20.04 has
# 2.31, so a binary from go-build cannot run on either: the RPM's generated
# `Requires: libc.so.6(GLIBC_2.34)` is unsatisfiable, and the .deb installs and
# then fails to start.  So we rebuild libbpf.a and the cgo binary in the el8
# build image, whose glibc is the oldest of every platform we package for, and
# ship that one binary everywhere.
#
# The BPF programs are kernel bytecode built by clang, so they are unaffected by
# glibc and are reused from felix's normal `build-bpf` as-is.
#
# This mirrors node/Makefile.rhel8 in calico-private, which does the same thing
# for calico-node's RHEL 8 RPM.  Delete this file, and the line that includes it,
# once every platform we package for has glibc >= what go-build links against.

FELIX_EL8_DIR        := $(OUTPUT_DIR)/felix-el8
FELIX_EL8_BINARY     := $(FELIX_EL8_DIR)/bin/calico-felix
FELIX_EL8_LIBBPF_DIR := $(FELIX_EL8_DIR)/libbpf/$(ARCH)
FELIX_EL8_LIBBPF_A   := $(FELIX_EL8_LIBBPF_DIR)/libbpf.a

# The repo is mounted where the Go module path expects it, exactly as
# calico/go-build does, so that `go build` and libbpf's Makefile see the paths
# they are used to.  in_container maps a path under the repo to its path inside.
CODE_IN_CONTAINER := /go/src/github.com/projectcalico/calico
in_container       = $(CODE_IN_CONTAINER)/$(patsubst $(REPO_ROOT)/%,%,$(1))

# Felix's own build flags, asked of felix's makefile rather than copied into
# this one, so that the packaged binary carries the same buildinfo stamps as
# every other build of it and cannot drift from them.
felix_make_var = $(shell $(MAKE) -C $(DIR_felix) --no-print-directory \
                     --eval='print-%: ; @echo $$($$*)' print-$(1) 2>/dev/null)
FELIX_LDFLAGS  = $(call felix_make_var,LDFLAGS)
GOMOD_CACHE   ?= $(if $(GOPATH),$(firstword $(subst :, ,$(GOPATH))),$(HOME)/go)/pkg/mod

# Run a Go build in the el8 image as the invoking user.  HOME is /tmp because
# that uid has no passwd entry inside the container and Go insists on writing
# somewhere; the module and build caches are shared with the repo's normal
# builds so that this does not re-download the module graph every time.
DOCKER_EL8_GO_RUN = mkdir -p $(REPO_ROOT)/.go-pkg-cache $(GOMOD_CACHE) && \
	docker run --rm --init --user $(DOCKER_USER) \
	    -e HOME=/tmp \
	    -e GOCACHE=/go-cache \
	    -v $(REPO_ROOT):$(CODE_IN_CONTAINER):rw \
	    -v $(REPO_ROOT)/.go-pkg-cache:/go-cache:rw \
	    -v $(GOMOD_CACHE):/go/pkg/mod:rw \
	    -w $(CODE_IN_CONTAINER)/felix

# libbpf, rebuilt here so that the archive we link into the binary does not
# itself refer to a newer glibc.  It goes under output/ rather than into
# felix/bpf-gpl/libbpf/src/$(ARCH)/, so that felix's own build state - which a
# developer or another build may be relying on - is left alone.
#
# Like the prepare stamps, this is built once per output/ tree rather than
# tracking libbpf's sources: `make clean` is what forces it to be rebuilt.
$(FELIX_EL8_LIBBPF_A): | $(STAMP_DIR) images-rhel-el8 check-rpm-build-tools
	$(MAKE) -C $(DIR_felix) clone-libbpf
	mkdir -p $(@D)
	$(DOCKER_EL8_GO_RUN) calico-build/el8 \
	    make -j$(shell nproc) -C bpf-gpl/libbpf/src \
	        BUILD_STATIC_ONLY=1 EXTRA_CFLAGS=-fPIC \
	        OBJDIR=$(call in_container,$(FELIX_EL8_LIBBPF_DIR))

$(FELIX_EL8_BINARY): $(FELIX_EL8_LIBBPF_A) | $(STAMP_DIR) images-rhel-el8
	mkdir -p $(@D)
	$(DOCKER_EL8_GO_RUN) \
	    -e CGO_ENABLED=1 \
	    -e CGO_CFLAGS="-I$(call in_container,$(DIR_felix))/bpf-gpl/libbpf/src -I$(call in_container,$(DIR_felix))/bpf-gpl" \
	    -e CGO_LDFLAGS="-L$(call in_container,$(FELIX_EL8_LIBBPF_DIR)) -lbpf -lelf -lz" \
	    calico-build/el8 \
	    go build -o $(call in_container,$@) -v -buildvcs=false \
	        -ldflags "$(FELIX_LDFLAGS)" \
	        github.com/projectcalico/calico/felix/cmd/calico-felix

# Felix's prepare step: the EL 8 binary, plus the BPF programs, which come from
# felix's normal build in the usual container because clang output does not care
# about glibc.
$(STAMP_DIR)/prepare-felix: $(FELIX_EL8_BINARY) | $(STAMP_DIR)
	$(MAKE) -C $(DIR_felix) build-bpf
	touch $@

# Handy on its own: `make felix-binary` then `ldd -r output/felix-el8/bin/calico-felix`.
.PHONY: felix-binary
felix-binary: $(FELIX_EL8_BINARY)
