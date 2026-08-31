include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

# libbpf headers are needed because the e2e tests import felix/bpf packages
# that use CGO with libbpf.h. These flags mirror felix/Makefile, which links the
# same static libbpf.a.
LIBBPF_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/libbpf/src
BPFGPL_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl
LIBBPF_A=../felix/bpf-gpl/libbpf/src/$(ARCH)/libbpf.a

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
# CROSS_CC points the C compiler at the target arch. Without it the host
# compiler would try to assemble the target's runtime/cgo assembly and fail.
DOCKER_RUN_CGO=$(DOCKER_RUN) -e CGO_ENABLED=1 $(if $(CROSS_CC),-e CC="$(CROSS_CC)") -e CGO_LDFLAGS=$(CGO_LDFLAGS) -e CGO_CFLAGS=$(CGO_CFLAGS)

$(LIBBPF_A): $(shell find ../felix/bpf-gpl/libbpf -type f -name '*.[ch]')
	$(MAKE) -C ../felix libbpf ARCH=$(ARCH)

SRC_FILES=$(shell find pkg cmd -name '*.go')

###############################################################################
# Build e2e test binaries
###############################################################################

build: bin/k8s/e2e.test bin/clusternetworkpolicy/e2e.test bin/gateway/e2e.test $(SRC_FILES)

bin/k8s/e2e.test: bin/k8s/e2e-linux-$(ARCH).test
	mv $< $@

bin/clusternetworkpolicy/e2e.test: $(LIBBPF_A) $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN_CGO) $(CALICO_BUILD) go test ./cmd/clusternetworkpolicy -c -o $@

bin/gateway/e2e.test: $(SRC_FILES)
	mkdir -p bin/gateway
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/gateway -c -o $@

# Per-arch e2e binary, cross-compiled inside the calico/go-build container. CGO
# stays on for every arch: the tests pull in felix/bpf, which falls back to stubs
# that panic when CGO is off, so keeping it on means every arch links the same
# libbpf-backed code and behaves the same.
bin/k8s/e2e-linux-$(ARCH).test: $(LIBBPF_A) $(SRC_FILES)
	mkdir -p bin/k8s
	$(DOCKER_RUN_CGO) $(CALICO_BUILD) go test ./cmd/k8s -c -o $@

.PHONY: build-all
build-all: $(addprefix sub-build-,$(VALIDARCHES))

# ARCH has to be set on the command line of a fresh make rather than per-target:
# lib.Makefile computes the cross-toolchain variables (CROSS_CC, CROSS_SYSROOT)
# with := at parse time from ARCH.
sub-build-%:
	$(MAKE) bin/k8s/e2e-linux-$*.test ARCH=$*

###############################################################################
# UTs
###############################################################################
ci: ut

# Only pkg carries unit tests; cmd holds the Ginkgo suites that need a cluster.
ut: $(LIBBPF_A)
	mkdir -p report
	$(DOCKER_RUN_CGO) $(CALICO_BUILD) gotestsum --junitfile report/e2e_ut.xml -- ./pkg/... -race -count 1

fv st:
	@:

###############################################################################
# Test sets
###############################################################################
# testsets/ records the specs each CI lane selects, so a selection change shows
# up as a reviewable diff.
.PHONY: gen-test-set
gen-test-set: bin/k8s/e2e.test
	$(DOCKER_RUN) $(CALICO_BUILD) go run ./cmd/gen-test-set -repo-root .. -binary e2e/bin/k8s/e2e.test -out e2e/testsets

.PHONY: check-test-set
check-test-set: gen-test-set
	@test -z "$$(git status --porcelain testsets)" || \
		( echo "e2e/testsets is out of date; run 'make -C e2e gen-test-set' and commit the result" && false )

###############################################################################
# test images
###############################################################################
# test-images builds a local single-arch image for development (kind etc.).
test-images:
	$(MAKE) -C images/rapidclient image

# publish does its own multi-arch buildx build+push, so it must NOT depend on the
# single-arch test-images target (that build would be wasted work).
publish-test-images:
	$(MAKE) -C images/rapidclient publish

clean:
	rm -rf bin/ report/
