include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

# libbpf headers are needed because the e2e tests import felix/bpf packages
# that use CGO with libbpf.h.
LIBBPF_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl/libbpf/src
BPFGPL_CONTAINER_PATH=/go/src/github.com/projectcalico/calico/felix/bpf-gpl
LIBBPF_A=../felix/bpf-gpl/libbpf/src/$(ARCH)/libbpf.a
CGO_LDFLAGS="-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) -lbpf -lelf -lz"
CGO_CFLAGS="-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH)"
DOCKER_RUN_CGO=$(DOCKER_RUN) -e CGO_ENABLED=1 -e CGO_LDFLAGS=$(CGO_LDFLAGS) -e CGO_CFLAGS=$(CGO_CFLAGS)

$(LIBBPF_A):
	$(MAKE) -C ../felix libbpf

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

bin/k8s/e2e-linux-amd64.test: $(LIBBPF_A) $(SRC_FILES)
	mkdir -p bin/k8s
	$(DOCKER_RUN_CGO) $(CALICO_BUILD) go test ./cmd/k8s -c -o $@

bin/k8s/e2e-linux-%.test: $(SRC_FILES)
	mkdir -p bin/k8s
	$(MAKE) build-e2e-binary ARCH=$* OUTPUT=$@

.PHONY: build-e2e-binary
build-e2e-binary:
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/k8s -c -o $(OUTPUT)

.PHONY: build-all
build-all: $(addprefix bin/k8s/e2e-linux-,$(addsuffix .test,$(VALIDARCHES)))

###############################################################################
# test images
###############################################################################
test-images:
	$(MAKE) -C images/rapidclient image

publish-test-images: test-images
	$(MAKE) -C images/rapidclient publish

clean:
	rm -rf bin/
