include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

SRC_FILES=$(shell find pkg cmd -name '*.go')

###############################################################################
# Build e2e test binaries
###############################################################################

build: bin/k8s/e2e.test bin/clusternetworkpolicy/e2e.test $(SRC_FILES)

bin/k8s/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/k8s -c -o $@

bin/clusternetworkpolicy/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/clusternetworkpolicy -c -o $@

# Multi-arch e2e binary targets. Each architecture gets its own binary, built
# via cross-compilation inside the calico/go-build container.
bin/k8s/e2e-linux-amd64.test: $(SRC_FILES)
	mkdir -p bin/k8s
	$(MAKE) build-e2e-binary ARCH=amd64

bin/k8s/e2e-linux-arm64.test: $(SRC_FILES)
	mkdir -p bin/k8s
	$(MAKE) build-e2e-binary ARCH=arm64

.PHONY: build-e2e-binary
build-e2e-binary:
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/k8s -c -o bin/k8s/e2e-linux-$(ARCH).test

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

