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
# via cross-compilation inside the calico/go-build container. Uses a pattern
# rule so that any arch in VALIDARCHES (including ppc64le, s390x) works.
# The recursive make sets ARCH so that DOCKER_RUN passes the correct GOARCH.
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

