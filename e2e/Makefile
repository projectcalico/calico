include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

SRC_FILES=$(shell find pkg cmd -name '*.go')
build: bin/k8s/e2e.test bin/clusternetworkpolicy/e2e.test $(SRC_FILES)

bin/k8s/e2e.test: bin/k8s/e2e-linux-$(ARCH).test
	mv $< $@

bin/clusternetworkpolicy/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/clusternetworkpolicy -c -o $@

# Per-arch e2e binary, cross-compiled inside the calico/go-build container.
bin/k8s/e2e-linux-$(ARCH).test: $(SRC_FILES)
	mkdir -p bin/k8s
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/k8s -c -o $@

.PHONY: build-all
build-all: $(addprefix sub-build-,$(VALIDARCHES))

# ARCH has to be set on a fresh make command line rather than per-target, since
# lib.Makefile computes the arch-dependent build variables with := at parse time.
sub-build-%:
	$(MAKE) bin/k8s/e2e-linux-$*.test ARCH=$*

###############################################################################
# test images
###############################################################################
test-images:
	$(MAKE) -C images/rapidclient image

publish-test-images: test-images
	$(MAKE) -C images/rapidclient publish

clean:
	rm -rf bin/

