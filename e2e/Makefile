include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

SRC_FILES=$(shell find pkg cmd -name '*.go')
build: bin/k8s/e2e.test bin/clusternetworkpolicy/e2e.test $(SRC_FILES)
bin/k8s/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/k8s -c -o $@

bin/clusternetworkpolicy/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/clusternetworkpolicy -c -o $@

###############################################################################
# test images
###############################################################################
test-images:
	$(MAKE) -C images/rapidclient image

publish-test-images: test-images
	$(MAKE) -C images/rapidclient publish

clean:
	rm -rf bin/

