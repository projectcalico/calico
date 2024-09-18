include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

build: bin/k8s/e2e.test bin/adminpolicy/e2e.test
bin/k8s/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/k8s -c -o $@

bin/adminpolicy/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd/adminpolicy -c -o $@

clean:
	rm -rf bin/
