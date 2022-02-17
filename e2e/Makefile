include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e
include ../lib.Makefile

SRC_FILES = $(shell find . -name "*.go")

build: bin/e2e.test 
bin/e2e.test: $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./cmd -c -o $@

clean:
	rm -rf bin/
