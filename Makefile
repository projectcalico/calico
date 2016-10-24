.PHONY: all test

BUILD_CONTAINER_NAME=calico/libcalico_test_container
BUILD_CONTAINER_MARKER=libcalico_test_container.created

GO_FILES:=$(shell find lib -name '*.go')

default: all
all: test
test: ut

## Use this to populate the vendor directory after checking out the repository.
## To update upstream dependencies, delete the glide.lock file first.
vendor: glide.lock
	glide install -strip-vendor -strip-vcs --cache

.PHONY: ut
## Run the UTs locally.  This requires a local etcd to be running.
ut: vendor
	./run-uts

.PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: run-etcd $(BUILD_CONTAINER_MARKER)
	docker run --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/projectcalico/libcalico-go:rw \
	$(BUILD_CONTAINER_NAME) bash -c 'make ut && chown $(shell id -u):$(shell id -g) -R ./vendor'

## Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/lint/golint
	go get -u github.com/onsi/ginkgo/ginkgo

## Run etcd as a container
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://127.0.0.1:2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

$(BUILD_CONTAINER_MARKER):
	docker build -f Dockerfile -t $(BUILD_CONTAINER_NAME) .
	touch $@

.PHONY: clean
clean:
	find . -name '*.coverprofile' -type f -delete
	rm -rf vendor
	-rm $(BUILD_CONTAINER_MARKER)

.PHONY: help
## Display this help text
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	$(info Available targets)
	@awk '/^[a-zA-Z\-\_0-9\/]+:/ {                                      \
		nb = sub( /^## /, "", helpMsg );                                \
		if(nb == 0) {                                                   \
			helpMsg = $$0;                                              \
			nb = sub( /^[^:]*:.* ## /, "", helpMsg );                   \
		}                                                               \
		if (nb)                                                         \
			printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg;  \
	}                                                                   \
	{ helpMsg = $$0 }'                                                  \
	width=20                                                            \
	$(MAKEFILE_LIST)