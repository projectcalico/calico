.PHONEY: all test ut update-vendor

BUILD_CONTAINER_NAME=calico/calicoctl_build_container
BUILD_CONTAINER_MARKER=calicoctl_build_container.created

default: all
all: test
test: ut

# Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor:
	glide install -strip-vendor -strip-vcs --cache

ut: bin/calicoctl
	./run-uts

.PHONEY: force
force:
	true

bin/calicoctl: vendor 
	mkdir -p bin
	go build -o "$@" "./calicoctl/calicoctl.go"

release/calicoctl: vendor force
	mkdir -p release
	cd build-calicoctl && docker build -t calicoctl-build .
	docker run --rm -v `pwd`:/libcalico-go calicoctl-build /libcalico-go/build-calicoctl/build.sh

# Build calicoctl in a container.
build-containerized: $(BUILD_CONTAINER_MARKER)
	mkdir -p dist
	docker run -ti --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/tigera/libcalico-go:rw \
	-v ${PWD}/dist:/go/src/github.com/tigera/libcalico-go/dist:rw \
	$(BUILD_CONTAINER_NAME) make bin/calicoctl

# Run the tests in a container. Useful for CI, Mac dev.
.PHONY: test-containerized
test-containerized: $(BUILD_CONTAINER_MARKER)
	docker run -ti --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/tigera/libcalico-go:rw \
	$(BUILD_CONTAINER_NAME) make ut
	
$(BUILD_CONTAINER_MARKER): Dockerfile.build
	docker build -f Dockerfile.build -t $(BUILD_CONTAINER_NAME) .
	touch $@

# Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/lint/golint
	go get -u github.com/onsi/ginkgo/ginkgo

# Etcd is used by the tests
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://127.0.0.1:2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"
