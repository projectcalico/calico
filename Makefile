.PHONY: all test

BUILD_CONTAINER_NAME=calico/libcalico_test_container
BUILD_CONTAINER_MARKER=libcalico_test_container.created

K8S_VERSION=1.4.5

GO_FILES:=$(shell find lib -name '*.go')

default: all
all: test
test: ut

## Use this to populate the vendor directory after checking out the repository.
## To update upstream dependencies, delete the glide.lock file first.
vendor: 
	glide install -strip-vendor -strip-vcs --cache

.PHONY: ut
## Run the UTs locally.  This requires a local etcd to be running.
ut: vendor
	./run-uts

.PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: $(BUILD_CONTAINER_MARKER) run-kubernetes-master 
	docker run --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/projectcalico/libcalico-go:rw \
	$(BUILD_CONTAINER_NAME) bash -c 'make WHAT=$(WHAT) ut && chown $(shell id -u):$(shell id -g) -R ./vendor'

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

run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

run-kubernetes-master: stop-kubernetes-master run-etcd-host
	# Run the kubelet which will launch the master components in a pod.
	docker run \
                -v /:/rootfs:ro \
	        -v /sys:/sys:ro \
	        -v /var/run:/var/run:rw \
	        -v /var/lib/kubelet/:/var/lib/kubelet:rw \
	        -v ${PWD}/kubernetes-manifests:/etc/kubernetes/manifests-multi:rw \
	        --net=host \
		--pid=host \
		--privileged=true \
		--name calico-kubelet-master \
		-d \
		gcr.io/google_containers/hyperkube-amd64:v${K8S_VERSION} \
		/hyperkube kubelet \
			--containerized \
			--hostname-override="127.0.0.1" \
			--address="0.0.0.0" \
			--api-servers=http://localhost:8080 \
			--config=/etc/kubernetes/manifests-multi \
			--cluster-dns=10.0.0.10 \
			--cluster-domain=cluster.local \
			--allow-privileged=true --v=2

stop-kubernetes-master:
	# Stop any existing kubelet that we started
	-docker rm -f calico-kubelet-master

	# Remove any pods that the old kubelet may have started.
	-docker rm -f $$(docker ps | grep k8s_ | awk '{print $$1}')

	# Remove any left over volumes
	-docker volume ls -qf dangling=true | xargs docker volume rm
	-mount |grep kubelet | awk '{print $$3}' |xargs umount

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
