SRCFILES=calico.go $(wildcard utils/*.go) $(wildcard k8s/*.go) ipam/calico-ipam.go
TEST_SRCFILES=$(wildcard test_utils/*.go) $(wildcard calico_cni_*.go)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)

K8S_VERSION=1.3.1
CALICO_NODE_VERSION=0.20.0

# Ensure that the dist directory is always created
MAKE_SURE_DIST_EXIST := $(shell mkdir -p dist)

BUILD_CONTAINER_NAME=calico/cni_build_container
BUILD_CONTAINER_MARKER=cni_build_container.created

.PHONY: all binary plugin ipam
default: all
all: vendor build-containerized test-containerized
binary:  plugin ipam
plugin: dist/calico
ipam: dist/calico-ipam

.PHONY: clean
clean:
	rm -rf dist vendor

# Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor:
	glide install -strip-vcs -strip-vendor --cache

# Build the Calico network plugin
dist/calico: $(SRCFILES) vendor
	CGO_ENABLED=0 go build -v -o dist/calico \
	-ldflags "-X main.VERSION=$(shell git describe --tags --dirty)" calico.go;

# Build the Calico ipam plugin
dist/calico-ipam: $(SRCFILES) vendor
	CGO_ENABLED=0 go build -v -o dist/calico-ipam  \
	-ldflags "-X main.VERSION=$(shell git describe --tags --dirty)" ipam/calico-ipam.go;

.PHONY: test
# Run the unit tests.
test: dist/calico dist/calico-ipam run-etcd
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo)

# Run the unit tests, watching for changes.
test-watch: dist/calico dist/calico-ipam
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo) watch

$(BUILD_CONTAINER_MARKER): Dockerfile.build
	docker build -f Dockerfile.build -t $(BUILD_CONTAINER_NAME) .
	touch $(BUILD_CONTAINER_MARKER)

# Run the tests in a container. Useful for CI
.PHONY: test-containerized
test-containerized: dist/host-local run-etcd $(BUILD_CONTAINER_MARKER) build-containerized
	docker run -ti --rm --privileged --net=host \
	-e ETCD_IP=$(LOCAL_IP_ENV) \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-cni:ro \
	$(BUILD_CONTAINER_NAME) ginkgo

# Run the build in a container. Useful for CI
.PHONY: build-containerized
build-containerized: $(BUILD_CONTAINER_MARKER) vendor
	mkdir -p dist
	docker run --rm \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-cni:ro \
	-v ${PWD}/dist:/go/src/github.com/projectcalico/calico-cni/dist \
	$(BUILD_CONTAINER_NAME) bash -c '\
		make binary; \
		chown -R $(shell id -u):$(shell id -u) dist'

# Etcd is used by the tests
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

# Install or update the tools needed for the static checks.
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/lint/golint

# Perform static checks on the code. The golint checks are allowed to fail, the others must pass.
.PHONY: static-checks
static-checks: vendor
	# Format the code and clean up imports
	goimports -w *.go utils/*.go ipam/*.go test_utils/*.go

	# Check for coding mistake and missing error handling
	go vet -x $(glide nv)
	errcheck . ./ipam/... ./utils/...

	# Check code style
	-golint calico.go
	-golint utils
	-golint ipam

install:
	CGO_ENABLED=0 go install github.com/projectcalico/calico-cni

# Retrieve a host-local plugin for use in the tests
dist/host-local:
	mkdir -p dist
	curl -L https://github.com/containernetworking/cni/releases/download/v0.2.2/cni-v0.2.2.tgz | tar -zxv -C dist

# Retrieve an old version of the Python CNI plugin for use in tests
dist/calico-python:
	curl -L -o dist/calico-python https://github.com/projectcalico/calico-cni/releases/download/v1.3.1/calico
	chmod +x dist/calico-python

# Retrieve an old version of the Python CNI plugin for use in tests
dist/calico-ipam-python:
	curl -L -o $@ https://github.com/projectcalico/calico-cni/releases/download/v1.3.1/calico-ipam
	chmod +x $@

# Retrieve calicoctl for use in tests
dist/calicoctl:
	curl -o dist/calicoctl -L https://github.com/projectcalico/calico-containers/releases/download/v$(CALICO_NODE_VERSION)/calicoctl
	chmod +x dist/calicoctl

# Copy the plugin into place
deploy-rkt: dist/calico
	cp dist/calico /etc/rkt/net.d

run-kubernetes-master: stop-kubernetes-master run-etcd binary dist/calicoctl
	echo Get kubectl from http://storage.googleapis.com/kubernetes-release/release/v$(K8S_VERSION)/bin/linux/amd64/kubectl
	mkdir -p net.d
	#echo '{"name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "podCidr"}}' >net.d/10-calico.conf
	echo '{"debug":true, "name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "10.101.0.0/16"}}' >net.d/10-calico.conf
	# Run the kubelet which will launch the master components in a pod.
	docker run \
		--volume=/:/rootfs:ro \
		--volume=/sys:/sys:ro \
		--volume=/var/lib/docker/:/var/lib/docker:rw \
		--volume=/var/lib/kubelet/:/var/lib/kubelet:rw \
		--volume=`pwd`/dist:/opt/cni/bin \
		--volume=`pwd`/net.d:/etc/cni/net.d \
		--volume=/var/run:/var/run:rw \
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
			--network-plugin=cni \
			--network-plugin-dir=/etc/cni/net.d \
			--cluster-domain=cluster.local \
			--allow-privileged=true --v=2

	# Start the Calico node
	sudo dist/calicoctl node

stop-kubernetes-master:
	# Stop any existing kubelet that we started
	-docker rm -f calico-kubelet-master

	# Remove any pods that the old kubelet may have started.
	-docker rm -f $$(docker ps | grep k8s_ | awk '{print $$1}')

run-kube-proxy:
	-docker rm -f calico-kube-proxy
	docker run --name calico-kube-proxy -d --net=host --privileged gcr.io/google_containers/hyperkube:v$(K8S_VERSION) /hyperkube proxy --master=http://127.0.0.1:8080 --v=2
