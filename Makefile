SRCFILES=calico.go $(wildcard utils/*.go) $(wildcard k8s/*.go) ipam/calico-ipam.go
TEST_SRCFILES=$(wildcard test_utils/*.go) $(wildcard calico_cni_*.go)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)

K8S_VERSION=1.3.1
CALICO_NODE_VERSION=0.20.0

CALICO_CNI_VERSION?=$(shell git describe --tags --dirty)

# Ensure that the dist directory is always created
MAKE_SURE_DIST_EXIST := $(shell mkdir -p dist)

BUILD_CONTAINER_NAME=calico/cni_build_container
BUILD_CONTAINER_MARKER=cni_build_container.created
DEPLOY_CONTAINER_NAME=calico/cni
DEPLOY_CONTAINER_MARKER=cni_deploy_container.created

.PHONY: all binary plugin ipam
default: all
all: vendor build-containerized test-containerized
binary:  plugin ipam
plugin: dist/calico
ipam: dist/calico-ipam
docker-image: $(DEPLOY_CONTAINER_MARKER)

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
	-ldflags "-X main.VERSION=$(CALICO_CNI_VERSION)" calico.go;

# Build the Calico ipam plugin
dist/calico-ipam: $(SRCFILES) vendor
	CGO_ENABLED=0 go build -v -o dist/calico-ipam  \
	-ldflags "-X main.VERSION=$(CALICO_CNI_VERSION)" ipam/calico-ipam.go;

.PHONY: test
# Run the unit tests.
test: dist/calico dist/calico-ipam dist/calicoctl dist/host-local run-etcd
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo)

# Run the unit tests, watching for changes.
test-watch: dist/calico dist/calico-ipam
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo) watch

$(BUILD_CONTAINER_MARKER): Dockerfile.build
	docker build -f Dockerfile.build -t $(BUILD_CONTAINER_NAME) .
	touch $@

$(DEPLOY_CONTAINER_MARKER): Dockerfile build-containerized
	docker build -f Dockerfile -t $(DEPLOY_CONTAINER_NAME) .
	touch $@

# Run the tests in a container. Useful for CI
.PHONY: test-containerized
test-containerized: dist/host-local dist/calicoctl run-etcd $(BUILD_CONTAINER_MARKER) build-containerized
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
	-p 2379:2379 \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

# Etcd is used by the kubernetes
run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

# Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/lint/golint
	go get -u github.com/onsi/ginkgo/ginkgo

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
deploy-rkt: binary
	cp dist/calico /etc/rkt/net.d
	cp dist/calico-ipam /etc/rkt/net.d
	echo '{"name": "prod","log_level":"warning","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"host-local","subnet": "10.10.0.0/8"}}' >/etc/rkt/net.d/calico-warning.conf
	echo '{"name": "mtu","mtu":999,"type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"host-local","subnet": "10.10.0.0/8"}}' >/etc/rkt/net.d/calico-mtu.conf
	echo '{"name": "dev", "log_level":"info","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"calico-ipam"}}' >/etc/rkt/net.d/calico-info.conf
	echo '{"name": "debug", "log_level":"debug","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"calico-ipam"}}' >/etc/rkt/net.d/calico-debug.conf
	echo '{"name": "ipv6", "log_level":"info","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"calico-ipam", "assign_ipv6":"true"}}' >/etc/rkt/net.d/calico-ipv6.conf
	echo '{"name": "secure", "log_level":"debug","type":"calico","etcd_endpoints":"https://etcd-authority-ssl:2379","etcd_key_file":"/etc/calico/client-key.pem","etcd_cert_file":"/etc/calico/client.pem","etcd_ca_cert_file":"/etc/calico/ca.pem", "ipam":{"type":"calico-ipam"}}' >/etc/rkt/net.d/calico-secure.conf
	@echo ""
	@echo Now create containers using rkt e.g.
	@echo sudo rkt run quay.io/coreos/alpine-sh --exec ifconfig --net=prod
	@echo sudo rkt run quay.io/coreos/alpine-sh --exec ifconfig --net=dev
	@echo sudo rkt run quay.io/coreos/alpine-sh --exec ifconfig --net=prod --net=dev

# Build a binary for a release
release: clean update-tools build-containerized test-containerized
	docker build -f Dockerfile -t $(DEPLOY_CONTAINER_NAME):$(CALICO_CNI_VERSION) .
	docker tag calico/cni:$(CALICO_CNI_VERSION) quay.io/calico/cni:$(CALICO_CNI_VERSION)
	@echo Now attach the binaries to github dist/calico and dist/calico-ipam
	@echo And push the images to Docker Hub and quay.io:
	@echo docker push calico/cni:$(CALICO_CNI_VERSION)
	@echo docker push quay.io/calico/cni:$(CALICO_CNI_VERSION)

run-kubernetes-master: stop-kubernetes-master run-etcd-host binary dist/calicoctl
	echo Get kubectl from http://storage.googleapis.com/kubernetes-release/release/v$(K8S_VERSION)/bin/linux/amd64/kubectl
	mkdir -p net.d
	#echo '{"name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
	#echo '{"log_level":"DEBUG", "name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "10.101.0.0/16"}}' >net.d/10-calico.conf
	#echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s", "k8s_api_root":"https://${LOCAL_IP_ENV}:6443", "k8s_auth_token":"ga4LHIvii6eKAOhCiHprzJQG3vEduAFJ"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"k8s_insecure_skip_tls_verify":true,"type": "k8s", "k8s_api_root":"https://10.7.50.75:6443", "k8s_auth_token":"YcFKOZdGR2c1XagRzhT6E5dHjNlbzmO9"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
#	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"k8s_insecure_skip_tls_verify":true,"type": "k8s", "k8s_api_root":"https://10.7.50.75:6443", "k8s_username":"admin", "k8s_password":"admin"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf

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

	# Remove any left over volumes
	-docker volume ls -qf dangling=true | xargs -r docker volume rm
	-mount |grep kubelet | awk '{print $$3}' |sudo xargs umount

run-kube-proxy:
	-docker rm -f calico-kube-proxy
	docker run --name calico-kube-proxy -d --net=host --privileged gcr.io/google_containers/hyperkube:v$(K8S_VERSION) /hyperkube proxy --master=http://127.0.0.1:8080 --v=2
