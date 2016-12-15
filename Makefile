SRCFILES=calico.go $(wildcard utils/*.go) $(wildcard k8s/*.go) ipam/calico-ipam.go
TEST_SRCFILES=$(wildcard test_utils/*.go) $(wildcard calico_cni_*.go)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')

# fail if unable to download
CURL=curl -sSf

K8S_VERSION=1.3.1

CALICO_CNI_VERSION?=$(shell git describe --tags --dirty)

# Ensure that the dist directory is always created
MAKE_SURE_DIST_EXIST := $(shell mkdir -p dist)

GO_CONTAINER_NAME?=dockerepo/glide
BUILD_CONTAINER_NAME=calico/cni_build_container
BUILD_CONTAINER_MARKER=cni_build_container.created
DEPLOY_CONTAINER_NAME=calico/cni
DEPLOY_CONTAINER_MARKER=cni_deploy_container.created

LIBCALICOGO_PATH?=none

.PHONY: all binary plugin ipam
default: all
all: vendor build-containerized test-containerized
binary:  plugin ipam
plugin: dist/calico
ipam: dist/calico-ipam
docker-image: $(DEPLOY_CONTAINER_MARKER)

.PHONY: clean
clean:
	rm -rf dist vendor $(BUILD_CONTAINER_MARKER) $(DEPLOY_CONTAINER_MARKER)

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)
	$(MAKE) build-containerized $(DEPLOY_CONTAINER_MARKER)
	# Check that the version output appears on a line of its own (the -x option to grep).
# Tests that the "git tag" makes it into the binary. Main point is to catch "-dirty" builds
	@echo "Checking if the tag made it into the binary"
	docker run --rm $(DEPLOY_CONTAINER_NAME) calico -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm $(DEPLOY_CONTAINER_NAME) calico -v` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm $(DEPLOY_CONTAINER_NAME) calico-ipam -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm $(DEPLOY_CONTAINER_NAME) calico-ipam -v | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )
	docker tag $(DEPLOY_CONTAINER_NAME) $(DEPLOY_CONTAINER_NAME):$(VERSION)
	docker tag $(DEPLOY_CONTAINER_NAME) quay.io/$(DEPLOY_CONTAINER_NAME):$(VERSION)
	docker tag $(DEPLOY_CONTAINER_NAME) quay.io/$(DEPLOY_CONTAINER_NAME):latest

	@echo "Now push the tag and images. Then create a release on Github and attach the dist/calico and dist/calico-ipam binaries"
	@echo "git push origin $(VERSION)"
	@echo "docker push calico/cni:$(VERSION)"
	@echo "docker push quay.io/calico/cni:$(VERSION)"
	@echo "docker push calico/cni:latest"
	@echo "docker push quay.io/calico/cni:latest"


# Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor: glide.yaml
	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
	docker run --rm \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-cni:rw $$EXTRA_DOCKER_BIND \
      --entrypoint /bin/sh $(GO_CONTAINER_NAME) -e -c ' \
	cd /go/src/github.com/projectcalico/calico-cni && \
	glide install -strip-vendor && \
	chown $(shell id -u):$(shell id -u) -R vendor'

# Build the Calico network plugin
dist/calico: $(SRCFILES) vendor
	mkdir -p $(@D)
	CGO_ENABLED=0 go build -v -o dist/calico \
	-ldflags "-X main.VERSION=$(CALICO_CNI_VERSION) -s -w" calico.go

# Build the Calico ipam plugin
dist/calico-ipam: $(SRCFILES) vendor
	mkdir -p $(@D)
	CGO_ENABLED=0 go build -v -o dist/calico-ipam  \
	-ldflags "-X main.VERSION=$(CALICO_CNI_VERSION) -s -w" ipam/calico-ipam.go

.PHONY: test
# Run the unit tests.
test: dist/calico dist/calico-ipam dist/host-local run-etcd
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo)

# Run the unit tests, watching for changes.
test-watch: dist/calico dist/calico-ipam
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo) watch

$(BUILD_CONTAINER_MARKER): Dockerfile.build fetch-cni-bins
	docker build -f Dockerfile.build -t $(BUILD_CONTAINER_NAME) .
	touch $@

$(DEPLOY_CONTAINER_MARKER): Dockerfile build-containerized fetch-cni-bins
	docker build -f Dockerfile -t $(DEPLOY_CONTAINER_NAME) .
	touch $@

.PHONY: fetch-cni-bins
fetch-cni-bins:
	mkdir -p dist
	mkdir -p tmp-cni
	$(CURL) -L --retry 5 https://github.com/containernetworking/cni/releases/download/v0.3.0/cni-v0.3.0.tgz | tar -xz -C tmp-cni/
	mv tmp-cni/flannel dist/flannel
	mv tmp-cni/loopback dist/loopback
	mv tmp-cni/host-local dist/host-local
	rm -rf tmp-cni/

# Run the tests in a container. Useful for CI
.PHONY: test-containerized
test-containerized: run-etcd build-containerized
	docker run --rm --privileged --net=host \
	-e ETCD_IP=$(LOCAL_IP_ENV) \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-cni:rw \
	$(BUILD_CONTAINER_NAME) /bin/sh -e -c \
        'make dist/host-local && ginkgo && chown $(shell id -u):$(shell id -u) -R dist'
	make stop-etcd

# Run the build in a container. Useful for CI
.PHONY: build-containerized
build-containerized: $(BUILD_CONTAINER_MARKER) vendor
	mkdir -p dist
	docker run --rm \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-cni:ro \
	-v ${PWD}/dist:/go/src/github.com/projectcalico/calico-cni/dist \
	$(BUILD_CONTAINER_NAME) bash -c '\
		make binary && \
		chown -R $(shell id -u):$(shell id -u) dist'

# Etcd is used by the tests
run-etcd: stop-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd quay.io/coreos/etcd \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

# Etcd is used by the kubernetes
run-etcd-host: stop-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

stop-etcd:
	@-docker rm -f calico-etcd

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


static-checks-containerized: vendor $(BUILD_CONTAINER_MARKER)
	docker run --rm \
        -v ${PWD}:/go/src/github.com/projectcalico/calico-cni:rw \
        --entrypoint /bin/sh $(BUILD_CONTAINER_NAME) -e -c ' \
        cd /go/src/github.com/projectcalico/calico-cni && \
        make update-tools static-checks'

install:
	CGO_ENABLED=0 go install github.com/projectcalico/calico-cni

# Retrieve a host-local plugin for use in the tests
dist/host-local:
	mkdir -p $(@D)
	$(CURL) -L https://github.com/containernetworking/cni/releases/download/v0.2.2/cni-v0.2.2.tgz | tar -zxv -C dist

# Retrieve an old version of the Python CNI plugin for use in tests
dist/calico-python:
	$(CURL) -L https://github.com/projectcalico/calico-cni/releases/download/v1.3.1/calico -o $@
	chmod +x $@

# Retrieve an old version of the Python CNI plugin for use in tests
dist/calico-ipam-python:
	$(CURL) -L https://github.com/projectcalico/calico-cni/releases/download/v1.3.1/calico-ipam -o $@
	chmod +x $@

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

run-kubernetes-master: stop-kubernetes-master run-etcd-host binary 
	echo Get kubectl from http://storage.googleapis.com/kubernetes-release/release/v$(K8S_VERSION)/bin/linux/amd64/kubectl
	mkdir -p net.d
	#echo '{"name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
	#echo '{"log_level":"DEBUG", "name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "10.101.0.0/16"}}' >net.d/10-calico.conf
	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1", "kubeconfig":"/etc/cni/net.d/kubeconfig"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
#	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"k8s_insecure_skip_tls_verify":true,"type": "k8s", "k8s_api_root":"https://10.7.50.75:6443", "k8s_auth_token":"YcFKOZdGR2c1XagRzhT6E5dHjNlbzmO9"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
#	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"k8s_insecure_skip_tls_verify":true,"type": "k8s", "k8s_api_root":"https://10.7.50.75:6443", "k8s_username":"admin", "k8s_password":"admin"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
	#echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "ipam": {"type": "host-local", "subnet": "10.13.0.0/16"}}' >net.d/10-calico.conf

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

	@echo "Now manually start a calico-node container"

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

ci: clean static-checks-containerized test-containerized docker-image
# Assumes that a few environment variables exist - BRANCH_NAME PULL_REQUEST_NUMBER
	set -e; \
	if [ -z $$PULL_REQUEST_NUMBER ]; then \
		docker tag calico/cni calico/cni:$$BRANCH_NAME && docker push calico/cni:$$BRANCH_NAME; \
		docker tag calico/cni quay.io/calico/cni:$$BRANCH_NAME && docker push quay.io/calico/cni:$$BRANCH_NAME; \
		if [ "$$BRANCH_NAME" = "master" ]; then \
			export VERSION=`git describe --tags --dirty`; \
			docker tag calico/cni calico/cni:$$VERSION && docker push calico/cni:$$VERSION; \
			docker tag calico/cni quay.io/calico/cni:$$VERSION && docker push quay.io/calico/cni:$$VERSION; \
		fi; \
	fi


