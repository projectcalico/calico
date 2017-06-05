
# Disable make's implicit rules, which are not useful for golang, and slow down the build
# considerably.
.SUFFIXES:

all: bin/confd

ETCDCTL_VER=v3.1.8

GO_BUILD_CONTAINER?=calico/go-build:v0.4
K8S_VERSION=1.6.4
TEST_CONTAINER=heschlie/confd-test
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')

# All go files.
GO_FILES:=$(shell find . -type f -name '*.go')

# Figure out the users UID.  This is needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
MY_UID:=$(shell id -u)

DOCKER_GO_BUILD := mkdir -p .go-pkg-cache && \
                   docker run --rm \
                              --net=host \
                              $(EXTRA_DOCKER_ARGS) \
                              -e LOCAL_USER_ID=$(MY_UID) \
                              -v ${CURDIR}:/go/src/github.com/kelseyhightower/confd:rw \
                              -v ${CURDIR}/.go-pkg-cache:/go/pkg:rw \
                              -w /go/src/github.com/kelseyhightower/confd \
                              $(GO_BUILD_CONTAINER)

# Update the vendored dependencies with the latest upstream versions matching
# our glide.yaml.  If there are any changes, this updates glide.lock
# as a side effect.  Unless you're adding/updating a dependency, you probably
# want to use the vendor target to install the versions from glide.lock.
.PHONY: update-vendor
update-vendor:
	mkdir -p $$HOME/.glide
	$(DOCKER_GO_BUILD) glide up --strip-vendor
	touch vendor/.up-to-date

# vendor is a shortcut for force rebuilding the go vendor directory.
.PHONY: vendor
vendor vendor/.up-to-date: glide.lock
	mkdir -p $$HOME/.glide
	$(DOCKER_GO_BUILD) glide install --strip-vendor
	touch vendor/.up-to-date

bin/confd: $(GO_FILES) vendor/.up-to-date
	@echo Building confd...
	mkdir -p bin
	$(DOCKER_GO_BUILD) \
	    sh -c 'go build -v -i -o $@ "github.com/kelseyhightower/confd" && \
               ( ldd bin/confd 2>&1 | grep -q "Not a valid dynamic program" || \
	             ( echo "Error: bin/confd was not statically linked"; false ) )'

.PHONY: test
## Run all tests
test: test-kdd test-etcd

.PHONY: test-kdd
## Run template tests against KDD
test-kdd: bin/confd fetch-bins run-etcd-host run-k8s-apiserver
	docker run --rm --net=host \
	    -v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-e LOCAL_USER_ID=0 \
		$(GO_BUILD_CONTAINER) /tests/test_kdd.sh

.PHONY: test-etcd
## Run template tests against etcd
test-etcd: bin/confd fetch-bins run-etcd-host run-k8s-apiserver
	docker run --rm --net=host \
	    -v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-e LOCAL_USER_ID=0 \
		$(GO_BUILD_CONTAINER) /tests/test_etcd.sh

## Etcd is used by the kubernetes
run-etcd-host: stop-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Stops calico-etcd containers
stop-etcd:
	@-docker rm -f calico-etcd

## Kubernetes apiserver used for tests
run-k8s-apiserver: stop-k8s-apiserver
	docker run --detach --net=host \
	  --name calico-k8s-apiserver \
  	gcr.io/google_containers/hyperkube-amd64:v$(K8S_VERSION) \
		  /hyperkube apiserver --etcd-servers=http://$(LOCAL_IP_ENV):2379 \
		  --service-cluster-ip-range=10.101.0.0/16 

## Stop Kubernetes apiserver
stop-k8s-apiserver:
	@-docker rm -f calico-k8s-apiserver

.PHONY: fetch-bins
## Fetch our binary files for testing
fetch-bins: bin/kubectl bin/bird bin/bird6 bin/etcdctl

bin/kubectl bin/bird bin/bird6 bin/etcdctl:
	mkdir -p bin/ tmp/
	wget -q https://storage.googleapis.com/kubernetes-release/release/v1.6.4/bin/linux/amd64/kubectl -O bin/kubectl
	wget -q https://github.com/projectcalico/bird/releases/download/v0.3.1/bird -O bin/bird
	wget -q https://github.com/projectcalico/bird/releases/download/v0.3.1/bird6 -O bin/bird6
	wget -q https://github.com/coreos/etcd/releases/download/v3.1.8/etcd-$(ETCDCTL_VER)-linux-amd64.tar.gz -O tmp/etcd-$(ETCDCTL_VER)-linux-amd64.tar.gz
	tar -zxvf tmp/etcd-$(ETCDCTL_VER)-linux-amd64.tar.gz --strip=1 -C bin/ etcd-$(ETCDCTL_VER)-linux-amd64/etcdctl
	rm tmp/etcd-$(ETCDCTL_VER)-linux-amd64.tar.gz
	chmod +x bin/kubectl bin/bird bin/bird6 bin/etcdctl

.PHONY: clean
clean:
	rm -rf bin/ tmp/
