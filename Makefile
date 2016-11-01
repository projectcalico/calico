.PHONY: all binary calico/node calico/ctl test ssl-certs node_image ctl_image

default: help
all: test                                     ## Run all the tests
binary: dist/calicoctl                        ## Create the calicoctl binary
calico/node: calico_node/.calico_node.created ## Create the calico/node image
calico/ctl: calicoctl/.calico_ctl.created     ## Create the calico/ctl image
test: ut                                      ## Run all the tests
ssl-certs: certs/.certificates.created        ## Generate self-signed SSL certificates

node_image: calico/node
ctl_image: calico/ctl

###############################################################################
# Common build variables
# Path to the sources.
# Default value: directory with Makefile
SOURCE_DIR?=$(dir $(lastword $(MAKEFILE_LIST)))
SOURCE_DIR:=$(abspath $(SOURCE_DIR))
###############################################################################
# URL for Calico binaries
# confd binary
CONFD_URL?=https://github.com/projectcalico/confd/releases/download/v0.10.0-scale/confd.static
# bird binaries
BIRD_URL?=https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/bird
BIRD6_URL?=https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/bird6
BIRDCL_URL?=https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/birdcl
CALICO_BGP_DAEMON_URL?=https://github.com/projectcalico/calico-bgp-daemon/releases/download/v0.1.0/calico-bgp-daemon
GOBGP_URL?=https://github.com/projectcalico/calico-bgp-daemon/releases/download/v0.1.0/gobgp

# we can use "custom" build image name
BUILD_CONTAINER_NAME?=calico/build:latest
###############################################################################
# calico/node build. Contains the following areas
# - Populate the calico_node/filesystem
# - Build the container itself
###############################################################################
NODE_CONTAINER_DIR=calico_node
NODE_CONTAINER_NAME?=calico/node:latest
NODE_CONTAINER_FILES=$(shell find $(NODE_CONTAINER_DIR)/filesystem/{etc,sbin} -type f)
NODE_CONTAINER_CREATED=$(NODE_CONTAINER_DIR)/.calico_node.created
NODE_CONTAINER_BIN_DIR=$(NODE_CONTAINER_DIR)/filesystem/bin
NODE_CONTAINER_BINARIES=startup allocate-ipip-addr calico-felix bird calico-bgp-daemon confd
FELIX_CONTAINER_NAME?=calico/felix:go

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker save --output $@ $(NODE_CONTAINER_NAME)

# Build ACI (the APPC image file format) of calico/node.
# Requires docker2aci installed on host: https://github.com/appc/docker2aci
calico-node-latest.aci: calico-node.tar
	docker2aci $<

# Build calico/node docker image
$(NODE_CONTAINER_CREATED): $(NODE_CONTAINER_DIR)/Dockerfile  $(addprefix $(NODE_CONTAINER_BIN_DIR)/,$(NODE_CONTAINER_BINARIES))
	docker build -t $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_DIR)
	touch $@

# Build binary from python files, e.g. startup.py or allocate-ipip-addr.py
$(NODE_CONTAINER_BIN_DIR)/%: $(NODE_CONTAINER_DIR)/%.py
	-docker run -v $(SOURCE_DIR):/code --rm \
	 $(BUILD_CONTAINER_NAME) \
	 sh -c 'pyinstaller -ayF --distpath $(@D) $< && chown $(shell id -u):$(shell id -g) -R $(@D)'

# Get felix binaries
$(NODE_CONTAINER_BIN_DIR)/calico-felix:
	-docker rm -f calico-felix
	# Latest felix binaries are stored in automated builds of calico/felix.
	# To get them, we pull that image, then copy the binaries out to our host
	docker create --name calico-felix $(FELIX_CONTAINER_NAME)
	docker cp calico-felix:/code/. $(@D)
	-docker rm -f calico-felix

# Get the confd binary
$(NODE_CONTAINER_BIN_DIR)/confd:
	curl -L $(CONFD_URL) -o $@
	chmod +x $@

# Get the calico-bgp-daemon binary
$(NODE_CONTAINER_BIN_DIR)/calico-bgp-daemon:
	curl -L $(CALICO_BGP_DAEMON_URL) -o $@
	chmod +x $@

# Get bird binaries
$(NODE_CONTAINER_BIN_DIR)/bird:
	# This make target actually downloads the bird6 and birdcl binaries too
	# Copy patched BIRD daemon with tunnel support.
	curl -L $(BIRD_URL) -o $@
	curl -L $(BIRD6_URL) -o $(@D)/bird6
	curl -L $(BIRDCL_URL) -o $(@D)/birdcl
	chmod +x $(@D)/*

clean_calico_node:
	# Building the node relies on a few upstream images.
	# Retag and remove them so that they will be pulled again
	# We avoid just deleting the image. We didn't build it here so it would be impolite to delete it.
	-docker tag $(FELIX_CONTAINER_NAME) $(FELIX_CONTAINER_NAME)-backup && docker rmi $(FELIX_CONTAINER_NAME)
	-docker tag $(BUILD_CONTAINER_NAME) $(BUILD_CONTAINER_NAME)-backup && docker rmi $(BUILD_CONTAINER_NAME)
	rm -rf $(NODE_CONTAINER_BIN_DIR)

###############################################################################
# calicoctl build
# - Building the calicoctl binary in a container
# - Building the calicoctl binary outside a container ("simple-binary")
# - Building the calico/ctl image
###############################################################################
CALICOCTL_DIR=calicoctl
CTL_CONTAINER_NAME?=calico/ctl:latest
CALICOCTL_FILE=$(CALICOCTL_DIR)/calicoctl.py $(wildcard $(CALICOCTL_DIR)/calico_ctl/*.py) calicoctl.spec
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created

LDFLAGS=-ldflags "-X github.com/projectcalico/calico-containers/calicoctl/commands.VERSION=$(CALICOCTL_VERSION) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands.BUILD_DATE=$(CALICOCTL_BUILD_DATE) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) -s -w"

BUILD_CONTAINER_NAME=calico/calicoctl_build_container
BUILD_CONTAINER_MARKER=calicoctl_build_container.created

GO_FILES:=$(shell find calicoctl -name '*.go')

CALICOCTL_VERSION?=$(shell git describe --tags --dirty --always)
CALICOCTL_BUILD_DATE?=$(shell date -u +'%FT%T%z')
CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)


.PHONY: vendor
## Use this to populate the vendor directory after checking out the repository.
## To update upstream dependencies, delete the glide.lock file first.
vendor vendor/.up-to-date: glide.lock
	rm -f vendor/.up-to-date
	glide install -strip-vendor -strip-vcs --cache
	touch vendor/.up-to-date

## Build the calicoctl binary locally.
bin/calicoctl: vendor/.up-to-date $(GO_FILES)
	mkdir -p bin
	go build -o "$@" $(LDFLAGS) "./calicoctl/calicoctl.go"

.PHONY: release/calicoctl
## Build the release calicoctl binary in a Centos 6 container
release/calicoctl: clean
	mkdir -p bin release
	docker build -f Dockerfile.calicoctl.release -t calicoctl-build .
	docker run --rm --privileged --net=host \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-containers:rw \
	-v ${PWD}/bin:/go/src/github.com/projectcalico/calico-containers/bin:rw \
	-w /go/src/github.com/projectcalico/calico-containers \
	calicoctl-build make bin/calicoctl
	mv bin/calicoctl release/calicoctl
	rm -rf bin
	mv release/calicoctl release/calicoctl-$(CALICOCTL_VERSION)
	cd release && ln -sf calicoctl-$(CALICOCTL_VERSION) calicoctl

## Build calicoctl in a container.
build-containerized: $(BUILD_CONTAINER_MARKER)
	mkdir -p dist
	docker run --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-containers:rw \
	-v ${PWD}/dist:/go/src/github.com/projectcalico/calico-containers/dist:rw \
	$(BUILD_CONTAINER_NAME) bash -c 'make bin/calicoctl; \
	chown $(shell id -u):$(shell id -g) -R ./vendor ./dist'


$(BUILD_CONTAINER_MARKER): Dockerfile.calicoctl.build
	docker build -f Dockerfile.calicoctl.build -t $(BUILD_CONTAINER_NAME) .
	touch $@

.PHONY: update-tools
## Install or update the tools used by the build
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/lint/golint
	go get -u github.com/onsi/ginkgo/ginkgo

###############################################################################
# Tests
# - Support for running etcd (both securely and insecurely)
# - Running UTs
###############################################################################
.PHONY: ut
## Run the Unit Tests locally
ut: bin/calicoctl
	./run-uts

.PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: run-etcd $(BUILD_CONTAINER_MARKER)
	docker run -ti --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/projectcalico/calico-containers:rw \
	$(BUILD_CONTAINER_NAME) bash -c 'make ut; \
	chown $(shell id -u):$(shell id -g) -R ./vendor'

## Generate the keys and certificates for running etcd with SSL.
certs/.certificates.created:
	mkdir -p certs
	curl -L "https://github.com/projectcalico/cfssl/releases/download/1.2.1/cfssl" -o certs/cfssl
	curl -L "https://github.com/projectcalico/cfssl/releases/download/1.2.1/cfssljson" -o certs/cfssljson
	chmod a+x certs/cfssl
	chmod a+x certs/cfssljson

	certs/cfssl gencert -initca tests/st/ssl-config/ca-csr.json | certs/cfssljson -bare certs/ca
	certs/cfssl gencert \
	  -ca certs/ca.pem \
	  -ca-key certs/ca-key.pem \
	  -config tests/st/ssl-config/ca-config.json \
	  tests/st/ssl-config/req-csr.json | certs/cfssljson -bare certs/client
	certs/cfssl gencert \
	  -ca certs/ca.pem \
	  -ca-key certs/ca-key.pem \
	  -config tests/st/ssl-config/ca-config.json \
	  tests/st/ssl-config/req-csr.json | certs/cfssljson -bare certs/server

	touch certs/.certificates.created

.PHONY: run-etcd
## Run etcd in a container. Used by the tests and generally useful.
run-etcd:
	$(MAKE) stop-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379" \
	--listen-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379"

.PHONY: run-etcd-ssl
## Run etcd in a container with SSL verification. Used primarily by tests.
run-etcd-ssl: certs/.certificates.created add-ssl-hostname
	$(MAKE) stop-etcd
	docker run --detach \
	--net=host \
	-v $(SOURCE_DIR)/certs:/etc/calico/certs \
	--name calico-etcd-ssl quay.io/coreos/etcd:v2.3.6 \
	--cert-file "/etc/calico/certs/server.pem" \
	--key-file "/etc/calico/certs/server-key.pem" \
	--ca-file "/etc/calico/certs/ca.pem" \
	--advertise-client-urls "https://etcd-authority-ssl:2379,https://localhost:2379" \
	--listen-client-urls "https://0.0.0.0:2379"

.PHONY: stop-etcd
stop-etcd:
	@-docker rm -f calico-etcd calico-etcd-ssl

.PHONY: add-ssl-hostname
add-ssl-hostname:
	# Set "LOCAL_IP etcd-authority-ssl" in /etc/hosts to use as a hostname for etcd with ssl
	if ! grep -q "etcd-authority-ssl" /etc/hosts; then \
	  echo "\n# Host used by Calico's ETCD with SSL\n$(LOCAL_IP_ENV) etcd-authority-ssl" >> /etc/hosts; \
	fi

.PHONY: clean
## Clean everything (including stray volumes)
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.coverprofile' -type f -delete
	-rm -rf bin
	-rm -rf release
	-rm -rf vendor
	-rm -rf certs
	-rm -f *.tar
	-docker rm -f calico-node
	-docker rmi $(NODE_CONTAINER_NAME)
	-docker rmi $(CTL_CONTAINER_NAME)
	-docker tag calico/test:latest calico/test:latest-backup && docker rmi calico/test:latest
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes
	-rm -rf $(NODE_CONTAINER_DIR)/bin
	-rm -rf $(CALICOCTL_DIR)/calicoctl

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
