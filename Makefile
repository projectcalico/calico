.PHONY: all binary calico/node test ut ut-circle st st-ssl clean run-etcd run-etcd-ssl help clean_calico_node
default: help
all: test                                 ## Run all the tests
test: st test-containerized               ## Run all the tests
ssl-certs: certs/.certificates.created    ## Generate self-signed SSL certificates
all: dist/calicoctl test-containerized

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
BUILD_CONTAINER_NAME?=calico/build:v0.18.0
###############################################################################
# calico/node build. Contains the following areas
# - Populate the calico_node/filesystem
# - Build the container itself
###############################################################################
NODE_CONTAINER_DIR=calico_node
NODE_CONTAINER_NAME?=calico/node:$(CALICOCONTAINERS_VERSION)
NODE_CONTAINER_FILES=$(shell find $(NODE_CONTAINER_DIR)/filesystem -type f)
# we can pass --build-arg during node image building
NODE_CONTAINER_BUILD_ARGS?=
NODE_CONTAINER_CREATED=$(NODE_CONTAINER_DIR)/.calico_node.created
NODE_CONTAINER_BIN_DIR=$(NODE_CONTAINER_DIR)/filesystem/bin
NODE_CONTAINER_BINARIES=startup allocate-ipip-addr calico-felix bird calico-bgp-daemon confd libnetwork-plugin
FELIX_CONTAINER_NAME?=calico/felix:2.0.0-beta.3
LIBNETWORK_PLUGIN_CONTAINER_NAME?=calico/libnetwork-plugin:v1.0.0-beta-rc2

calico/node: $(NODE_CONTAINER_CREATED)    ## Create the calico/node image

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker save --output $@ $(NODE_CONTAINER_NAME)

# Build ACI (the APPC image file format) of calico/node.
# Requires docker2aci installed on host: https://github.com/appc/docker2aci
calico-node-latest.aci: calico-node.tar
	docker2aci $<

# Build calico/node docker image - explicitly depend on the container binaries.
$(NODE_CONTAINER_CREATED): $(NODE_CONTAINER_DIR)/Dockerfile $(NODE_CONTAINER_FILES) $(addprefix $(NODE_CONTAINER_BIN_DIR)/,$(NODE_CONTAINER_BINARIES))
	docker build $(NODE_CONTAINER_BUILD_ARGS) -t $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_DIR)
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

# Get libnetwork-plugin binaries
$(NODE_CONTAINER_BIN_DIR)/libnetwork-plugin:
	-docker rm -f calico-$(@F)
	# Latest libnetwork-plugin binaries are stored in automated builds of calico/libnetwork-plugin.
	# To get them, we pull that image, then copy the binaries out to our host
	docker create --name calico-$(@F) $(LIBNETWORK_PLUGIN_CONTAINER_NAME)
	docker cp calico-$(@F):/$(@F) $(@D)
	-docker rm -f calico-$(@F)

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
# Tests
# - Support for running etcd (both securely and insecurely)
# - Running UTs and STs
###############################################################################
# These variables can be overridden by setting an environment variable.
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
ST_TO_RUN?=tests/st/
UT_TO_RUN?=tests/unit/

# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=
HOST_CHECKOUT_DIR?=$(shell pwd)

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

busybox.tar:
	docker pull busybox:latest
	docker save --output busybox.tar busybox:latest

routereflector.tar:
	docker pull calico/routereflector:latest
	docker save --output routereflector.tar calico/routereflector:latest

## Run etcd in a container. Used by the STs and generally useful.
run-etcd-st:
	$(MAKE) stop-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379" \
	--listen-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379"

stop-etcd:
	@-docker rm -f calico-etcd calico-etcd-ssl

## Run etcd in a container with SSL verification. Used primarily by STs.
run-etcd-ssl: certs/.certificates.created add-ssl-hostname
	$(MAKE) stop-etcd
	docker run --detach \
	--net=host \
	-v $(SOURCE_DIR)/certs:/etc/calico/certs \
	--name calico-etcd-ssl quay.io/coreos/etcd \
	etcd \
	--cert-file "/etc/calico/certs/server.pem" \
	--key-file "/etc/calico/certs/server-key.pem" \
	--trusted-ca-file "/etc/calico/certs/ca.pem" \
	--advertise-client-urls "https://etcd-authority-ssl:2379,https://localhost:2379" \
	--listen-client-urls "https://0.0.0.0:2379"

IPT_ALLOW_ETCD:=-A INPUT -i docker0 -p tcp --dport 2379 -m comment --comment "calico-st-allow-etcd" -j ACCEPT

.PHONY: st-checks
st-checks:
	# Check that we're running as root.
	test `id -u` -eq '0' || { echo "STs must be run as root to allow writes to /proc"; false; }

	# Insert an iptables rule to allow access from our test containers to etcd
	# running on the host.
	iptables-save | grep -q 'calico-st-allow-etcd' || iptables $(IPT_ALLOW_ETCD)

## Run the STs in a container
.PHONY: st
st: dist/calicoctl busybox.tar routereflector.tar calico-node.tar #run-etcd-st
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	#$(MAKE) st-checks
	#docker run --uts=host \
	#           --pid=host \
	#           --net=host \
	#           --privileged \
	#           -e HOST_CHECKOUT_DIR=$(HOST_CHECKOUT_DIR) \
	#           -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
	#           -e MY_IP=$(LOCAL_IP_ENV) \
	#           --rm -ti \
	#           -v /var/run/docker.sock:/var/run/docker.sock \
	#           -v $(SOURCE_DIR):/code \
	#           calico/test \
	#           sh -c 'cp -ra tests/st/* /tests/st && cd / && nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)'
	#$(MAKE) stop-etcd
	echo "No STs to run at the moment"

## Run the STs in a container using etcd with SSL certificate/key/CA verification.
.PHONY: st-ssl
st-ssl: run-etcd-ssl dist/calicoctl busybox.tar calico-node.tar routereflector.tar
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	# Mount the full path to the etcd certs directory.
	#   - docker copies this directory directly from the host, but the
	#     calicoctl node command reads the files from the test container
	$(MAKE) st-checks
	docker run --uts=host \
	           --pid=host \
	           --net=host \
	           --privileged \
	           -e HOST_CHECKOUT_DIR=$(HOST_CHECKOUT_DIR) \
	           -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           -e ETCD_SCHEME=https \
	           -e ETCD_CA_CERT_FILE=$(SOURCE_DIR)/certs/ca.pem \
	           -e ETCD_CERT_FILE=$(SOURCE_DIR)/certs/client.pem \
	           -e ETCD_KEY_FILE=$(SOURCE_DIR)/certs/client-key.pem \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v $(SOURCE_DIR):/code \
	           -v $(SOURCE_DIR)/certs:$(SOURCE_DIR)/certs \
	           calico/test \
	           sh -c 'cp -ra tests/st/* /tests/st && cd / && nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

.PHONY: add-ssl-hostname
add-ssl-hostname:
	# Set "LOCAL_IP etcd-authority-ssl" in /etc/hosts to use as a hostname for etcd with ssl
	if ! grep -q "etcd-authority-ssl" /etc/hosts; then \
	  echo "\n# Host used by Calico's ETCD with SSL\n$(LOCAL_IP_ENV) etcd-authority-ssl" >> /etc/hosts; \
	fi

# This depends on clean to ensure that dependent images get untagged and repulled
.PHONY: semaphore
semaphore: clean
	# Clean up unwanted files to free disk space.
	bash -c 'rm -rf /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv}'

	# Actually run the tests (refreshing the images as required)
	make st

	bash -c 'if [ -z "$$PULL_REQUEST_NUMBER" ]; then \
		docker push $(NODE_CONTAINER_NAME) && \
		docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME) && \
		docker push quay.io/$(NODE_CONTAINER_NAME); \
	fi'

###############################################################################
# calicoctl UTs
###############################################################################
.PHONY: ut
## Run the Unit Tests locally
ut: dist/calicoctl
	# Run tests in random order find tests recursively (-r).
	ginkgo -cover -r --skipPackage vendor

	@echo
	@echo '+==============+'
	@echo '| All coverage |'
	@echo '+==============+'
	@echo
	@find . -iname '*.coverprofile' | xargs -I _ go tool cover -func=_

	@echo
	@echo '+==================+'
	@echo '| Missing coverage |'
	@echo '+==================+'
	@echo
	@find . -iname '*.coverprofile' | xargs -I _ go tool cover -func=_ | grep -v '100.0%'

PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: dist/calicoctl
	docker run --rm -v ${PWD}:/go/src/github.com/projectcalico/calico-containers:rw \
	$(BUILD_CALICOCTL_CONTAINER_NAME) bash -c 'make ut'

###############################################################################
# calicoctl build
# - Building the calicoctl binary in a container
# - Building the calicoctl binary outside a container ("simple-binary")
# - Building the calico/ctl image
###############################################################################
CALICOCTL_DIR=calicoctl
CTL_CONTAINER_NAME?=calico/ctl:latest
CALICOCTL_FILES=$(shell find $(CALICOCTL_DIR) -name '*.go')
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created

CALICOCONTAINERS_VERSION?=$(shell git describe --tags --dirty --always)
CALICOCTL_BUILD_DATE?=$(shell date -u +'%FT%T%z')
CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)

LDFLAGS=-ldflags "-X github.com/projectcalico/calico-containers/calicoctl/commands.VERSION=$(CALICOCONTAINERS_VERSION) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands/node.VERSION=$(CALICOCONTAINERS_VERSION) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands.BUILD_DATE=$(CALICOCTL_BUILD_DATE) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) -s -w"

GO_CONTAINER_NAME?=dockerepo/glide
BUILD_CALICOCTL_CONTAINER_NAME=calico/calicoctl_build_container
BUILD_CALICOCTL_CONTAINER_MARKER=calicoctl_build_container.created

LIBCALICOGO_PATH?=none

calico/ctl: $(CTL_CONTAINER_CREATED)      ## Create the calico/ctl image

## Use this to populate the vendor directory after checking out the repository.
## To update upstream dependencies, delete the glide.lock file first.
vendor:
	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
	docker run --rm -v ${PWD}:/go/src/github.com/projectcalico/calico-containers:rw $$EXTRA_DOCKER_BIND \
      --entrypoint /bin/sh $(GO_CONTAINER_NAME) -e -c ' \
	    cd /go/src/github.com/projectcalico/calico-containers && \
	    glide install -strip-vendor && \
	    chown $(shell id -u):$(shell id -u) -R vendor'

## Build the calicoctl
binary: $(CALICOCTL_FILES) vendor
	CGO_ENABLED=0 go build -v -o dist/calicoctl $(LDFLAGS) "./calicoctl/calicoctl.go"

$(BUILD_CALICOCTL_CONTAINER_MARKER): Dockerfile.calicoctl.build
	docker build -f Dockerfile.calicoctl.build -t $(BUILD_CALICOCTL_CONTAINER_NAME) .
	touch $@

# build calico_ctl image
$(CTL_CONTAINER_CREATED): Dockerfile.calicoctl dist/calicoctl
	docker build -t $(CTL_CONTAINER_NAME) -f Dockerfile.calicoctl .
	touch $@

## Run the build in a container. Useful for CI
dist/calicoctl: $(BUILD_CALICOCTL_CONTAINER_MARKER) vendor
	mkdir -p dist
	docker run --rm \
	  -v ${PWD}:/go/src/github.com/projectcalico/calico-containers:ro \
	  -v ${PWD}/dist:/go/src/github.com/projectcalico/calico-containers/dist \
	  $(BUILD_CALICOCTL_CONTAINER_NAME) bash -c '\
	    make binary && \
		chown -R $(shell id -u):$(shell id -u) dist'

## Etcd is used by the tests
.PHONY: run-etcd
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Etcd is used by the STs
.PHONY: run-etcd-host
run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	go get -u github.com/golang/lint/golint
	go get -u github.com/onsi/ginkgo/ginkgo

## Perform static checks on the code. The golint checks are allowed to fail, the others must pass.
.PHONY: static-checks
static-checks: vendor
	# Format the code and clean up imports
	goimports -w $(CALICOCTL_FILES)

	# Check for coding mistake and missing error handling
	go vet -x $(glide nv)
	errcheck ./calicoctl

	# Check code style
	-golint $(CALICOCTL_FILES)

.PHONY: install
install:
	CGO_ENABLED=0 go install github.com/projectcalico/calico-containers/calicoctl

## Build a binary for a release
release-calicoctl: clean update-tools dist/calicoctl test-containerized
	docker tag calico/calicoctl:$(CALICOCONTAINERS_VERSION) quay.io/calico/calicoctl:$(CALICOCONTAINERS_VERSION)
	@echo Now attach the binaries to github dist/calicoctl
	@echo And push the images to Docker Hub and quay.io:
	@echo docker push calico/calicoctl:$(CALICOCONTAINERS_VERSION)
	@echo docker push quay.io/calico/calicoctl:$(CALICOCONTAINERS_VERSION)

release-caliconode: calico/node
	docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME)
	docker run $(NODE_CONTAINER_NAME) calico-felix --version
	docker run $(NODE_CONTAINER_NAME) libnetwork-plugin -v
	@echo And push the images to Docker Hub and quay.io:
	@echo docker push $(NODE_CONTAINER_NAME)
	@echo docker push quay.io/$(NODE_CONTAINER_NAME)

## Clean everything (including stray volumes)
clean: clean_calico_node
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	-rm -r dist
	-rm -r build
	-rm -r certs
	-rm *.tar
	-rm -r vendor
	-rm $(BUILD_CALICOCTL_CONTAINER_MARKER)
	-rm $(CTL_CONTAINER_CREATED)
	-docker rm -f calico-node
	-docker rmi $(NODE_CONTAINER_NAME)
	-docker rmi $(CTL_CONTAINER_NAME)
	-docker rmi $(BUILD_CALICOCTL_CONTAINER_NAME)
	-docker tag calico/test:latest calico/test:latest-backup && docker rmi calico/test:latest
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes
	-rm -r $(NODE_CONTAINER_DIR)/bin

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
