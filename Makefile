.PHONY: all binary calico/node test ut ut-circle st st-ssl clean run-etcd run-etcd-ssl help
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

# we can use "custom" build image and test image name
PYTHON_BUILD_CONTAINER_NAME?=calico/build:v0.18.0
SYSTEMTEST_CONTAINER?=calico/test

# calicoctl and calico/node current share a single version - this is it.
CALICOCONTAINERS_VERSION?=$(shell git describe --tags --dirty --always)

###############################################################################
# calico/node build. Contains the following areas
# - Populate the calico_node/filesystem
# - Build the container itself
###############################################################################
NODE_CONTAINER_DIR=calico_node
NODE_CONTAINER_NAME?=calico/node
NODE_CONTAINER_FILES=$(shell find $(NODE_CONTAINER_DIR)/filesystem -type f)
NODE_CONTAINER_CREATED=$(NODE_CONTAINER_DIR)/.calico_node.created
NODE_CONTAINER_BIN_DIR=$(NODE_CONTAINER_DIR)/filesystem/bin
NODE_CONTAINER_BINARIES=startup allocate-ipip-addr calico-felix bird calico-bgp-daemon confd libnetwork-plugin
FELIX_CONTAINER_NAME?=calico/felix:2.0.0-beta.3
LIBNETWORK_PLUGIN_CONTAINER_NAME?=calico/libnetwork-plugin:v1.0.0-beta

calico/node: $(NODE_CONTAINER_CREATED)    ## Create the calico/node image

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker save --output $@ $(NODE_CONTAINER_NAME)

# Build ACI (the APPC image file format) of calico/node.
# Requires docker2aci installed on host: https://github.com/appc/docker2aci
calico-node-latest.aci: calico-node.tar
	docker2aci $<

# Build calico/node docker image - explicitly depend on the container binaries.
$(NODE_CONTAINER_CREATED): $(NODE_CONTAINER_DIR)/Dockerfile $(NODE_CONTAINER_FILES) $(addprefix $(NODE_CONTAINER_BIN_DIR)/,$(NODE_CONTAINER_BINARIES))
	docker build -t $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_DIR)
	touch $@

# Build binary from python files, e.g. startup.py or allocate-ipip-addr.py
$(NODE_CONTAINER_BIN_DIR)/%: $(NODE_CONTAINER_DIR)/%.py
	-docker run -v $(SOURCE_DIR):/code --rm \
	 $(PYTHON_BUILD_CONTAINER_NAME) \
	 sh -c 'pyinstaller -ayF --specpath /tmp/spec --workpath /tmp/build --distpath $(@D) $< && chown $(shell id -u):$(shell id -g) -R $(@D)'

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

workload.tar:
	cd workload && docker build -t workload .
	docker save --output workload.tar workload

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
st: dist/calicoctl busybox.tar routereflector.tar calico-node.tar workload.tar run-etcd-st
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	# $(MAKE) st-checks
	docker run --uts=host \
	           --pid=host \
	           --net=host \
	           --privileged \
	           -e HOST_CHECKOUT_DIR=$(HOST_CHECKOUT_DIR) \
	           -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v $(SOURCE_DIR):/code \
	           $(SYSTEMTEST_CONTAINER) \
	           sh -c 'cp -ra tests/st/* /tests/st && cd / && nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

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
	           $(SYSTEMTEST_CONTAINER) \
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
	CALICOCTL_NODE_VERSION=$$BRANCH_NAME $(MAKE) calico/ctl calico/node st

	# Assumes that a few environment variables exist - BRANCH_NAME PULL_REQUEST_NUMBER
	# If this isn't a PR, then push :BRANCHNAME tagged images to Dockerhub and quay for both calico/node and calico/ctl
	set -e; \
	if [ -z $$PULL_REQUEST_NUMBER ]; then \
		docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push quay.io/$(NODE_CONTAINER_NAME):$$BRANCH_NAME; \
		docker tag $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push $(NODE_CONTAINER_NAME):$$BRANCH_NAME; \
		docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push quay.io/$(CTL_CONTAINER_NAME):$$BRANCH_NAME; \
		docker tag $(CTL_CONTAINER_NAME) $(CTL_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push $(CTL_CONTAINER_NAME):$$BRANCH_NAME; \

		# Now build a calico/ctl that points at a calico/node:$(CALICOCONTAINERS_VERSION) image
		rm dist/calicoctl ;\
		CALICOCTL_NODE_VERSION=$(CALICOCONTAINERS_VERSION) $(MAKE) calico/ctl ;\

		docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push quay.io/$(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
		docker tag $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push $(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
		docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push quay.io/$(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
		docker tag $(CTL_CONTAINER_NAME) $(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push $(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
	fi


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
test-containerized: dist/calicoctl calicoctl_test_container.created
	docker run --rm -v ${PWD}:/go/src/github.com/projectcalico/calico-containers:rw \
	$(TEST_CALICOCTL_CONTAINER_NAME) bash -c 'make ut'

###############################################################################
# calicoctl build
# - Building the calicoctl binary in a container
# - Building the calicoctl binary outside a container ("simple-binary")
# - Building the calico/ctl image
###############################################################################
CALICOCTL_DIR=calicoctl
CTL_CONTAINER_NAME?=calico/ctl
CALICOCTL_FILES=$(shell find $(CALICOCTL_DIR) -name '*.go')
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created

CALICOCTL_NODE_VERSION?="latest"
CALICOCTL_BUILD_DATE?=$(shell date -u +'%FT%T%z')
CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)

LDFLAGS=-ldflags "-X github.com/projectcalico/calico-containers/calicoctl/commands.VERSION=$(CALICOCONTAINERS_VERSION) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands/node.VERSION=$(CALICOCTL_NODE_VERSION) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands.BUILD_DATE=$(CALICOCTL_BUILD_DATE) \
	-X github.com/projectcalico/calico-containers/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) -s -w"

GLIDE_CONTAINER_NAME?=dockerepo/glide
TEST_CALICOCTL_CONTAINER_NAME=calico/calicoctl_test_container
TEST_CALICOCTL_CONTAINER_MARKER=calicoctl_test_container.created

LIBCALICOGO_PATH?=none

calico/ctl: $(CTL_CONTAINER_CREATED)      ## Create the calico/ctl image

## Use this to populate the vendor directory after checking out the repository.
## To update upstream dependencies, delete the glide.lock file first.
vendor: glide.lock
	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
	docker run --rm \
		-v ${HOME}/.glide:/root/.glide:rw \
		-v ${PWD}:/go/src/github.com/projectcalico/calico-containers:rw $$EXTRA_DOCKER_BIND \
      --entrypoint /bin/sh $(GLIDE_CONTAINER_NAME) -e -c ' \
        cd /go/src/github.com/projectcalico/calico-containers && \
        glide install -strip-vendor && \
        chown $(shell id -u):$(shell id -u) -R vendor'

## Build the calicoctl
binary: $(CALICOCTL_FILES) vendor
	CGO_ENABLED=0 go build -v -o dist/calicoctl $(LDFLAGS) "./calicoctl/calicoctl.go"

$(TEST_CALICOCTL_CONTAINER_MARKER): calicoctl/Dockerfile.calicoctl.build
	docker build -f calicoctl/Dockerfile.calicoctl.build -t $(TEST_CALICOCTL_CONTAINER_NAME) .
	touch $@

# build calico_ctl image
$(CTL_CONTAINER_CREATED): calicoctl/Dockerfile.calicoctl dist/calicoctl
	docker build -t $(CTL_CONTAINER_NAME) -f calicoctl/Dockerfile.calicoctl .
	touch $@

## Run the build in a container. Useful for CI
dist/calicoctl: $(CALICOCTL_FILES) vendor
	mkdir -p dist
	docker run --rm \
	  -v ${PWD}:/go/src/github.com/projectcalico/calico-containers:ro \
	  -v ${PWD}/dist:/go/src/github.com/projectcalico/calico-containers/dist \
	  golang:1.7 bash -c '\
	    cd /go/src/github.com/projectcalico/calico-containers && \
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

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)

	CALICOCTL_NODE_VERSION=$(VERSION) $(MAKE) dist/calicoctl calico/ctl calico/node
	# Check that the version output includes the version specified.
# Tests that the "git tag" makes it into the binary. Main point is to catch "-dirty" builds
	if ! dist/calicoctl version | grep -P 'Version:\s*$(VERSION)$$'; then echo "Reported version:" `dist/calicoctl version` "\nExpected version: $(VERSION)"; false; else echo "Version check passed\n"; fi

	# Retag images with corect version and quay
	docker tag $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_NAME):$(VERSION)
	docker tag $(CTL_CONTAINER_NAME) $(CTL_CONTAINER_NAME):$(VERSION)
	docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):$(VERSION)
	docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):$(VERSION)


	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(NODE_CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(NODE_CONTAINER_NAME):$(VERSION)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME):$(VERSION)

	# Check that the images container the right sub-components
	docker run $(NODE_CONTAINER_NAME) calico-felix --version
	docker run $(NODE_CONTAINER_NAME) libnetwork-plugin -v

	@echo "\nNow push the tag and images. Then create a release on Github and attach the dist/calicoctl binary"
	@echo "git push origin $(VERSION)"
	@echo "docker push calico/ctl:$(VERSION)"
	@echo "docker push quay.io/calico/ctl:$(VERSION)"
	@echo "docker push calico/node:$(VERSION)"
	@echo "docker push quay.io/calico/node:$(VERSION)"
	@echo "docker push calico/ctl:latest"
	@echo "docker push quay.io/calico/ctl:latest"
	@echo "docker push calico/node:latest"
	@echo "docker push quay.io/calico/node:latest"

## Clean enough that a new release build will be clean
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf dist build certs *.tar vendor $(NODE_CONTAINER_DIR)/filesystem/bin

	# Delete images that we built in this repo
	docker rmi calico/node:latest || true
	docker rmi calico/ctl:latest || true
	docker rmi calico/calicoctl_test_container:latest || true

	# Retag and remove external images so that they will be pulled again
	# We avoid just deleting the image. We didn't build them here so it would be impolite to delete it.
	docker tag $(FELIX_CONTAINER_NAME) $(FELIX_CONTAINER_NAME)-backup && docker rmi $(FELIX_CONTAINER_NAME) || true
	docker tag $(PYTHON_BUILD_CONTAINER_NAME) $(PYTHON_BUILD_CONTAINER_NAME)-backup && docker rmi $(PYTHON_BUILD_CONTAINER_NAME) || true
	docker tag $(SYSTEMTEST_CONTAINER):latest $(SYSTEMTEST_CONTAINER):latest-backup && docker rmi $(SYSTEMTEST_CONTAINER):latest || true

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
