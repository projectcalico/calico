###############################################################################
# Versions:
RELEASE_STREAM?=v2.3
CALICO_NODE_DIR=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))
VERSIONS_FILE?=$(CALICO_NODE_DIR)/../_data/versions.yml
# For local builds this can be made faster by running "go get github.com/mikefarah/yaml" and changing YAML_CMD to "yaml"
YAML_CMD?=$(shell which yaml || echo docker run -i calico/go-build yaml)
CALICO_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].title')
CALICO_GIT_VER ?= $(shell git describe --tags --dirty --always)
BIRD_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.calico-bird.version')
GOBGPD_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.calico-bgp-daemon.version')
FELIX_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.felix.version')
CALICOCTL_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.calicoctl.version')
LIBNETWORK_PLUGIN_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.libnetwork-plugin.version')
TYPHA_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.typha.version')
K8S_POLICY_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.calico/kube-policy-controller.version')
CNI_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '"$(RELEASE_STREAM)".[0].components.calico/cni.version')
# TODO - Why isn't confd in versions.yaml
CONFD_VER := v0.12.1-calico0.1.0

SYSTEMTEST_CONTAINER_VER := latest
GO_BUILD_VER:=v0.7
# we can use "custom" build image and test image name
SYSTEMTEST_CONTAINER?=calico/test:$(SYSTEMTEST_CONTAINER_VER)

# Ensure that the dist directory is always created
MAKE_SURE_BIN_EXIST := $(shell mkdir -p dist)

###############################################################################
# URL for Calico binaries
# confd binary
CONFD_URL?=https://github.com/projectcalico/confd/releases/download/$(CONFD_VER)/confd
# bird binaries
BIRD_URL?=https://github.com/projectcalico/calico-bird/releases/download/$(BIRD_VER)/bird
BIRD6_URL?=https://github.com/projectcalico/calico-bird/releases/download/$(BIRD_VER)/bird6
BIRDCL_URL?=https://github.com/projectcalico/calico-bird/releases/download/$(BIRD_VER)/birdcl
CALICO_BGP_DAEMON_URL?=https://github.com/projectcalico/calico-bgp-daemon/releases/download/$(GOBGPD_VER)/calico-bgp-daemon
GOBGP_URL?=https://github.com/projectcalico/calico-bgp-daemon/releases/download/$(GOBGPD_VER)/gobgp

###############################################################################
# calico/node build. Contains the following areas
# - Populate the calico_node/filesystem
# - Build the container itself
###############################################################################
NODE_CONTAINER_DIR=.
NODE_CONTAINER_NAME?=calico/node
NODE_CONTAINER_FILES=$(shell find $(NODE_CONTAINER_DIR)/filesystem -type f)
NODE_CONTAINER_CREATED=$(NODE_CONTAINER_DIR)/.calico_node.created
NODE_CONTAINER_BIN_DIR=$(NODE_CONTAINER_DIR)/filesystem/bin
NODE_CONTAINER_BINARIES=startup allocate-ipip-addr calico-felix bird calico-bgp-daemon confd libnetwork-plugin
FELIX_REPO?=calico/felix
FELIX_CONTAINER_NAME?=$(FELIX_REPO):$(FELIX_VER)
LIBNETWORK_PLUGIN_REPO?=calico/libnetwork-plugin
LIBNETWORK_PLUGIN_CONTAINER_NAME?=$(LIBNETWORK_PLUGIN_REPO):$(LIBNETWORK_PLUGIN_VER)
CTL_CONTAINER_NAME?=calico/ctl:master

STARTUP_DIR=$(NODE_CONTAINER_DIR)/startup
STARTUP_FILES=$(shell find $(STARTUP_DIR) -name '*.go')
ALLOCATE_IPIP_DIR=$(NODE_CONTAINER_DIR)/allocateipip
ALLOCATE_IPIP_FILES=$(shell find $(ALLOCATE_IPIP_DIR) -name '*.go')

TEST_CONTAINER_NAME?=calico/test:latest
TEST_CONTAINER_FILES=$(shell find tests/ -type f ! -name '*.created')

CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
LOCAL_USER_ID?=$(shell id -u $$USER)

PACKAGE_NAME?=github.com/projectcalico/calico/calico_node

LIBCALICOGO_PATH?=none

# Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor: glide.yaml
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide

	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
  docker run --rm \
    -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
    -v $(HOME)/.glide:/home/user/.glide:rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
      glide install -strip-vendor'


# Download calicoctl v1.0.2 from releases.  Used for STs (testing pre/post v1.1.0 data model)
dist/calicoctl-v1.0.2:
	wget https://github.com/projectcalico/calicoctl/releases/download/v1.0.2/calicoctl -O dist/calicoctl-v1.0.2
	chmod +x dist/calicoctl-v1.0.2

# Pull the latest calicoctl binary.  Used for STs
dist/calicoctl:
	-docker rm -f calicoctl
	docker create --name calicoctl $(CTL_CONTAINER_NAME)
	docker cp calicoctl:calicoctl dist/calicoctl && \
	  test -e dist/calicoctl && \
	  touch dist/calicoctl
	-docker rm -f calicoctl

test_image: calico_test.created ## Create the calico/test image

calico_test.created: $(TEST_CONTAINER_FILES)
	cd calico_test && docker build -f Dockerfile.calico_test -t $(TEST_CONTAINER_NAME) .
	touch calico_test.created

$(NODE_CONTAINER_NAME): $(NODE_CONTAINER_CREATED)    ## Create the calico/node image

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker save --output $@ $(NODE_CONTAINER_NAME)

# Build ACI (the APPC image file format) of calico/node.
# Requires docker2aci installed on host: https://github.com/appc/docker2aci
calico-node-latest.aci: calico-node.tar
	docker2aci $<

# Build calico/node docker image - explicitly depend on the container binaries.
$(NODE_CONTAINER_CREATED): $(NODE_CONTAINER_DIR)/Dockerfile $(NODE_CONTAINER_FILES) $(addprefix $(NODE_CONTAINER_BIN_DIR)/,$(NODE_CONTAINER_BINARIES))
	docker build --pull -t $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_DIR)
	touch $@

# Get felix binaries
.PHONY: update-felix
$(NODE_CONTAINER_BIN_DIR)/calico-felix update-felix:
	-docker rm -f calico-felix
	# Latest felix binaries are stored in automated builds of calico/felix.
	# To get them, we create (but don't start) a container from that image.
	docker create --name calico-felix $(FELIX_CONTAINER_NAME)
	# Then we copy the files out of the container.  Since docker preserves
	# mtimes on its copy, check the file really did appear, then touch it
	# to make sure that downstream targets get rebuilt.
	docker cp calico-felix:/code/. $(NODE_CONTAINER_BIN_DIR) && \
	  test -e $(NODE_CONTAINER_BIN_DIR)/calico-felix && \
	  touch $(NODE_CONTAINER_BIN_DIR)/calico-felix
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
	$(CURL) -L $(CONFD_URL) -o $@
	chmod +x $@

# Get the calico-bgp-daemon binary
$(NODE_CONTAINER_BIN_DIR)/calico-bgp-daemon:
	$(CURL) -L $(GOBGP_URL) -o $(@D)/gobgp
	$(CURL) -L $(CALICO_BGP_DAEMON_URL) -o $@
	chmod +x $(@D)/*

# Get bird binaries
$(NODE_CONTAINER_BIN_DIR)/bird:
	# This make target actually downloads the bird6 and birdcl binaries too
	# Copy patched BIRD daemon with tunnel support.
	$(CURL) -L $(BIRD6_URL) -o $(@D)/bird6
	$(CURL) -L $(BIRDCL_URL) -o $(@D)/birdcl
	$(CURL) -L $(BIRD_URL) -o $@
	chmod +x $(@D)/*

$(NODE_CONTAINER_BIN_DIR)/startup: dist/startup
	mkdir -p $(NODE_CONTAINER_BIN_DIR)
	cp dist/startup $(NODE_CONTAINER_BIN_DIR)/startup

$(NODE_CONTAINER_BIN_DIR)/allocate-ipip-addr: dist/allocate-ipip-addr
	mkdir -p $(NODE_CONTAINER_BIN_DIR)
	cp dist/allocate-ipip-addr $(NODE_CONTAINER_BIN_DIR)/allocate-ipip-addr

## Build startup.go
.PHONY: startup
startup:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -v -i -o dist/startup $(LDFLAGS) startup/startup.go

dist/startup: $(STARTUP_FILES) vendor
	mkdir -p dist
	mkdir -p .go-pkg-cache
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
		-v $(CURDIR)/dist:/go/src/$(PACKAGE_NAME)/dist \
		-v $(VERSIONS_FILE):/versions.yaml:ro \
        -e VERSIONS_FILE=/versions.yaml \
	  	$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			make CALICO_GIT_VER=$(CALICO_GIT_VER) startup'

## Build allocate_ipip_addr.go
.PHONY: allocate-ipip-addr
allocate-ipip-addr:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -v -i -o dist/allocate-ipip-addr $(LDFLAGS) allocateipip/allocate_ipip_addr.go

dist/allocate-ipip-addr: $(ALLOCATE_IPIP_FILES) vendor
	mkdir -p dist
	mkdir -p .go-pkg-cache
	docker run --rm \
  	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
  	-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
  	-v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
  	-v $(VERSIONS_FILE):/versions.yaml:ro \
    -e VERSIONS_FILE=/versions.yaml \
	-v $(CURDIR)/dist:/go/src/$(PACKAGE_NAME)/dist \
	  $(CALICO_BUILD) sh -c '\
		cd /go/src/$(PACKAGE_NAME) && \
		make CALICO_GIT_VER=$(CALICO_GIT_VER) allocate-ipip-addr'

###############################################################################
# Tests
# - Support for running etcd (both securely and insecurely)
# - Running UTs and STs
###############################################################################
# These variables can be overridden by setting an environment variable.
###############################################################################
# Common build variables
# Path to the sources.
# Default value: directory with Makefile
SOURCE_DIR?=$(dir $(lastword $(MAKEFILE_LIST)))
SOURCE_DIR:=$(abspath $(SOURCE_DIR))
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
ST_TO_RUN?=tests/st/

# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=
HOST_CHECKOUT_DIR?=$(shell pwd)

# curl should failed on 404
CURL=curl -sSf
## Generate the keys and certificates for running etcd with SSL.
ssl-certs: certs/.certificates.created    ## Generate self-signed SSL certificates
certs/.certificates.created:
	mkdir -p certs
	$(CURL) -L "https://github.com/projectcalico/cfssl/releases/download/1.2.1/cfssl" -o certs/cfssl
	$(CURL) -L "https://github.com/projectcalico/cfssl/releases/download/1.2.1/cfssljson" -o certs/cfssljson
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

stop-etcd:
	@-docker rm -f calico-etcd calico-etcd-ssl

.PHONY: run-etcd-ssl
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
st: dist/calicoctl dist/calicoctl-v1.0.2 busybox.tar routereflector.tar calico-node.tar workload.tar run-etcd-host calico_test.created
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
	           -e NODE_CONTAINER_NAME=$(NODE_CONTAINER_NAME) \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v $(SOURCE_DIR):/code \
	           $(SYSTEMTEST_CONTAINER) \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

## Run the STs in a container using etcd with SSL certificate/key/CA verification.
.PHONY: st-ssl
st-ssl: run-etcd-ssl dist/calicoctl busybox.tar calico-node.tar routereflector.tar workload.tar calico_test.created
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
	           -e NODE_CONTAINER_NAME=$(NODE_CONTAINER_NAME) \
	           -e ETCD_SCHEME=https \
	           -e ETCD_CA_CERT_FILE=$(SOURCE_DIR)/certs/ca.pem \
	           -e ETCD_CERT_FILE=$(SOURCE_DIR)/certs/client.pem \
	           -e ETCD_KEY_FILE=$(SOURCE_DIR)/certs/client-key.pem \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v $(SOURCE_DIR):/code \
	           -v $(SOURCE_DIR)/certs:$(SOURCE_DIR)/certs \
	           $(SYSTEMTEST_CONTAINER) \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture --with-xunit --xunit-file="/code/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

.PHONY: add-ssl-hostname
add-ssl-hostname:
	# Set "LOCAL_IP etcd-authority-ssl" in /etc/hosts to use as a hostname for etcd with ssl
	if ! grep -q "etcd-authority-ssl" /etc/hosts; then \
	  echo "\n# Host used by Calico's ETCD with SSL\n$(LOCAL_IP_ENV) etcd-authority-ssl" >> /etc/hosts; \
	fi

## Etcd is used by the tests
.PHONY: run-etcd
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd quay.io/coreos/etcd \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379" \
	--listen-client-urls "http://0.0.0.0:2379"

## Etcd is used by the STs
.PHONY: run-etcd-host
run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379" \
	--listen-client-urls "http://0.0.0.0:2379"

###############################################################################
# calico_node FVs
###############################################################################
.PHONY: node-fv
## Run the Functional Verification tests locally, must have local etcd running
node-fv:
	# Run tests in random order find tests recursively (-r).
	ginkgo -cover -r -skipPackage vendor startup allocateipip calicoclient

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

PHONY: node-test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
node-test-containerized: vendor run-etcd-host
	docker run --rm \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	-v $(VERSIONS_FILE):/versions.yaml:ro \
	-e VERSIONS_FILE=/versions.yaml \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	--net=host \
	$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && make node-fv'

# This depends on clean to ensure that dependent images get untagged and repulled
# THIS JOB DELETES LOTS OF THINGS - DO NOT RUN IT ON YOUR LOCAL DEV MACHINE.
.PHONY: semaphore
semaphore:
	# Clean up unwanted files to free disk space.
	bash -c 'rm -rf /usr/local/golang /opt /var/lib/mongodb /usr/lib/jvm /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv}'

	# Run the containerized UTs first.
	$(MAKE) node-test-containerized

	# Actually run the tests (refreshing the images as required), we only run a
	# small subset of the tests for testing SSL support.  These tests are run
	# using "latest" tagged images.
	$(MAKE) RELEASE_STREAM=master $(NODE_CONTAINER_NAME) st
	ST_TO_RUN=tests/st/policy $(MAKE) RELEASE_STREAM=master st-ssl

release: clean
	@if [[ `git rev-parse --abbrev-ref HEAD` == "master" ]]; then echo 'Release process should not be run from master'; exit 1; fi

	git tag $(CALICO_VER)

	# Build the calico/node images.
	$(MAKE) $(NODE_CONTAINER_NAME)

	# Create the release archive
	$(MAKE) release-archive

	# Retag images with corect version and quay
	docker tag $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_NAME):$(CALICO_VER)
	docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):$(CALICO_VER)
	docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):latest

	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(NODE_CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(NODE_CONTAINER_NAME):$(CALICO_VER)

	# Check that the images container the right sub-components
	docker run $(NODE_CONTAINER_NAME) calico-felix --version
	docker run $(NODE_CONTAINER_NAME) libnetwork-plugin -v
	
	@echo "See RELEASING.md for detailed instructions."
	@echo "Now push images."
	@echo "docker push $(NODE_CONTAINER_NAME):$(CALICO_VER)"
	@echo "docker push quay.io/$(NODE_CONTAINER_NAME):$(CALICO_VER)"
	@echo "docker push $(NODE_CONTAINER_NAME):latest"
	@echo "docker push quay.io/$(NODE_CONTAINER_NAME):latest"
	
	@echo "Only push the tag AFTER this branch is merged to origin/master"
	@echo "git push origin $(CALICO_VER)"


RELEASE_DIR:=release-$(CALICO_VER)
RELEASE_DIR_K8S_MANIFESTS:=$(RELEASE_DIR)/k8s-manifests
RELEASE_DIR_IMAGES:=$(RELEASE_DIR)/images
RELEASE_DIR_BIN:=$(RELEASE_DIR)/bin
MANIFEST_SRC := ../_site/$(RELEASE_STREAM)/getting-started/kubernetes/installation

## Create an archive that contains a complete "Calico" release
release-archive: $(RELEASE_DIR).tgz

$(RELEASE_DIR).tgz: $(RELEASE_DIR) $(RELEASE_DIR_K8S_MANIFESTS) $(RELEASE_DIR_IMAGES) $(RELEASE_DIR_BIN) $(RELEASE_DIR)/README
	tar -czvf $(RELEASE_DIR).tgz $(RELEASE_DIR)/*

$(RELEASE_DIR_IMAGES): $(RELEASE_DIR_IMAGES)/calico-node.tar $(RELEASE_DIR_IMAGES)/calico-typha.tar $(RELEASE_DIR_IMAGES)/calico-cni.tar $(RELEASE_DIR_IMAGES)/calico-kube-policy-controller.tar
$(RELEASE_DIR_BIN): $(RELEASE_DIR_BIN)/calicoctl $(RELEASE_DIR_BIN)/calicoctl-windows-amd64.exe $(RELEASE_DIR_BIN)/calicoctl-darwin-amd64

$(RELEASE_DIR)/README:
	@echo "This directory contains a complete release of Calico $(CALICO_VER)" >> $@
	@echo "Documentation for this release can be found at http://docs.projectcalico.org/$(RELEASE_STREAM)" >> $@
	@echo "" >> $@
	@echo "Docker images (under 'images'). Load them with 'docker load'" >> $@
	@echo "* The calico/node docker image  (version $(CALICO_VER))" >> $@
	@echo "* The calico/typha docker image  (version $(TYPHA_VER))" >> $@
	@echo "* The calico/cni docker image  (version $(CNI_VER))" >> $@
	@echo "* The calico/kube-policy-controller docker image (version $(K8S_POLICY_VER))" >> $@
	@echo "" >> $@
	@echo "Binaries (for amd64) (under 'bin')" >> $@
	@echo "* The calicoctl binary (for Linux) (version $(CALICOCTL_VER))" >> $@
	@echo "* The calicoctl-windows-amd64.exe binary (for Windows) (version $(CALICOCTL_VER))" >> $@
	@echo "* The calicoctl-darwin-amd64 binary (for Mac) (version $(CALICOCTL_VER))" >> $@
	@echo "" >> $@
	@echo "Kubernetes manifests (under 'k8s-manifests directory')" >> $@

$(RELEASE_DIR):
	mkdir -p $(RELEASE_DIR)

$(RELEASE_DIR_K8S_MANIFESTS):
	# Ensure that the docs site is generated
	$(MAKE) -C .. _site

	# Find all the hosted manifests and copy them into the release dir. Use xargs to mkdir the destination directory structure before copying them.
	# -printf "%P\n" prints the file name and directory structure with the search dir stripped off
	find $(MANIFEST_SRC)/hosted -name  '*.yaml' -printf "%P\n" | \
	  xargs -I FILE sh -c \
	    'mkdir -p $(RELEASE_DIR_K8S_MANIFESTS)/hosted/`dirname FILE`;\
	    cp $(MANIFEST_SRC)/hosted/FILE $(RELEASE_DIR_K8S_MANIFESTS)/hosted/`dirname FILE`;'

	# Copy the non-hosted manifets too
	cp $(MANIFEST_SRC)/*.yaml $(RELEASE_DIR_K8S_MANIFESTS)

$(RELEASE_DIR_IMAGES)/calico-node.tar:
	mkdir -p $(RELEASE_DIR_IMAGES)
	docker save --output $@ $(NODE_CONTAINER_NAME)

$(RELEASE_DIR_IMAGES)/calico-typha.tar:
	mkdir -p $(RELEASE_DIR_IMAGES)
	docker pull calico/typha:$(TYPHA_VER)
	docker save --output $@ calico/typha:$(TYPHA_VER)

$(RELEASE_DIR_IMAGES)/calico-cni.tar:
	mkdir -p $(RELEASE_DIR_IMAGES)
	docker pull calico/cni:$(CNI_VER)
	docker save --output $@ calico/cni:$(CNI_VER)

$(RELEASE_DIR_IMAGES)/calico-kube-policy-controller.tar:
	mkdir -p $(RELEASE_DIR_IMAGES)
	docker pull calico/kube-policy-controller:$(K8S_POLICY_VER)
	docker save --output $@ calico/kube-policy-controller:$(K8S_POLICY_VER)

$(RELEASE_DIR_BIN)/%:
	mkdir -p $(RELEASE_DIR_BIN)
	wget https://github.com/projectcalico/calicoctl/releases/download/$(CALICOCTL_VER)/$(@F) -O $@
	chmod +x $@

## Clean enough that a new release build will be clean
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf dist build certs *.tar vendor $(NODE_CONTAINER_DIR)/filesystem/bin

	# Delete images that we built in this repo
	docker rmi $(NODE_CONTAINER_NAME):latest || true
	docker rmi $(SYSTEMTEST_CONTAINER) || true

	# Retag and remove external images so that they will be pulled again
	# We avoid just deleting the image. We didn't build them here so it would be impolite to delete it.
	docker tag $(FELIX_CONTAINER_NAME) $(FELIX_CONTAINER_NAME)-backup && docker rmi $(FELIX_CONTAINER_NAME) || true

	rm -rf $(RELEASE_DIR)

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

