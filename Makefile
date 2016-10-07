.PHONY: all binary calico/node test ut ut-circle st st-ssl clean run-etcd run-etcd-ssl help clean_calico_node
default: help
all: test                ## Run all the tests
binary: dist/calicoctl   ## Create the calicoctl binary
calico/node: calico_node/.calico_node.created ## Create the calico/node image
calico/ctl: calicoctl/.calico_ctl.created ## Create the calico/node image
node_image: calico/node
ctl_image: calico/ctl
test: st ut              ## Run all the tests
ssl-certs: certs/.certificates.created ## Generate self-signed SSL certificates

###############################################################################
# URL for Calico binaries
# confd binary
CONFD_URL?=https://github.com/projectcalico/confd/releases/download/v0.10.0-scale/confd.static
# bird binaries
BIRD_URL?=https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/bird
BIRD6_URL?=https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/bird6
BIRDCL_URL?=https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/birdcl

###############################################################################
# calico/node build. Contains the following areas
# - Populate the calico_node/filesystem
# - Build the container itself
###############################################################################
NODE_CONTAINER_DIR=calico_node
NODE_CONTAINER_FILES=$(shell find $(NODE_CONTAINER_DIR)/filesystem/{etc,sbin} -type f)
NODE_CONTAINER_CREATED=$(NODE_CONTAINER_DIR)/.calico_node.created
NODE_CONTAINER_BIN_DIR=$(NODE_CONTAINER_DIR)/filesystem/bin
NODE_CONTAINER_BINARIES=startup allocate-ipip-addr calico-felix bird calico-bgp-daemon confd

calico-node.tar: $(NODE_CONTAINER_CREATED)
	docker save --output $@ calico/node:latest

# Build ACI (the APPC image file format) of calico/node.
# Requires docker2aci installed on host: https://github.com/appc/docker2aci
calico-node-latest.aci: calico-node.tar
	docker2aci $<

# Build calico/node docker image
$(NODE_CONTAINER_CREATED): $(NODE_CONTAINER_DIR)/Dockerfile  $(addprefix $(NODE_CONTAINER_BIN_DIR)/,$(NODE_CONTAINER_BINARIES))
	docker build -t calico/node:latest calico_node
	touch $@

$(NODE_CONTAINER_BIN_DIR)/calico-bgp-daemon: $(NODE_CONTAINER_DIR)/calico-bgp-daemon/main.go
	docker run \
	-v `pwd`/calico_node/calico-bgp-daemon:/go/src/github.com/projectcalico/calico-bgp-daemon \
	-v `pwd`/$(NODE_CONTAINER_DIR):/$(NODE_CONTAINER_DIR) \
	golang:1.7 sh -c \
	'cd /go/src/github.com/projectcalico/calico-bgp-daemon/ && go get -v . && go build -o /$@ . && chown $(shell id -u):$(shell id -g) -R /$(@D)'

# Build binary from python files, e.g. startup.py or allocate-ipip-addr.py
$(NODE_CONTAINER_BIN_DIR)/%: calico_node/%.py
	-docker run -v `pwd`:/code --rm \
	 calico/build:latest \
	 sh -c 'pyinstaller -ayF --distpath $(@D) $< && chown $(shell id -u):$(shell id -g) -R $(@D)'

# Get felix binaries
$(NODE_CONTAINER_BIN_DIR)/calico-felix:
	-docker rm -f calico-felix
	# Latest felix binaries are stored in automated builds of calico/felix.
	# To get them, we pull that image, then copy the binaries out to our host
	docker create --name calico-felix calico/felix:latest
	docker cp calico-felix:/code/. $(@D)

# Get the confd binary
$(NODE_CONTAINER_BIN_DIR)/confd:
	curl -L $(CONFD_URL) -o $@
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
	rm -rf $(NODE_CONTAINER_BIN_DIR)

###############################################################################
# calicoctl build
# - Building the calicoctl binary in a container
# - Building the calicoctl binary outside a container ("simple-binary")
# - Building the calico/ctl image
###############################################################################
CALICOCTL_DIR=calicoctl
CALICOCTL_FILE=$(CALICOCTL_DIR)/calicoctl.py $(wildcard $(CALICOCTL_DIR)/calico_ctl/*.py) calicoctl.spec
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created

dist/calicoctl: $(CALICOCTL_FILE) birdcl gobgp
	# Ignore errors on docker command. CircleCI throws a benign error
	# from the use of the --rm flag
    #
    # We create two versions of calicoctl built using wheezy and jessie based
    # build containers.  The main build is the more up-to-date jessie build,
    # but we also build a wheezy version for support of older versions of glibc.
	-docker run -v `pwd`:/code --rm \
	 calico/build:latest-wheezy \
	 pyinstaller calicoctl-debian-glibc-2.13.spec -ayF

	-docker run -v `pwd`:/code --rm \
	 calico/build:latest \
	 pyinstaller calicoctl.spec -ayF

birdcl:
	curl -L $(BIRDCL_URL) -o $@
	chmod +x birdcl

gobgp:
	docker pull osrg/gobgp
	docker run \
	-v `pwd`:/code \
	--entrypoint=sh \
	osrg/gobgp \
	-c 'cp /go/bin/gobgp /code'

simple-binary: $(CALICOCTL_FILE) birdcl gobgp
	pip install git+https://github.com/projectcalico/libcalico.git@master
	pip install -r https://raw.githubusercontent.com/projectcalico/libcalico/master/build-requirements.txt
	pyinstaller calicoctl/calicoctl.py -ayF --clean

setup-env:
	virtualenv venv
	venv/bin/pip install --upgrade -r calicoctl/requirements.txt
	@echo "run\n. venv/bin/activate"

# build calico_ctl image
$(CTL_CONTAINER_CREATED): $(CALICOCTL_DIR)/Dockerfile $(CALICOCTL_DIR)/calicoctl
	docker build -t calico/ctl:latest $(CALICOCTL_DIR)
	touch $@

$(CALICOCTL_DIR)/calicoctl: dist/calicoctl
	cp $< $@

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

## Run the UTs in a container.
ut:
	docker run --rm -v `pwd`/calicoctl:/code calico/test \
		nosetests $(UT_TO_RUN) -c nose.cfg
	docker run --rm -v `pwd`/calico_node:/code calico/test \
		nosetests tests --with-coverage --cover-package=startup

ut-circle: dist/calicoctl
	# Test this locally using CIRCLE_TEST_REPORTS=/tmp COVERALLS_REPO_TOKEN=bad make ut-circle
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/test \
	sh -c '\
	cd calicoctl; nosetests tests/unit -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

	docker run --rm -v `pwd`/calico_node:/code calico/test \
		nosetests tests --with-coverage --cover-package=startup

## Run etcd in a container. Used by the STs and generally useful.
run-etcd:
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
	-v `pwd`/certs:/etc/calico/certs \
	--name calico-etcd-ssl quay.io/coreos/etcd:v2.0.11 \
	--cert-file "/etc/calico/certs/server.pem" \
	--key-file "/etc/calico/certs/server-key.pem" \
	--ca-file "/etc/calico/certs/ca.pem" \
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
st: run-etcd dist/calicoctl busybox.tar routereflector.tar calico-node.tar
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	$(MAKE) st-checks
	docker run --uts=host \
	           --pid=host \
	           --net=host \
	           --privileged \
	           -e HOST_CHECKOUT_DIR=$(HOST_CHECKOUT_DIR) \
	           -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v `pwd`:/code \
	           calico/test \
	           sh -c 'cp -ra tests/st/* /tests/st && cd / && nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

## Run the STs in a container using etcd with SSL certificate/key/CA verification.
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
	           -e ETCD_CA_CERT_FILE=`pwd`/certs/ca.pem \
	           -e ETCD_CERT_FILE=`pwd`/certs/client.pem \
	           -e ETCD_KEY_FILE=`pwd`/certs/client-key.pem \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v `pwd`:/code \
	           -v `pwd`/certs:`pwd`/certs \
	           calico/test \
	           sh -c 'cp -ra tests/st/* /tests/st && cd / && nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

add-ssl-hostname:
	# Set "LOCAL_IP etcd-authority-ssl" in /etc/hosts to use as a hostname for etcd with ssl
	if ! grep -q "etcd-authority-ssl" /etc/hosts; then \
	  echo "\n# Host used by Calico's ETCD with SSL\n$(LOCAL_IP_ENV) etcd-authority-ssl" >> /etc/hosts; \
	fi

semaphore:
	# Clean up unwanted files to free disk space.
	bash -c 'rm -rf /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv}'

	# Actually run the tests (refreshing the images as required)
	make st

	# Run subset of STs with secure etcd
	ST_TO_RUN=tests/st/no_orchestrator/ make st-ssl
	ST_TO_RUN=tests/st/bgp/test_route_reflector_cluster.py make st-ssl


## Clean everything (including stray volumes)
clean: clean_calico_node
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-rm -rf build
	-rm -rf certs
	-rm -f *.tar
	-docker rm -f calico-node
	-docker rmi calico/node
	-docker rmi calico/ctl
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes
	-rm -rf calico_node/bin
	-rm -rf $(CALICOCTL_DIR)/calicoctl

## Display this help text
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	$(info Available targets)
	@awk '/^[a-zA-Z\-\_0-9]+:/ {                                   \
		nb = sub( /^## /, "", helpMsg );                             \
		if(nb == 0) {                                                \
			helpMsg = $$0;                                             \
			nb = sub( /^[^:]*:.* ## /, "", helpMsg );                  \
		}                                                            \
		if (nb)                                                      \
			printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg; \
	}                                                              \
	{ helpMsg = $$0 }'                                             \
	width=$$(grep -o '^[a-zA-Z_0-9]\+:' $(MAKEFILE_LIST) | wc -L)  \
	$(MAKEFILE_LIST)
