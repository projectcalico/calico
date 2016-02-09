.PHONEY: all binary node_image test_image test ut ut-circle st st-ssl clean run-etcd run-etcd-ssl create-dind help

# These variables can be overridden by setting an environment variable.
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
ST_TO_RUN?=tests/st/
UT_TO_RUN?=tests/unit/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=
HOST_CHECKOUT_DIR?=$(shell pwd)

CALICOCTL_DIR=calicoctl
CALICOCTL_FILE=$(CALICOCTL_DIR)/calicoctl.py $(wildcard $(CALICOCTL_DIR)/calico_ctl/*.py) calicoctl.spec

TEST_CONTAINER_DIR=calico_test
TEST_CONTAINER_FILES=$(shell find calico_test/ -type f ! -name '*.created')

NODE_CONTAINER_DIR=calico_node
NODE_CONTAINER_FILES=$(shell find calico_node/ -type f ! -name '*.created')

WHEEL_VERSION=0.0.0

default: help
all: test                ## Run all the tests
binary: dist/calicoctl   ## Create the calicoctl binary
node_image: calico_node/.calico_node.created ## Create the calico/node image
test_image: calico_test/.calico_test.created ## Create the calico/test image
test: st ut              ## Run all the tests
ssl-certs: certs/.certificates.created ## Generate self-signed SSL certificates

dist/calicoctl: $(CALICOCTL_FILE) birdcl 
	# Ignore errors on docker command. CircleCI throws an benign error
	# from the use of the --rm flag

	-docker run -v `pwd`:/code --rm \
	 calico/build:latest \
	 pyinstaller calicoctl.spec -ayF

calico_test/.calico_test.created: $(TEST_CONTAINER_FILES)
	cd calico_test && docker build -t calico/test:latest .
	touch calico_test/.calico_test.created

calico_node/.calico_node.created: $(NODE_CONTAINER_FILES)
	cd calico_node && docker build -t calico/node:latest .
	touch calico_node/.calico_node.created

## Generate the keys and certificates for running etcd with SSL.
certs/.certificates.created:
	mkdir -p certs
	curl -L "https://pkg.cfssl.org/R1.1/cfssl_linux-amd64" -o certs/cfssl
	curl -L "https://pkg.cfssl.org/R1.1/cfssljson_linux-amd64" -o certs/cfssljson
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

calico-node.tar: calico_node/.calico_node.created
	docker save --output calico-node.tar calico/node:latest

busybox.tar:
	docker pull busybox:latest
	docker save --output busybox.tar busybox:latest

routereflector.tar:
	docker pull calico/routereflector:latest
	docker save --output routereflector.tar calico/routereflector:latest

## Download the latest docker binary
docker:
	curl https://get.docker.com/builds/Linux/x86_64/docker-1.9.1 -o docker
	chmod +x docker

birdcl:
	wget -N https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/birdcl
	chmod +x birdcl

## Run the UTs in a container.
ut: calico_test/.calico_test.created
	docker run --rm -v `pwd`/calicoctl:/code calico/test \
		nosetests $(UT_TO_RUN) -c nose.cfg

ut-circle: calico_test/.calico_test.created dist/calicoctl
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

## Run etcd in a container. Used by the STs and generally useful.
run-etcd:
	@-docker rm -f calico-etcd calico-etcd-ssl
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379" \
	--listen-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379"

## Run etcd in a container with SSL verification. Used primarily by STs.
run-etcd-ssl: certs/.certificates.created add-ssl-hostname
	@-docker rm -f calico-etcd calico-etcd-ssl
	docker run --detach \
	--net=host \
	-v `pwd`/certs:/etc/calico/certs \
	--name calico-etcd-ssl quay.io/coreos/etcd:v2.0.11 \
	--cert-file "/etc/calico/certs/server.pem" \
	--key-file "/etc/calico/certs/server-key.pem" \
	--ca-file "/etc/calico/certs/ca.pem" \
	--advertise-client-urls "https://etcd-authority-ssl:2379,https://localhost:2379" \
	--listen-client-urls "https://0.0.0.0:2379"

## Run the STs in a container
st: run-etcd dist/calicoctl docker calico_test/.calico_test.created busybox.tar routereflector.tar calico-node.tar
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	docker run --uts=host \
	           --pid=host \
	           --net=host \
	           --privileged \
	           -e HOST_CHECKOUT_DIR=$(HOST_CHECKOUT_DIR) \
	           -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v `pwd`:/code \
	           calico/test \
	           sh -c 'cp -ra tests/st/* /tests/st && cd / && nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)'

## Run the STs in a container using etcd with SSL certificate/key/CA verification.
st-ssl: run-etcd-ssl dist/calicoctl docker calico_test/.calico_test.created busybox.tar calico-node.tar routereflector.tar
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	# Mount the full path to the etcd certs directory.
	#   - docker copies this directory directly from the host, but the
	#     calicoctl node command reads the files from the test container
	docker run --uts=host \
	           --pid=host \
	           --net=host \
	           --privileged \
	           -e HOST_CHECKOUT_DIR=$(HOST_CHECKOUT_DIR) \
	           -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
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

add-ssl-hostname:
	# Set "LOCAL_IP etcd-authority-ssl" in /etc/hosts to use as a hostname for etcd with ssl
	if ! grep -q "etcd-authority-ssl" /etc/hosts; then \
	  echo "\n# Host used by Calico's ETCD with SSL\n$(LOCAL_IP_ENV) etcd-authority-ssl" >> /etc/hosts; \
	fi

semaphore:
	# Clean up unwanted files to free disk space.
	rm -rf /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv}

	# Make sure semaphore has the modules loaded that we need.
	modprobe -a ip6_tables xt_set

	# Actually run the tests (refreshing the images as required)
	make st

	# Run subset of STs with secure etcd
	ST_TO_RUN=tests/st/no_orchestrator/ make st-ssl
	ST_TO_RUN=tests/st/bgp/test_route_reflector_cluster.py make st-ssl


## Run a Docker in Docker (DinD) container.
create-dind: docker
	@echo "You may want to load calico-node with"
	@echo "docker load --input /code/calico-node.tar"
	@ID=$$(docker run --privileged -v `pwd`:/code -v `pwd`/docker:/usr/local/bin/docker \
	-tid calico/dind:latest) ;\
	docker exec -ti $$ID bash;\
	docker rm -f $$ID

## Clean everything (including stray volumes)
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	-rm -f docker
	-rm -rf dist
	-rm -rf build
	-rm -rf certs
	-rm -f *.tar
	-docker rm -f calico-node
	-docker rmi calico/node
	-docker rmi calico/test
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

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

setup-env:
	virtualenv venv
	venv/bin/pip install --upgrade -r calicoctl/requirements.txt
	@echo "run\n. venv/bin/activate"
