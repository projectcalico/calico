.PHONEY: all binary node_image test_image test ut ut-circle st st-ssl clean run-etcd run-etcd-ssl create-dind help

# These variables can be overridden by setting an environment variable.
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
ST_TO_RUN?=tests/st/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=
HOST_CHECKOUT_DIR?=$(shell pwd)

CALICOCTL_DIR=calicoctl
CALICOCTL_FILE=$(CALICOCTL_DIR)/calicoctl.py $(wildcard $(CALICOCTL_DIR)/calico_ctl/*.py)

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

dist/calicoctl: $(CALICOCTL_FILE) 
	# Ignore errors on docker command. CircleCI throws an benign error
	# from the use of the --rm flag

	-docker run -v `pwd`:/code --rm \
	 calico/build \
	 pyinstaller calicoctl/calicoctl.py -ayF

calico_test/.calico_test.created: $(TEST_CONTAINER_FILES)
	cd calico_test && docker build -t calico/test:latest .
	touch calico_test/.calico_test.created

calico_node/.calico_node.created: $(NODE_CONTAINER_FILES)
	cd calico_node && docker build -t calico/node:latest .
	touch calico_node/.calico_node.created

## Generate the keys and certificates for running etcd with SSL.
certs/.certificates.created:
	mkdir -p certs
	curl -L "https://github.com/projectcalico/etcd-ca/releases/download/v1.0/etcd-ca" -o certs/etcd-ca
	chmod +x certs/etcd-ca
	cd certs && find . ! -name 'etcd-ca' -type f -exec rm {} + && \
	  ./etcd-ca init --organization "Metaswitch" --passphrase "" && \
	  ./etcd-ca new-cert --passphrase "" --organization "Metaswitch" client && \
	  ./etcd-ca new-cert --passphrase "" --ip "$(LOCAL_IP_ENV),127.0.0.1" --organization "Metaswitch" server && \
	  ./etcd-ca sign --passphrase "" client && \
	  ./etcd-ca sign --passphrase "" server && \
	  ./etcd-ca export --insecure --passphrase "" client | tar xvf - && \
	  ./etcd-ca export --insecure --passphrase "" server | tar xvf - && \
	  ./etcd-ca export | tar xvf -
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
	curl https://get.docker.com/builds/Linux/x86_64/docker-1.9.0 -o docker
	chmod +x docker

## Run the UTs in a container.
ut: calico_test/.calico_test.created
	docker run --rm -v `pwd`/calicoctl:/code calico/test \
		nosetests tests/unit  -c nose.cfg

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
run-etcd-ssl: certs/.certificates.created
	@-docker rm -f calico-etcd calico-etcd-ssl
	docker run --detach \
	--net=host \
	-v `pwd`/certs:/etc/calico/certs \
	--name calico-etcd-ssl quay.io/coreos/etcd:v2.0.11 \
	--cert-file "/etc/calico/certs/server.crt" \
	--key-file "/etc/calico/certs/server.key.insecure" \
	--ca-file "/etc/calico/certs/ca.crt" \
	--advertise-client-urls "https://$(LOCAL_IP_ENV):2379,https://127.0.0.1:2379" \
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
	           -e ETCD_CA_CERT_FILE=`pwd`/certs/ca.crt \
	           -e ETCD_CERT_FILE=`pwd`/certs/client.crt \
	           -e ETCD_KEY_FILE=`pwd`/certs/client.key.insecure \
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v `pwd`:/code \
	           -v `pwd`/certs:`pwd`/certs \
	           calico/test \
	           sh -c 'cp -ra tests/st/* /tests/st && cd / && nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)'

semaphore:
	# Clean up unwanted files to free disk space.
	rm -rf /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv}

	# Caching - From http://tschottdorf.github.io/cockroach-docker-circleci-continuous-integration/
	#find . -exec touch -t 201401010000 {} \;
	#for x in $(git ls-tree --full-tree --name-only -r HEAD); do touch -t  $(date -d "$(git log -1 --format=%ci "${x}")" +%y%m%d%H%M.%S) "${x}"; done

	# "Upgrade" docker
	docker version
	stop docker
	curl https://get.docker.com/builds/Linux/x86_64/docker-1.9.0 -o /usr/bin/docker
	cp /usr/bin/docker .
	start docker

	# Use the cache
	#cp $SEMAPHORE_CACHE_DIR/busybox.tar calico_containers || true
	#docker load --input $SEMAPHORE_CACHE_DIR/calico-node.tar || true
	#docker load --input $SEMAPHORE_CACHE_DIR/calico-build.tar || true

	# Make sure semaphore has the modules loaded that we need.
	modprobe -a ip6_tables xt_set

	# Actually run the tests (refreshing the images as required)
	make st

	# Run subset of STs with secure etcd
	#TODO Fix secure STs
	#ST_TO_RUN=tests/st/no_orchestrator/ make st-ssl
	#ST_TO_RUN=tests/st/bgp/test_route_reflector_cluster.py make st-ssl

	# Store off the images if the tests passed.
	#cp calico_containers/calico-node.tar $SEMAPHORE_CACHE_DIR
	#cp calico_containers/busybox.tar $SEMAPHORE_CACHE_DIR
	#docker save --output $SEMAPHORE_CACHE_DIR/calico-build.tar calico/build

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
