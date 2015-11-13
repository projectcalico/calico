.PHONEY: all binary node test ut ut-circle st clean run-etcd create-dind help

SRCDIR=calico_containers
PYCALICO=$(wildcard $(SRCDIR)/calico_ctl/*.py) $(wildcard $(SRCDIR)/*.py)
BUILD_DIR=build_calicoctl
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt
TEST_CONTAINER_DIR=calico_test
TEST_CONTAINER_FILES=Dockerfile.test $(TEST_CONTAINER_DIR)/requirements.txt $(shell find calico_containers/tests/ -type f)
# There are subdirectories so use shell rather than wildcard
NODE_FILESYSTEM=$(shell find calico_node/filesystem/ -type f)
NODE_FILES=$(wildcard calico_node/*) $(NODE_FILESYSTEM)
WHEEL_VERSION=0.0.0

# These variables can be overridden by setting an environment variable.
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
ST_TO_RUN?=calico_containers/tests/st/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=
HOST_CHECKOUT_DIR?=$(shell pwd)

default: help
all: test                ## Run all the tests
binary: dist/calicoctl   ## Create the calicoctl binary
node: caliconode.created ## Create the calico/node image
test: st ut              ## Run all the tests

## Display this help text
help:
	# Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
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


calicobuild.created: $(BUILD_FILES)  ## Run all the tests
	docker build -f build_calicoctl/Dockerfile -t calico/build .
	touch calicobuild.created

dist/calicoctl: $(PYCALICO) calicobuild.created
	mkdir -p dist
	chmod 777 dist

	# Ignore errors on both docker commands. CircleCI throws an benign error
	# from the use of the --rm flag

	# mount calico_containers and dist under /code work directory.  Don't use /code
	# as the mountpoint directly since the host permissions may not allow the
	# `user` account in the container to write to it.
	-docker run -v `pwd`/calico_containers:/code/calico_containers \
	 -v `pwd`/dist:/code/dist --rm \
	 calico/build \
	 pyinstaller calico_containers/calicoctl.py -ayF

calicotest.created: $(TEST_CONTAINER_FILES) $(PYCALICO) dist/calicoctl
	docker build -f Dockerfile.test -t calico/test .
	touch calicotest.created

caliconode.created: $(PYCALICO) $(NODE_FILES)
	docker build -f calico_node/Dockerfile -t calico/node calico_node
	touch caliconode.created

calico_containers/calico-node.tar: caliconode.created
	docker save --output calico_containers/calico-node.tar calico/node

calico_containers/busybox.tar:
	docker pull busybox:latest
	docker save --output calico_containers/busybox.tar busybox:latest

calico_containers/routereflector.tar:
	docker pull calico/routereflector:latest
	docker save --output calico_containers/routereflector.tar calico/routereflector:latest

## Download the latest docker binary
docker:
	curl https://get.docker.com/builds/Linux/x86_64/docker-1.9.0 -o docker
	chmod +x docker

## Run the UTs in a container.
ut: calicotest.created
	docker run --rm -v `pwd`/calico_containers:/code calico/test \
		nosetests tests/unit  -c nose.cfg

ut-circle: calicotest.created
	# Test this locally using CIRCLE_TEST_REPORTS=/tmp COVERALLS_REPO_TOKEN=bad make ut-circle
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/test \
	sh -c '\
	cd calico_containers; nosetests tests/unit -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

## Run etcd in a container. Used by the STs and generally useful.
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379" \
	--listen-client-urls "http://0.0.0.0:2379"

## Run the STs in a container
st: run-etcd calicotest.created calico_containers/busybox.tar calico_containers/routereflector.tar calico_containers/calico-node.tar
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
	           --rm -ti \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           -v `pwd`:/code \
	           calico/test \
	           nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer $(ST_OPTIONS)

## Run a Docker in Docker (DinD) container.
create-dind: docker
	@echo "You may want to load calico-node with"
	@echo "docker load --input /code/calico_containers/calico-node.tar"
	@ID=$$(docker run --privileged -v `pwd`:/code -v `pwd`/docker:/usr/local/bin/docker \
	-tid calico/dind:latest) ;\
	docker exec -ti $$ID bash;\
	docker rm -f $$ID

## Clean everything (including stray volumes)
clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -f docker
	-rm -rf dist
	-rm -rf build
	-rm -f calico_containers/busybox.tar
	-rm -f calico_containers/calico-node.tar
	-rm -f calico_containers/routereflector.tar
	-docker rm -f calico-build
	-docker rm -f calico-node
	-docker rmi calico/node
	-docker rmi calico/build
	-docker rmi calico/test
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes
