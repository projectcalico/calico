.PHONEY: all binary test ut ut-circle st clean setup-env run-etcd install-completion fast-st

SRCDIR=calico_containers
PYCALICO=$(wildcard $(SRCDIR)/calico_ctl/*.py) $(wildcard $(SRCDIR)/*.py)
BUILD_DIR=build_calicoctl
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt
# There are subdirectories so use shell rather than wildcard
NODE_FILESYSTEM=$(shell find calico_node/filesystem/ -type f)
NODE_FILES=$(wildcard calico_node/*) $(NODE_FILESYSTEM)
WHEEL_VERSION=0.0.0

# These variables can be overridden by setting an environment variable.
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
ST_TO_RUN?=calico_containers/tests/st/

default: all
all: test
binary: dist/calicoctl
node: caliconode.created

caliconode.created: $(PYCALICO) $(NODE_FILES)
	docker build -f calico_node/Dockerfile -t calico/node calico_node
	touch caliconode.created

calicobuild.created: $(BUILD_FILES)
	docker build -f build_calicoctl/Dockerfile -t calico/build .
	touch calicobuild.created

docker:
	# Download the latest docker to test.
	curl https://master.dockerproject.org/linux/amd64/docker-1.9.0-dev -o docker
	chmod +x docker

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

test: st ut 

ut: calicobuild.created
	# Use the `root` user, since code coverage requires the /code directory to
	# be writable.  It may not be writable for the `user` account inside the
	# container.
	docker run --rm -v `pwd`/calico_containers:/code -u root \
	calico/build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	nosetests tests/unit  -c nose.cfg'

# UT runs on Cicle need to create the calicoctl binary
ut-circle: calicobuild.created dist/calicoctl
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	cd calico_containers; nosetests tests/unit -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

calico_containers/busybox.tar:
	docker pull busybox:latest
	docker save --output calico_containers/busybox.tar busybox:latest

calico_containers/routereflector.tar:
	docker pull calico/routereflector:latest
	docker save --output calico_containers/routereflector.tar calico/routereflector:latest

calico_containers/calico-node.tar: caliconode.created
	docker save --output calico_containers/calico-node.tar calico/node

st: docker binary calico_containers/busybox.tar calico_containers/routereflector.tar calico_containers/calico-node.tar run-etcd
	nosetests $(ST_TO_RUN) -sv --nologcapture --with-timer

fast-st: docker calico_containers/busybox.tar calico_containers/routereflector.tar calico_containers/calico-node.tar run-etcd
	# This runs the tests by calling python directory without using the
	# calicoctl binary - this doesn't work with DIND so commenting out for now.
	#	CALICOCTL=$(CURDIR)/calico_containers/calicoctl.py \
	nosetests $(ST_TO_RUN) \
	-sv --nologcapture --with-timer -a '!slow'

run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

create-dind: docker
	@echo "You may want to load calico-node with"
	@echo "docker load --input /code/calico_containers/calico-node.tar"
	@ID=$$(docker run --privileged -v `pwd`:/code -v `pwd`/docker:/usr/local/bin/docker \
	-tid calico/dind:latest) ;\
	docker exec -ti $$ID bash;\
	docker rm -f $$ID

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
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

setup-env:
	virtualenv venv
	venv/bin/pip install --upgrade -r build_calicoctl/requirements.txt
	@echo "run\n. venv/bin/activate"

