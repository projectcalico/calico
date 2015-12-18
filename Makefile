.PHONY: all binary test plugin ipam ut clean

SRCFILES=$(shell find calico_cni)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)


default: all
all: binary test
binary: dist/calico dist/calico-ipam
test: ut fv
plugin: dist/calico
ipam: dist/calico-ipam


# Builds the Calico CNI plugin binary.
dist/calico: $(SRCFILES) 
	# Make sure the output directory exists.
	mkdir -p dist
	chmod 777 `pwd`/dist

	# Pull the build container.
	docker pull calico/build:latest

	# Build the CNI plugin
	docker run \
	-u user \
	-v `pwd`/dist:/code/dist \
	-v `pwd`/calico_cni:/code/calico_cni \
	calico/build pyinstaller calico_cni/calico_cni.py -a -F -s -n calico --clean

# Makes the IPAM plugin.
dist/calico-ipam: $(SRCFILES)
	mkdir -p dist
	chmod 777 `pwd`/dist

	# Build the CNI IPAM plugin
	docker run \
	-u user \
	-v `pwd`/dist:/code/dist \
	-v `pwd`/calico_cni:/code/calico_cni \
	calico/build pyinstaller calico_cni/ipam.py -a -F -s -n calico-ipam --clean

# Run the unit tests.
ut: 
	docker run --rm -v `pwd`/calico_cni:/code/calico_cni \
	-v `pwd`/calico_cni/nose.cfg:/code/nose.cfg \
	calico/test \
	nosetests calico_cni/tests/unit -c nose.cfg

# Run the fv tests.
fv: 
	docker run --rm -v `pwd`/calico_cni:/code/calico_cni \
	-v `pwd`/calico_cni/nose.cfg:/code/nose.cfg \
	calico/test \
	nosetests calico_cni/tests/fv -c nose.cfg

# Makes tests on Circle CI.
test-circle: binary
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/test sh -c \
	'>/dev/null 2>&1 & \
	cd calico_cni; nosetests tests -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes


## Run etcd in a container. Generally useful.
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.2.2 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

