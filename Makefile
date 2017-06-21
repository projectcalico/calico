.PHONY: all policy-controller docker-image clean

SRCDIR=.
CONTAINER_NAME=calico/kube-policy-controller

default: all
all: policy-controller

# Build the calico/kube-policy-controller Docker container.
docker-image: image.created

# Run the unit tests.
ut: update-version
	docker run --rm -v `pwd`:/code \
	calico/test \
	nosetests tests/unit -c nose.cfg

# Run system tests.
st: docker-image run-etcd run-k8s-apiserver
	./tests/system/apiserver-reconnection.sh
	$(MAKE) stop-k8s-apiserver stop-etcd

GET_CONTAINER_IP := docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
K8S_VERSION=1.6.4
.PHONY: run-k8s-apiserver stop-k8s-apiserver run-etcd stop-etcd
run-k8s-apiserver: stop-k8s-apiserver
	ETCD_IP=`$(GET_CONTAINER_IP) st-etcd` && \
	docker run --detach \
	  --name st-apiserver \
	gcr.io/google_containers/hyperkube-amd64:v$(K8S_VERSION) \
		  /hyperkube apiserver --etcd-servers=http://$${ETCD_IP}:2379 \
		  --service-cluster-ip-range=10.101.0.0/16 -v=10 \
		  --authorization-mode=RBAC

stop-k8s-apiserver:
	@-docker rm -f st-apiserver

run-etcd: stop-etcd
	docker run --detach \
	--name st-etcd quay.io/coreos/etcd:v3.1.5 \
	etcd \
	--advertise-client-urls "http://127.0.0.1:2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

stop-etcd:
	@-docker rm -f st-etcd

# Makes tests on Circle CI.
test-circle: update-version
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/test sh -c \
	'nosetests tests/unit -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

image.created: update-version
	# Build the docker image for the policy controller.
	docker build -t $(CONTAINER_NAME) .
	touch image.created

# Update the version file.
update-version:
	echo "VERSION='`git describe --tags --dirty`'" > version.py

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)
	$(MAKE) image.created
	docker tag $(CONTAINER_NAME) $(CONTAINER_NAME):$(VERSION)
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):$(VERSION)

# Ensure reported version is correct.
	if ! docker run calico/kube-policy-controller:$(VERSION) version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run calico/kube-policy-controller:$(VERSION) version` "\nExpected version: $(VERSION)"; false; else echo "Version check passed\n"; fi

	@echo "Now push the tag and images."
	@echo "git push $(VERSION)"
	@echo "docker push calico/kube-policy-controller:$(VERSION)"
	@echo "docker push quay.io/calico/kube-policy-controller:$(VERSION)"

clean:
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf dist image.created
	-docker rmi $(CONTAINER_NAME)

ci: clean docker-image ut st
