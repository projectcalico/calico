.PHONY: all policy-controller docker-image clean

SRCDIR=.
CONTAINER_NAME=calico/kube-policy-controller

default: all
all: policy-controller

# Build the calico/kube-policy-controller Docker container.
docker-image: image.created

# Run the unit tests.
ut:
	docker run --rm -v `pwd`:/code \
	calico/test \
	nosetests tests/unit -c nose.cfg

# Makes tests on Circle CI.
test-circle: 
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

image.created:
	# Build the docker image for the policy controller.
	docker build -t $(CONTAINER_NAME) . 
	touch image.created

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)
	$(MAKE) image.created
# It's not possible to check that the version number is correct in the container
# The policy controller doesn't self report its version
	docker tag $(CONTAINER_NAME) $(CONTAINER_NAME):$(VERSION)
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):$(VERSION)

	@echo "Now push the tag and images."
	@echo "git push $(VERSION)"
	@echo "docker push calico/libnetwork-plugin:$(VERSION)"
	@echo "docker push quay.io/calico/libnetwork-plugin:$(VERSION)"

clean:
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf dist image.created
	-docker rmi $(CONTAINER_NAME)
