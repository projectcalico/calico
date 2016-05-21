.PHONY: all policy-agent docker-image clean

SRCDIR=.

default: all
all: policy-agent 

# Build the calico/k8s-policy-agent Docker container.
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
	# Build the docker image for the policy agent.
	docker build -t calico/k8s-policy-agent . 
	touch image.created

clean:
	find . -name '*.pyc' -exec rm -f {} +
	-sudo rm -rf dist
	-docker rmi calico/k8s-policy-agent
	rm -f image.created
