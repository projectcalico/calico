.PHONY: all policy-agent policy-tool docker-image clean

SRCDIR=.

default: all
all: policy-agent policy-tool 

# Build the policy agent binary.
policy-agent: dist/policy_agent

# Build the policy command line tool.
policy-tool: dist/policy

# Build the calico/k8s-policy-agent Docker container.
docker-image: image.created

dist/policy_agent: 
	# Build the kubernetes policy agent
	docker run --rm \
	-v `pwd`:/code \
	calico/build \
	pyinstaller policy_agent.py -ayF 

dist/policy: $(shell find policy_tool) 
	# Build NetworkPolicy install tool. 
	docker run --rm \
	-v `pwd`:/code \
	calico/build \
	pyinstaller policy_tool/policy.py -ayF 

# Run the unit tests.
ut:
	docker run --rm -v `pwd`:/code \
	calico/test \
	nosetests tests/unit -c nose.cfg

image.created: dist/policy_agent 
	# Build the docker image for the policy agent.
	docker build -t calico/k8s-policy-agent . 
	touch image.created

clean:
	find . -name '*.pyc' -exec rm -f {} +
	-sudo rm -rf dist
	-docker rmi calico/k8s-policy-agent
	rm -f image.created
