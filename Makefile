.PHONY: all binary ut clean

SRCDIR=.

default: all
all: binary create 

binary: 
	# Build the kubernetes policy agent
	docker run --rm \
	-v `pwd`:/code \
	calico/build \
	pyinstaller policy_agent.py -ayF 

create: 
	# Build NetworkPolicy install tool. 
	docker run --rm \
	-v `pwd`:/code \
	calico/build \
	pyinstaller create.py -ayF 

docker-image: binary
	docker build -t calico/k8s-policy-agent . 
	docker save -o k8s-network-policy.tar calico/k8s-policy-agent

clean:
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes
