include variables.mk

### Actual rules below here!

.PHONY: create_docker_container clean

all: create_docker_container run_nosetests_docker clean_docker_container

## Setting up

create_docker_container: .docker_container.stamp

.docker_container.stamp: Dockerfile requirements.txt config.json
	$(info +++ Building docker container with Calico $(CALICO_VERSION), Operator $(OPERATOR_VERSION), Flannel $(FLANNEL_VERSION))
	@docker buildx build \
		--quiet \
		-t $(CALICO_POSTRELEASE_TEST_IMAGE) \
		--build-arg VERSION=$(CALICO_VERSION) \
		--build-arg FLANNEL_VERSION=$(FLANNEL_VERSION) \
		--build-arg OPERATOR_VERSION=$(OPERATOR_VERSION) \
		.
	@touch .docker_container.stamp

## Execution 

run_nosetests_docker: create_docker_container
	$(info +++ Running nose tests)
	@docker run -it --rm                     \
		-v ./tests:/code                     \
		-v /run/docker.sock:/run/docker.sock \
		-e NOSE_PROCESSES=$(NOSE_PROCESSES)  \
		-e QUAY_API_TOKEN                    \
		$(CALICO_POSTRELEASE_TEST_IMAGE)     \
		nosetests -vv 

## Cleanup

clean:	clean_docker_container

clean_docker_container:
	$(info +++ Cleaning docker container)
	@docker rmi $(CALICO_POSTRELEASE_TEST_IMAGE) 2> /dev/null || true
	@rm -f .docker_container.stamp