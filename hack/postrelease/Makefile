include variables.mk

### Actual rules below here!

.PHONY: create_docker_container clean

all: create_docker_container run_nosetests_docker clean_docker_container

## Setting up

create_docker_container: .docker_container.stamp

.docker_container.stamp: Dockerfile requirements.txt config.json
	$(info +++ Building docker container with Calico $(CALICO_VERSION), Operator $(OPERATOR_VERSION), Flannel $(FLANNEL_VERSION))
	docker buildx build \
		-t $(CALICO_POSTRELEASE_TEST_IMAGE)              \
		--build-arg VERSION=$(CALICO_VERSION)            \
		--build-arg FLANNEL_VERSION=$(FLANNEL_VERSION)   \
		--build-arg OPERATOR_VERSION=$(OPERATOR_VERSION) \
		.
	@touch .docker_container.stamp

## Execution

run_nosetests_docker: create_docker_container
	$(info +++ Running postrelease tests)
	@docker run -it --rm                         \
		-v .:/code                           \
		-v /run/docker.sock:/run/docker.sock \
		-e QUAY_TOKEN                        \
		$(CALICO_POSTRELEASE_TEST_IMAGE)     \
		pytest -v --junitxml=xunit.xml tests

## Cleanup

# `clean` is meant to be run manually, as it also runs clean_xunit, which
# deletes the xunit file. We actually want that file to exist in e.g. semaphore.
clean: clean_docker_container clean_xunit

clean_xunit:
	@rm -f xunit.xml

clean_docker_container:
	$(info +++ Cleaning docker container)
	@docker rmi $(CALICO_POSTRELEASE_TEST_IMAGE) 2> /dev/null || true
	@rm -f .docker_container.stamp
