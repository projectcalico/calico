include variables.mk

### Binaries we need

bin/yq:
	$(info Downloading YQ from $(YQ4_URL))
	@mkdir -p bin
	@curl -fsSL $(YQ4_URL) -o $(YQ4)
	@chmod +x $(YQ4)

### Utility!

require_var = $(if \
                  $(filter-out undefined,$(origin $(1))),\
                  ,\
                  $(error The variable $(1) is required but is not defined) \
          )

require-vars-%:
	$(foreach var,$(subst -, ,$*),$(call require_var,$(var)))

### Actual rules below here!

.PHONY: create_docker_container clean

all: create_docker_container run_pytests_docker clean_docker_container

## Setting up

create_docker_container: .docker_container.stamp

.docker_container.stamp: bin/yq Dockerfile config.json
	$(info +++ Building docker container with Calico $(CALICO_VERSION), Operator $(OPERATOR_VERSION), Flannel $(FLANNEL_VERSION))
	docker buildx build \
		-t $(CALICO_POSTRELEASE_TEST_IMAGE)              \
		--build-arg UID=$(shell id -u)                   \
		--build-arg VERSION=$(CALICO_VERSION)            \
		--build-arg FLANNEL_VERSION=$(FLANNEL_VERSION)   \
		--build-arg OPERATOR_VERSION=$(OPERATOR_VERSION) \
		.
	@touch .docker_container.stamp

## Execution

run_pytests_docker: create_docker_container
	$(info +++ Running postrelease tests)
	@docker run -it --rm                     \
		-v .:/code                           \
		-v /run/docker.sock:/run/docker.sock \
		$(CALICO_POSTRELEASE_TEST_IMAGE)     \
		pytest -v --junitxml=xunit.xml tests

## Cleanup

# `clean` is meant to be run manually, as it also runs clean_xunit, which
# deletes the xunit file. We actually want that file to exist in e.g. semaphore.
clean: clean_docker_container clean_xunit clean_bin

clean_xunit:
	$(RM) xunit.xml

clean_bin:
	$(RM) -r bin

clean_docker_container: bin/yq
	$(info +++ Cleaning docker container)
	@docker rmi $(CALICO_POSTRELEASE_TEST_IMAGE) 2> /dev/null || true
	$(RM) .docker_container.stamp
