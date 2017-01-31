.PHONY: all binary calico/node test clean help
default: help
all: test                                               ## Run all the tests
test: st test-containerized node-test-containerized     ## Run all the tests
all: dist/calicoctl dist/calicoctl-darwin-amd64 dist/calicoctl-windows-amd64.exe test-containerized node-test-containerized

# Include the build file for calico/node (This also pulls in Makefile.calicoctl)
include Makefile.calico-node


# This depends on clean to ensure that dependent images get untagged and repulled
.PHONY: semaphore
semaphore: clean
	# Clean up unwanted files to free disk space.
	bash -c 'rm -rf /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv}'

	# Run the containerized UTs first.
	$(MAKE) test-containerized
	$(MAKE) node-test-containerized

	# Actually run the tests (refreshing the images as required), we only run a
	# small subset of the tests for testing SSL support.  These tests are run
	# using "latest" tagged images.
	$(MAKE) calico/ctl calico/node st
	ST_TO_RUN=tests/st/policy $(MAKE) st-ssl

	# Make sure that calicoctl builds cross-platform.
	$(MAKE) dist/calicoctl-darwin-amd64 dist/calicoctl-windows-amd64.exe

	# Assumes that a few environment variables exist - BRANCH_NAME PULL_REQUEST_NUMBER
	# If this isn't a PR, then push :BRANCHNAME tagged and :CALICOCONTAINERS_VERSION
	# tagged images to Dockerhub and quay for both calico/node and calico/ctl.  This
	# requires a rebuild of calico/ctl in both cases.
	set -e; \
	if [ -z $$PULL_REQUEST_NUMBER ]; then \
		rm dist/calicoctl ;\
		CALICOCTL_NODE_VERSION=$$BRANCHNAME $(MAKE) calico/ctl ;\
		docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push quay.io/$(NODE_CONTAINER_NAME):$$BRANCH_NAME; \
		docker tag $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push $(NODE_CONTAINER_NAME):$$BRANCH_NAME; \
		docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push quay.io/$(CTL_CONTAINER_NAME):$$BRANCH_NAME; \
		docker tag $(CTL_CONTAINER_NAME) $(CTL_CONTAINER_NAME):$$BRANCH_NAME && \
		docker push $(CTL_CONTAINER_NAME):$$BRANCH_NAME; \
		rm dist/calicoctl ;\
		CALICOCTL_NODE_VERSION=$(CALICOCONTAINERS_VERSION) $(MAKE) calico/ctl ;\
		docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push quay.io/$(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
		docker tag $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push $(NODE_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
		docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push quay.io/$(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
		docker tag $(CTL_CONTAINER_NAME) $(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION) && \
		docker push $(CTL_CONTAINER_NAME):$(CALICOCONTAINERS_VERSION); \
	fi

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)

	# Check to make sure the tag isn't "-dirty".
	if git describe --tags --dirty | grep dirty; \
	then echo current git working tree is "dirty". Make sure you do not have any uncommitted changes ;false; fi

	# Build the calicoctl binaries, as well as the calico/ctl and calico/node images.
	CALICOCTL_NODE_VERSION=$(VERSION) $(MAKE) dist/calicoctl dist/calicoctl-darwin-amd64 dist/calicoctl-windows-amd64.exe 
	CALICOCTL_NODE_VERSION=$(VERSION) $(MAKE) calico/ctl calico/node

	# Check that the version output includes the version specified.
	# Tests that the "git tag" makes it into the binaries. Main point is to catch "-dirty" builds
	# Release is currently supported on darwin / linux only.
	if ! docker run $(CTL_CONTAINER_NAME) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(CTL_CONTAINER_NAME) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	# Retag images with corect version and quay
	docker tag $(NODE_CONTAINER_NAME) $(NODE_CONTAINER_NAME):$(VERSION)
	docker tag $(CTL_CONTAINER_NAME) $(CTL_CONTAINER_NAME):$(VERSION)
	docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):$(VERSION)
	docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):$(VERSION)
	docker tag $(NODE_CONTAINER_NAME) quay.io/$(NODE_CONTAINER_NAME):latest
	docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):latest

	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(NODE_CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(NODE_CONTAINER_NAME):$(VERSION)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME):$(VERSION)

	# Check that the images container the right sub-components
	docker run $(NODE_CONTAINER_NAME) calico-felix --version
	docker run $(NODE_CONTAINER_NAME) libnetwork-plugin -v

	@echo "\nNow push the tag and images. Then create a release on Github and"
	@echo "attach dist/calicoctl, dist/calicoctl-darwin-amd64, and dist/calicoctl-windows-amd64.exe binaries"
	@echo "\nAdd release notes for calicoctl and calico/node. Use this command"
	@echo "to find commit messages for this release: git log --oneline <old_release_version>...$(VERSION)"
	@echo "\nRelease notes for sub-components can be found at"
	@echo "https://github.com/projectcalico/<component_name>/releases/tag/<version>"
	@echo "\nAdd release notes from the following sub-component version releases:"
	@echo "\nfelix:$(FELIX_VER)"
	@echo "\nlibnetwork-plugin:$(LIBNETWORK_PLUGIN_VER)"
	@echo "\nlibcalico-go:$(LIBCALICOGO_VER)"
	@echo "\ncalico-bgp-daemon:$(GOBGPD_VER)"
	@echo "\ncalico-bird:$(BIRD_VER)"
	@echo "\nconfd:$(CONFD_VER)"
	@echo "git push origin $(VERSION)"
	@echo "docker push calico/ctl:$(VERSION)"
	@echo "docker push quay.io/calico/ctl:$(VERSION)"
	@echo "docker push calico/node:$(VERSION)"
	@echo "docker push quay.io/calico/node:$(VERSION)"
	@echo "docker push calico/ctl:latest"
	@echo "docker push quay.io/calico/ctl:latest"
	@echo "docker push calico/node:latest"
	@echo "docker push quay.io/calico/node:latest"
	@echo "See RELEASING.md for detailed instructions."

## Clean enough that a new release build will be clean
clean: clean-calicoctl
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf dist build certs *.tar vendor $(NODE_CONTAINER_DIR)/filesystem/bin

	# Delete images that we built in this repo
	docker rmi $(NODE_CONTAINER_NAME):latest || true

	# Retag and remove external images so that they will be pulled again
	# We avoid just deleting the image. We didn't build them here so it would be impolite to delete it.
	docker tag $(FELIX_CONTAINER_NAME) $(FELIX_CONTAINER_NAME)-backup && docker rmi $(FELIX_CONTAINER_NAME) || true
	docker tag $(SYSTEMTEST_CONTAINER) $(SYSTEMTEST_CONTAINER)-backup && docker rmi $(SYSTEMTEST_CONTAINER) || true

.PHONY: help
## Display this help text
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	$(info Available targets)
	@awk '/^[a-zA-Z\-\_0-9\/]+:/ {                                      \
		nb = sub( /^## /, "", helpMsg );                                \
		if(nb == 0) {                                                   \
			helpMsg = $$0;                                              \
			nb = sub( /^[^:]*:.* ## /, "", helpMsg );                   \
		}                                                               \
		if (nb)                                                         \
			printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg;  \
	}                                                                   \
	{ helpMsg = $$0 }'                                                  \
	width=20                                                            \
	$(MAKEFILE_LIST)
