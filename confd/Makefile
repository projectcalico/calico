include ../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/confd

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

.PHONY: clean
clean:
	rm -rf vendor
	rm -rf bin/*
	rm -rf tests/logs

###############################################################################
# Building the binary
###############################################################################
build: bin/confd-$(ARCH)
build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

bin/confd-$(ARCH): $(SRC_FILES)
	$(call build_binary, $(PACKAGE_NAME), $@)
	ln -sf confd-$(ARCH) bin/confd

###############################################################################
# Unit Tests
###############################################################################

test: ut fv

# No system tests for confd; override the st prerequisite from lib.Makefile.
st:

.PHONY: ut
## Run the fast set of unit tests in a container.
ut:
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -race --junit-report=confd_ut.xml --output-dir=report/ --skip-package=tests .'

UPDATE_EXPECTED_DATA?=false

.PHONY: fv
## Run confd functional verification tests (envtest-based, replaces bash test suite).
fv: setup-envtest
	mkdir -p report
	$(DOCKER_RUN) \
		-v $$(ls -d $(ENVTEST_DIR)/k8s/*-$(BUILDOS)-$(BUILDARCH) | tail -1):/envtest:ro \
		-e KUBEBUILDER_ASSETS=/envtest \
		-e UPDATE_EXPECTED_DATA=$(UPDATE_EXPECTED_DATA) \
		$(CALICO_BUILD) \
		gotestsum --junitfile report/confd_fv.xml -- -count=1 -v -timeout 600s ./tests/...
# -count=1 disables test caching; envtest-based tests should always run fresh.

# Upstream BIRD image (built by bird/). Used to validate rendered golden configs
# against a real BIRD 3.x binary and to extract bird/birdcl for legacy targets.
BIRD_IMAGE ?= $(firstword $(DEV_REGISTRIES))/bird:$(BIRD_VERSION)

.PHONY: bird-image
# Build (or no-op if already present) the upstream calico/bird image locally, so
# validate-bird-config has a real BIRD binary to run. Mirrors node's bird-image
# target; the ../bird producer also applies the plain bird:$(BIRD_VERSION) tag
# that BIRD_IMAGE refers to here.
bird-image:
	$(MAKE) -C ../bird image ARCH=$(ARCH)

.PHONY: validate-bird-config
## Validate every rendered golden BIRD config against a real BIRD 3.x binary
## (bird -p -c). Catches invalid syntax that the golden-file text comparison
## cannot. Runs the BIRD binary from the BIRD_IMAGE container so no local BIRD
## install is required.
validate-bird-config: bird-image
	docker run --rm \
		-v $(CURDIR)/tests/compiled_templates:/golden:ro \
		--entrypoint /bin/sh $(BIRD_IMAGE) -c '\
			fail=0; \
			for cfg in $$(find /golden -name bird.cfg | sort); do \
				if ! bird -p -c "$$cfg" >/tmp/out 2>&1; then \
					echo "FAIL: $$cfg"; cat /tmp/out; fail=1; \
				fi; \
			done; \
			if [ $$fail -eq 0 ]; then echo "All BIRD configs valid."; fi; \
			exit $$fail'


bin/kubectl:
	curl -sSf -L --retry 5 https://dl.k8s.io/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@

bin/bird bin/birdcl:
	-docker rm -f calico-bird
	# BIRD binaries are stored in the calico/bird image (built by bird/).
	# To get them, we create (but don't start) a container from that image.
	docker pull $(BIRD_IMAGE)
	docker create --name calico-bird $(BIRD_IMAGE) /bin/sh
	# Then we copy the files out of the container.  Since docker preserves
	# mtimes on its copy, check the file really did appear, then touch it
	# to make sure that downstream targets get rebuilt.
	docker cp calico-bird:/usr/sbin/bird bin/ && \
	docker cp calico-bird:/usr/sbin/birdcl bin/ && \
	  test -e $@ && \
	  touch $@
	-docker rm -f calico-bird

bin/calico-node:
	cp fakebinary $@
	chmod +x $@

bin/etcdctl:
	curl -sSfL --retry 5 -o /tmp/etcd.tar.gz https://github.com/coreos/etcd/releases/download/$(ETCD_VERSION)/etcd-$(ETCD_VERSION)-linux-$(ARCH).tar.gz
	tar -xz -C bin --strip-components=1 -f /tmp/etcd.tar.gz etcd-$(ETCD_VERSION)-linux-$(ARCH)/etcdctl && rm -f /tmp/etcd.tar.gz

bin/calicoctl:
	make -C ../calicoctl build
	cp ../calicoctl/bin/calicoctl-linux-$(ARCH) $@

bin/typha:
	make -C ../typha build
	cp ../typha/bin/calico-typha-$(ARCH) $@

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download static-checks test validate-bird-config
