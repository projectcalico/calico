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
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, $(PACKAGE_NAME), $@)
else
	$(call build_binary, $(PACKAGE_NAME), $@)
endif
	ln -sf confd-$(ARCH) bin/confd

###############################################################################
# Unit Tests
###############################################################################
# Set to true when calling test-xxx to update the rendered templates instead of
# checking them.
UPDATE_EXPECTED_DATA?=false

test: ut fv test-kdd test-etcd

.PHONY: test-kdd
## Run template tests against KDD
test-kdd: bin/confd-$(ARCH) bin/kubectl bin/bird bin/bird6 bin/calico-node bin/calicoctl bin/typha run-k8s-apiserver
	-git clean -fx etc/calico/confd
	mkdir -p tests/logs
	docker run --rm --net=host \
		-v $(CERTS_PATH):/home/user/certs \
		-v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-v $(CURDIR)/etc/calico:/etc/calico/ \
		-v $(CURDIR)/../:/go/src/github.com/projectcalico/calico:rw \
		-e CALICO_CRD_PATH=$(CALICO_CRD_PATH) \
		-e CALICO_API_GROUP=$(CALICO_API_GROUP) \
		-e GOPATH=/go \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e FELIX_TYPHAADDR=127.0.0.1:5473 \
		-e FELIX_TYPHAREADTIMEOUT=50 \
		-e UPDATE_EXPECTED_DATA=$(UPDATE_EXPECTED_DATA) \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) /tests/test_suite_kdd.sh || \
	{ \
	    echo; \
	    echo === confd single-shot log:; \
	    cat tests/logs/kdd/logss || true; \
	    echo; \
	    echo === confd daemon log:; \
	    cat tests/logs/kdd/logd1 || true; \
	    echo; \
	    echo === Typha log:; \
	    cat tests/logs/kdd/typha || true; \
	    echo; \
	    false; \
	}
	-git clean -fx etc/calico/confd

.PHONY: test-etcd
## Run template tests against etcd
test-etcd: bin/confd-$(ARCH) bin/etcdctl bin/bird bin/bird6 bin/calico-node bin/kubectl bin/calicoctl run-etcd run-k8s-apiserver
	-git clean -fx etc/calico/confd
	mkdir -p tests/logs
	docker run --rm --net=host \
		-v $(CERTS_PATH):/home/user/certs \
		-v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-v $(CURDIR)/etc/calico:/etc/calico/ \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-e GOPATH=/go \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e UPDATE_EXPECTED_DATA=$(UPDATE_EXPECTED_DATA) \
		$(CALICO_BUILD) /tests/test_suite_etcd.sh
	-git clean -fx etc/calico/confd

.PHONY: ut
## Run the fast set of unit tests in a container.
ut:
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -race --junit-report=confd_ut.xml --output-dir=report/ .'

.PHONY: fv
## Run confd functional verification tests (envtest-based, replaces bash test suite).
fv: setup-envtest
	$(DOCKER_RUN) \
		-v $$(ls -d $(ENVTEST_DIR)/k8s/*-$(BUILDOS)-$(BUILDARCH) | tail -1):/envtest:ro \
		-e KUBEBUILDER_ASSETS=/envtest \
		$(CALICO_BUILD) \
		go test -count=1 -v -timeout 600s ./confd/tests/...


bin/kubectl:
	curl -sSf -L --retry 5 https://dl.k8s.io/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@

bin/bird bin/bird6:
	-docker rm -f calico-bird
	# Latest BIRD binaries are stored in automated builds of calico/bird.
	# To get them, we create (but don't start) a container from that image.
	docker pull calico/bird:$(BIRD_VERSION)-$(ARCH)
	docker create --name calico-bird calico/bird:$(BIRD_VERSION)-$(ARCH) /bin/sh
	# Then we copy the files out of the container.  Since docker preserves
	# mtimes on its copy, check the file really did appear, then touch it
	# to make sure that downstream targets get rebuilt.
	docker cp calico-bird:/bird bin/ && \
	docker cp calico-bird:/bird6 bin/ && \
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

fv st:
	@echo "No FVs or STs available."

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download static-checks test
