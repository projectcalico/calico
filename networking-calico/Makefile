include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

export BUILDKIT_PROGRESS=plain

# The test environment, for both the container and a native run.
TEST_PYTHON_VERSION := 3.8
TEST_TOX_VERSION := 3.28.0
TEST_ETCD_VERSION := v3.6.0

# NATIVE_PYTHON=true runs tox on this machine rather than in a container, with
# the same interpreter, tox and etcd. tox reformats with an unpinned black, whose
# newest release depends on the interpreter, so the interpreter is pinned too
# rather than taken from the host. Only executables land under bin/; uv keeps
# the interpreter and tox outside the checkout.
ifeq ($(NATIVE_PYTHON),true)
TEST_CODE_DIR := $(CURDIR)
NATIVE_BIN := $(CURDIR)/bin
UV := ../bin/uv
export UV_PYTHON_BIN_DIR := $(NATIVE_BIN)
export UV_TOOL_BIN_DIR := $(NATIVE_BIN)

build-test-container: $(NATIVE_BIN)/tox $(NATIVE_BIN)/etcd

RUN_TEST_CONTAINER = env PATH=$(NATIVE_BIN):$$PATH $(if $(PIP_CONSTRAINT),PIP_CONSTRAINT=$(PIP_CONSTRAINT))

$(UV):
	$(MAKE) -C .. bin/uv

$(NATIVE_BIN)/tox: $(UV)
	$(UV) python install $(TEST_PYTHON_VERSION)
	$(UV) tool install --python $(TEST_PYTHON_VERSION) tox==$(TEST_TOX_VERSION)

$(NATIVE_BIN)/etcd:
	../hack/fetch-file https://github.com/etcd-io/etcd/releases/download/$(TEST_ETCD_VERSION)/etcd-$(TEST_ETCD_VERSION)-linux-amd64.tar.gz /tmp/etcd.tar.gz
	mkdir -p $(NATIVE_BIN)
	tar -xzf /tmp/etcd.tar.gz -C $(NATIVE_BIN) --strip-components=1 etcd-$(TEST_ETCD_VERSION)-linux-amd64/etcd
	rm -f /tmp/etcd.tar.gz
else
TEST_CODE_DIR := /code

build-test-container:
	docker build -t networking-calico-test \
		--build-arg PYTHON_VERSION=$(TEST_PYTHON_VERSION) \
		--build-arg TOX_VERSION=$(TEST_TOX_VERSION) \
		--build-arg ETCD_VERSION=$(TEST_ETCD_VERSION) .

RUN_TEST_CONTAINER = docker run -i --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code -e PIP_CONSTRAINT --rm networking-calico-test
endif

tox: build-test-container
	$(RUN_TEST_CONTAINER) tox -e py38

tox-%: upper-constraints-%.txt
	$(MAKE) tox PIP_CONSTRAINT=$(TEST_CODE_DIR)/upper-constraints-$*.txt

# Functional-verification tests.  Separate target because they spawn a
# real etcd subprocess and use eventlet's cooperative I/O, so they can't
# run alongside the standard unit-test discovery (see tox.ini's [testenv:fv]).
tox-fv: build-test-container
	$(RUN_TEST_CONTAINER) tox -e fv

tox-fv-%: upper-constraints-%.txt
	$(MAKE) tox-fv PIP_CONSTRAINT=$(TEST_CODE_DIR)/upper-constraints-$*.txt

upper-constraints-caracal.txt:
	../hack/fetch-file https://raw.githubusercontent.com/openstack/requirements/refs/heads/$$(./infer-openstack-branch.sh caracal requirements)/upper-constraints.txt $@

fmtpy: build-test-container
	$(RUN_TEST_CONTAINER) tox -e black

flake8: build-test-container
	$(RUN_TEST_CONTAINER) tox -e flake8
