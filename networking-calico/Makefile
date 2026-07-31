include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

export BUILDKIT_PROGRESS=plain

build-test-container:
	docker build -t networking-calico-test .

RUN_TEST_CONTAINER = docker run -i --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code -e PIP_CONSTRAINT --rm networking-calico-test

tox: build-test-container
	$(RUN_TEST_CONTAINER) tox -e py38

tox-%: upper-constraints-%.txt
	$(MAKE) tox PIP_CONSTRAINT=/code/upper-constraints-$*.txt

# Functional-verification tests.  Separate target because they spawn a
# real etcd subprocess and use eventlet's cooperative I/O, so they can't
# run alongside the standard unit-test discovery (see tox.ini's [testenv:fv]).
tox-fv: build-test-container
	$(RUN_TEST_CONTAINER) tox -e fv

tox-fv-%: upper-constraints-%.txt
	$(MAKE) tox-fv PIP_CONSTRAINT=/code/upper-constraints-$*.txt

upper-constraints-caracal.txt:
	curl -fsSL --retry 5 https://raw.githubusercontent.com/openstack/requirements/refs/heads/$$(./infer-openstack-branch.sh caracal requirements)/upper-constraints.txt -o $@

fmtpy: build-test-container
	$(RUN_TEST_CONTAINER) tox -e black

flake8: build-test-container
	$(RUN_TEST_CONTAINER) tox -e flake8
