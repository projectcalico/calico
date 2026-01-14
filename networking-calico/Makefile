include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

export BUILDKIT_PROGRESS=plain

build-test-container:
	docker build -t networking-calico-test .

RUN_TEST_CONTAINER = docker run -it --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code -e PIP_CONSTRAINT --rm networking-calico-test

tox: build-test-container
	$(RUN_TEST_CONTAINER) tox -e py38

tox-%: upper-constraints-%.txt
	$(MAKE) tox PIP_CONSTRAINT=/code/upper-constraints-$*.txt

upper-constraints-yoga.txt:
	curl -fsSL --retry 5 https://releases.openstack.org/constraints/upper/yoga -o $@

upper-constraints-caracal.txt:
	curl -fsSL --retry 5 https://raw.githubusercontent.com/openstack/requirements/refs/heads/$$(./infer-openstack-branch.sh caracal requirements)/upper-constraints.txt -o $@

fmtpy: build-test-container
	$(RUN_TEST_CONTAINER) tox -e black

flake8: build-test-container
	$(RUN_TEST_CONTAINER) tox -e flake8
