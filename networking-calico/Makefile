include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

export BUILDKIT_PROGRESS=plain

tox:
	docker build -t networking-calico-test .
	docker run -it --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code -e PIP_CONSTRAINT --rm networking-calico-test tox

tox-%: upper-constraints-%.txt
	$(MAKE) tox PIP_CONSTRAINT=/code/upper-constraints-$*.txt

upper-constraints-yoga.txt:
	curl -fsSL --retry 5 https://releases.openstack.org/constraints/upper/yoga -o $@

upper-constraints-caracal.txt:
	curl -fsSL --retry 5 https://raw.githubusercontent.com/openstack/requirements/refs/heads/stable/2024.1/upper-constraints.txt -o $@
