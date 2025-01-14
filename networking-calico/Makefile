include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

export BUILDKIT_PROGRESS=plain

tox:
	docker build -t networking-calico-test .
	docker run -it --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code -e PIP_CONSTRAINT --rm networking-calico-test tox

tox-%:
	curl -L $${UPPER_CONSTRAINTS_FILE:-https://releases.openstack.org/constraints/upper/$*} -o upper-constraints-$*.txt
	$(MAKE) tox PIP_CONSTRAINT=/code/upper-constraints-$*.txt
