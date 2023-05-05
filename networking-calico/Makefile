include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

export BUILDKIT_PROGRESS=plain

tox:
	docker build -t networking-calico-test .
	docker run -it --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code -e PIP_CONSTRAINT --rm networking-calico-test tox

tox-ussuri:
	curl -L https://releases.openstack.org/constraints/upper/ussuri -o upper-constraints-ussuri.txt
	sed -i '/etcd3gw/d' upper-constraints-ussuri.txt
	$(MAKE) tox PIP_CONSTRAINT=/code/upper-constraints-ussuri.txt

tox-yoga:
	curl -L https://releases.openstack.org/constraints/upper/yoga -o upper-constraints-yoga.txt
	sed -i '/etcd3gw/d' upper-constraints-yoga.txt
	$(MAKE) tox PIP_CONSTRAINT=/code/upper-constraints-yoga.txt
