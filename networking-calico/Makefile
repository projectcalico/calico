include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

export BUILDKIT_PROGRESS=plain

tox:
	curl -L https://releases.openstack.org/constraints/upper/ussuri -o upper-constraints-ussuri.txt
	sed -i '/etcd3gw/d' upper-constraints-ussuri.txt
	docker build -t networking-calico-test .
	docker run -it --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code -e PIP_CONSTRAINT=/code/upper-constraints-ussuri.txt --rm networking-calico-test tox
