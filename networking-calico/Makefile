include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

tox:
	curl -L https://releases.openstack.org/constraints/upper/ussuri -o upper-constraints.txt
	sed -i '/etcd3gw/d' upper-constraints.txt
	docker build -t networking-calico-test .
	docker run -it --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code --rm networking-calico-test tox
