include ../metadata.mk

###############################################################################
# TODO: Release
###############################################################################

tox:
	docker build -t networking-calico-test .
	docker run -it --user `id -u`:`id -g` -v `pwd`:/code -w /code -e HOME=/code --rm networking-calico-test tox
