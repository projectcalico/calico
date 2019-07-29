
.PHONY: release-publish
VERSION ?= master
release-publish:
	VERSION=$(VERSION) utils/create-update-packages.sh
