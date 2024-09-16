
.PHONY: release-publish release
VERSION ?= master
release-publish:
	VERSION=$(VERSION) PUBLISH=true utils/create-update-packages.sh
release:
	VERSION=$(VERSION) utils/create-update-packages.sh
