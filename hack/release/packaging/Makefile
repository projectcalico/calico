
.PHONY: release-publish release
VERSION ?= master
release-publish:
	VERSION=$(VERSION) PUBLISH=true utils/create-update-packages.sh
release:
	VERSION=$(VERSION) utils/create-update-packages.sh
set-git-identity:
	$(info *** Setting git identity to Daniel Fox <dan.fox@tigera.io> (unless it is already set))
	@git config --get user.name >/dev/null || git config user.name "Daniel Fox" && echo "Setting git user.name == Daniel Fox"
	@git config --get user.email >/dev/null || git config user.email "dan.fox@tigera.io"
