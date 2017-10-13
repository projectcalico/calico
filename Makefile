###############################################################################
# Determine whether there's a local yaml installed or use dockerized version.
# Note, to install yaml: "go get github.com/mikefarah/yaml"
GO_BUILD_VER?=v0.7
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
YAML_CMD:=$(shell which yaml || echo docker run --rm -i $(CALICO_BUILD) yaml)

###############################################################################
# Versions
CALICO_DIR=$(shell git rev-parse --show-toplevel)
VERSIONS_FILE?=$(CALICO_DIR)/_data/versions.yml

###############################################################################
# HtmlProofer
HP_IGNORE_LOCAL_DIRS?=$(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - "htmlProoferLocalDirIgnore")

JEKYLL_VERSION=3.5.2
DEV?=false

CONFIG=--config _config.yml
ifeq ($(DEV),true)
	CONFIG:=$(CONFIG),_config_dev.yml
endif

serve:
	docker run --rm -ti -e JEKYLL_UID=`id -u` -p 4000:4000 -v $$PWD:/srv/jekyll jekyll/jekyll:$(JEKYLL_VERSION) jekyll serve --incremental $(CONFIG)

.PHONY: build
_site build:
	docker run --rm -ti -e JEKYLL_UID=`id -u` -v $$PWD:/srv/jekyll jekyll/jekyll:$(JEKYLL_VERSION) jekyll build --incremental $(CONFIG)

clean:
	docker run --rm -ti -e JEKYLL_UID=`id -u` -v $$PWD:/srv/jekyll jekyll/jekyll:$(JEKYLL_VERSION) jekyll clean

htmlproofer: clean _site
	docker run -ti -e JEKYLL_UID=`id -u` --rm -v $$PWD/_site:/_site/ quay.io/calico/htmlproofer /_site --file-ignore ${HP_IGNORE_LOCAL_DIRS} --assume-extension --check-html --empty-alt-ignore --url-ignore "/docs.openshift.org/,#,/github.com\/projectcalico\/calico\/releases\/download/"
	-docker run -ti -e JEKYLL_UID=`id -u` --rm -v $$PWD/_site:/_site/ quay.io/calico/htmlproofer /_site --assume-extension --check-html --empty-alt-ignore --url-ignore "#"
	# Rerun htmlproofer across _all_ files, but ignore failure, allowing us to notice legacy docs issues without failing CI
	
	docker run -v $$PWD:/calico --entrypoint /bin/sh -ti garethr/kubeval:0.1.1 -c 'find /calico/_site/master -name "*.yaml" |grep -v config.yaml | xargs /kubeval'

strip_redirects:
	find \( -name '*.md' -o -name '*.html' \) -exec sed -i'' '/redirect_from:/d' '{}' \;


add_redirects_for_latest: strip_redirects
ifndef VERSION
	$(error VERSION is undefined - run using make add_redirects_for_latest VERSION=vX.Y)
endif
	# Check that the VERSION directory already exists
	@test -d $(VERSION)

	# Add the redirect line - look at .md files only and add "redirect_from: XYZ" on a new line after each "title:"
	find $(VERSION) \( -name '*.md' -o -name '*.html' \) -exec sed -i 's#^title:.*#&\nredirect_from: {}#' '{}' \;

	# Check the redirect_from lines and update the version to be "latest"
	find $(VERSION) \( -name '*.md' -o -name '*.html' \) -exec sed -i 's#^\(redirect_from: \)$(VERSION)#\1latest#' '{}' \;

	# Check the redirect_from lines and strip the .md from the URL
	find $(VERSION) \( -name '*.md' -o -name '*.html' \) -exec sed -i 's#^\(redirect_from:.*\)\.md#\1#' '{}' \;
