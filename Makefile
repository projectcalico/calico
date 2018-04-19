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

JEKYLL_VERSION=pages
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

htmlproofer:
	@echo "Do not make docs changes against this branch, please use master."

###############################################################################
# CI / test targets 
###############################################################################

ci: htmlproofer kubeval

kubeval:
	# Run kubeval to check master manifests are valid Kubernetes resources.
		docker run -v $$PWD:/calico --entrypoint /bin/sh -ti garethr/kubeval:0.1.1 -c 'ok=true; for f in `find /calico/_site/v2.6 -name "*.yaml" |grep -v "\(config\|allow-istio-pilot\|30-policy\).yaml"`; do echo Running kubeval on $$f; /kubeval $$f || ok=false; done; $$ok'

htmlproofer-all:
	# Run htmlproofer across _all_ files. This is not part of CI. 
	echo "Running a soft check across all files"
	docker run -ti -e JEKYLL_UID=`id -u` --rm -v $(pwd)/_site:/_site/ quay.io/calico/htmlproofer:${HP_VERSION} /_site --assume-extension --check-html --empty-alt-ignore --url-ignore "#"

###############################################################################
# Docs automation 
###############################################################################

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
