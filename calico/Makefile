include ../metadata.mk

CALICO_DIR=$(shell git rev-parse --show-toplevel)/calico
VERSIONS_FILE?=$(CALICO_DIR)/_data/versions.yml
JEKYLL_VERSION=pages
HP_VERSION=v0.2
DEV?=false
CONFIG=--config _config.yml
ifeq ($(DEV),true)
	CONFIG:=$(CONFIG),_config_dev.yml
endif

# Set DEV_NULL=true to enable the Null Converter which renders the docs site as markdown.
# This is useful for comparing changes to templates & includes.
ifeq ($(DEV_NULL),true)
	CONFIG:=$(CONFIG),_config_null.yml
endif

include ../metadata.mk
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
LOCAL_USER_ID?=$(shell id -u $$USER)
PACKAGE_NAME = github.com/projectcalico/calico/calico

# Determine whether there's a local yaml installed or use dockerized version.
# Note in order to install local (faster) yaml: "go get github.com/mikefarah/yq.v2"
YAML_CMD:=$(shell which yq.v2 || echo docker run --rm -i mikefarah/yq:2.4.2 yq)

# Local directories to ignore when running htmlproofer
HP_IGNORE_LOCAL_DIRS="/v1.5/,/v1.6/,/v2.0/,/v2.1/,/v2.2/,/v2.3/,/v2.4/,/v2.5/,/v2.6/,/v3.0/"

##############################################################################
# Version information used for cutting a release.
RELEASE_STREAM := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '[0].title' | grep --only-matching --extended-regexp '(v[0-9]+\.[0-9]+)|master')

# Use := so that these V_ variables are computed only once per make run.
CALICO_VER := $(shell cat $(VERSIONS_FILE) | $(YAML_CMD) read - '[0].title')

###############################################################################
# Include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

##############################################################################
serve: bin/helm
	# We have to override JEKYLL_DOCKER_TAG which is usually set to 'pages'.
	# When set to 'pages', jekyll starts in safe mode which means it will not
	# load any plugins. Since we're no longer running in github-pages, but would
	# like to use a docker image that comes preloaded with all the github-pages plugins,
	# its ok to override this variable.
	docker run --rm -it \
	  -v $(CURDIR)/bin/helm:/usr/local/bin/helm:ro \
	  -v $(CURDIR):/srv/jekyll \
	  -v $(CURDIR)/../libcalico-go:/srv/libcalico-go \
	  -e JEKYLL_DOCKER_TAG="" \
	  -e JEKYLL_UID=`id -u` \
	  -p 4000:4000 \
	  jekyll/jekyll:$(JEKYLL_VERSION) jekyll serve --incremental $(CONFIG)

.PHONY: build
_site build: bin/helm bin/helm3
	docker run --rm \
	-e JEKYLL_DOCKER_TAG="" \
	-e JEKYLL_UID=`id -u` \
	-v $(CURDIR)/bin/helm:/usr/local/bin/helm:ro \
	-v $(CURDIR)/:/srv/jekyll \
	-v $(CURDIR)/../libcalico-go:/srv/libcalico-go \
	-v $(VERSIONS_FILE):/srv/jekyll/_data/versions.yml \
	jekyll/jekyll:$(JEKYLL_VERSION) jekyll build --incremental $(CONFIG)
	# Move the manifests into the the generated site, and also update
	# the repos manifests that the site generated, removing the templates dir.
	cp -r ../manifests/ _site/manifests
	rsync -a _site/manifest-templates/ ../manifests/ && rm -r _site/manifest-templates

# Update the static manifests 
gen-manifests: clean _site

## Clean enough that a new release build will be clean
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf _output _site .jekyll-metadata pinned_versions.yaml _includes/charts/*/values.yaml

###############################################################################
# CI / test targets
###############################################################################
ci: htmlproofer kubeval helm-tests gen-manifests check-dirty

htmlproofer: _site
	docker run -ti -e JEKYLL_UID=`id -u` --rm \
		-v $(CURDIR)/_site:/_site/ \
		quay.io/calico/htmlproofer:$(HP_VERSION) \
		/_site --assume-extension --check-html --empty-alt-ignore --file-ignore $(HP_IGNORE_LOCAL_DIRS) --internal_domains "projectcalico.docs.tigera.io" --disable_external --allow-hash-href

kubeval: _site
	# Run kubeval to check master manifests are valid Kubernetes resources.
	-docker run -v $(CURDIR):/calico --entrypoint /bin/sh garethr/kubeval:0.7.3 -c 'ok=true; for f in `find /calico/_site/master -name "*.yaml" |grep -v "\(config\|allow-istio-pilot\|30-policy\|istio-app-layer-policy\|istio-inject-configmap.*\|-cf\).yaml"`; do echo Running kubeval on $$f; /kubeval $$f || ok=false; done; $$ok' 1>stderr.out 2>&1

	# Filter out error loading schema for non-standard resources.
	# Filter out error reading empty secrets (which we use for e.g. etcd secrets and seem to work).
	-grep -v "Could not read schema from HTTP, response status is 404 Not Found" stderr.out | grep -v "invalid Secret" > filtered.out

	# Display the errors with context and fail if there were any.
	-rm stderr.out
	! grep -C3 -P "invalid|\t\*" filtered.out
	rm filtered.out

helm-tests: bin/helm values.yaml
	$(DOCKER_RUN) \
		-v $(CURDIR)/bin/helm3:/usr/local/bin/helm \
		$(CALICO_BUILD) \
		sh -c "$(GIT_CONFIG_SSH) ginkgo -cover -r ./helm-tests -chart-path=./_includes/$(RELEASE_STREAM)/charts/calico $(GINKGO_ARGS)"

###############################################################################
# Docs automation
###############################################################################

# URLs to ignore when checking external links.
HP_IGNORE_URLS="/docs.openshift.org/,/localhost/"

check_external_links: _site
	docker run -ti -e JEKYLL_UID=`id -u` --rm -v $(CURDIR)/_site:/_site/ quay.io/calico/htmlproofer:$(HP_VERSION) /_site --external_only --file-ignore $(HP_IGNORE_LOCAL_DIRS) --assume-extension --url-ignore $(HP_IGNORE_URLS) --internal_domains "docs.projectcalico.org"

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

update_canonical_urls:
	# Looks through all directories and replaces previous latest release version numbers in canonical URLs with new
	python release-scripts/update-canonical-urls.py

###############################################################################
# Release targets
###############################################################################
release-build: .release-$(VERSION).created 
.release-$(VERSION).created:
	$(MAKE) clean chart _site
	touch $@

chart: clean _includes/charts/tigera-operator/values.yaml bin/helm3
	bin/helm3 package ./_includes/charts/tigera-operator \
	--destination ./bin/ \
	--version $(GIT_VERSION) \
	--app-version $(GIT_VERSION)
ifdef CHART_RELEASE
	mv ./bin/tigera-operator-$(GIT_VERSION).tgz ./bin/tigera-operator-$(GIT_VERSION)-$(CHART_RELEASE).tgz
endif

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) helm-index
	touch $@

## Kicks semaphore job which syncs github released helm charts with helm index file
.PHONY: helm-index
helm-index:
	@echo "Triggering semaphore workflow to update helm index."
	SEMAPHORE_PROJECT_ID=30f84ab3-1ea9-4fb0-8459-e877491f3dea SEMAPHORE_WORKFLOW_BRANCH=master SEMAPHORE_WORKFLOW_FILE=../releases/calico/helmindex/update_helm.yml $(MAKE) semaphore-run-workflow

## Generates release notes for the given version.
.PHONY: release-notes
release-notes: #release-prereqs
	VERSION=$(CALICO_VER) GITHUB_TOKEN=$(GITHUB_TOKEN) python2 ./release-scripts/generate-release-notes.py

update-authors:
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN must be set)
endif
	@echo "# Calico authors" > AUTHORS.md
	@echo "" >> AUTHORS.md
	@echo "This file is auto-generated based on contribution records reported" >> AUTHORS.md
	@echo "by GitHub for the core repositories within the projectcalico/ organization. It is ordered alphabetically." >> AUTHORS.md
	@echo "" >> AUTHORS.md
	@docker run -ti --rm -v $(CURDIR):/code -e GITHUB_TOKEN=$(GITHUB_TOKEN) python:3 \
		bash -c 'pip install pygithub && /usr/local/bin/python /code/release-scripts/get-contributors.py >> /code/AUTHORS.md'

###############################################################################
# Utilities
###############################################################################
# TODO: stop using bin/helm as an entrypoint in build scripts.
bin/helm:
	mkdir -p bin
	$(eval TMP := $(shell mktemp -d))
	wget -q https://get.helm.sh/helm-v2.16.3-linux-amd64.tar.gz -O $(TMP)/helm.tar.gz
	tar -zxvf $(TMP)/helm.tar.gz -C $(TMP)
	mv $(TMP)/linux-amd64/helm bin/helm

bin/helm3:
	mkdir -p bin
	$(eval TMP := $(shell mktemp -d))
	wget -q https://get.helm.sh/helm-v3.3.1-linux-amd64.tar.gz -O $(TMP)/helm3.tar.gz
	tar -zxvf $(TMP)/helm3.tar.gz -C $(TMP)
	mv $(TMP)/linux-amd64/helm bin/helm3

.PHONY: values.yaml
values.yaml: _includes/charts/calico/values.yaml _includes/charts/tigera-operator/values.yaml
_includes/charts/%/values.yaml: _plugins/values.rb _plugins/helm.rb _data/versions.yml
	docker run --rm \
	  -v $(CURDIR):/calico \
	  -w /calico \
	  ruby:2.5 ruby ./hack/gen_values_yml.rb --chart $* > $@

DOCS_TEST_CONTAINER=projectcalico/release-test
.PHONY: release-test-image
release-test-image:
	cd release-scripts/tests && docker build -t $(DOCS_TEST_CONTAINER) . && cd -

.PHONY: release-test
release-test: release-test-image
	docker run --rm \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v $(CURDIR):/docs \
	-e RELEASE_STREAM=$(RELEASE_STREAM) \
	$(DOCS_TEST_CONTAINER) sh -c \
	"nosetests . -e "$(EXCLUDE_REGEX)" \
	-s -v --with-xunit \
	--xunit-file='/docs/nosetests.xml' \
	--with-timer $(EXTRA_NOSE_ARGS)"

API_GEN_REPO?=tmjd/gen-crd-api-reference-docs
API_GEN_BRANCH?=kb_v2
OPERATOR_VERSION?=master
OPERATOR_REPO?=tigera/operator
build-operator-reference:
	mkdir -p .go-pkg-cache && \
	   docker run --rm \
	   --net=host \
	   -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	   -v $(CURDIR)/.go-pkg-cache:/go/pkg:rw \
	   -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	   -w /go/src/$(PACKAGE_NAME) \
	   $(CALICO_BUILD) /bin/bash -c 'rm -rf builder && mkdir builder && cd builder && \
	           git clone --depth=1 -b $(API_GEN_BRANCH) https://github.com/$(API_GEN_REPO) api-gen && cd api-gen && \
	           go mod edit -replace github.com/tigera/operator=github.com/$(OPERATOR_REPO)@$(OPERATOR_VERSION) && \
	           go mod download all && go build && \
	           ./gen-crd-api-reference-docs -config /go/src/$(PACKAGE_NAME)/reference/installation/config.json \
	                   -api-dir github.com/tigera/operator/api -out-file /go/src/$(PACKAGE_NAME)/reference/installation/_api.html'
