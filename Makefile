# Versions
CALICO_DIR=$(shell git rev-parse --show-toplevel)
VERSIONS_FILE?=$(CALICO_DIR)/_data/versions.yml

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

htmlproofer: clean _site
	# Run htmlproofer, failing if we hit any errors. 
	./htmlproofer.sh

	# Run kubeval to check master manifests are valid Kubernetes resources.
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
    
update_canonical_urls:
	# You must pass two version numbers into this command, e.g., make update_canonical_urls OLD=v3.0 NEW=v3.1
	# Looks through all directories and replaces previous latest release version numbers in canonical URLs with new
	find . \( -name '*.md' -o -name '*.html' \) -exec sed -i '/canonical_url:/s/$(OLD)/$(NEW)/g' {} \;
