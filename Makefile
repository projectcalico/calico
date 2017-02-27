JEKYLL_VERSION=3.3.1
serve:
	docker run --rm -ti -e JEKYLL_UID=`id -u` -p 4000:4000 -v $$PWD:/srv/jekyll jekyll/jekyll:$(JEKYLL_VERSION) jekyll serve --incremental

.PHONY: build
_site build:
	docker run --rm -ti -e JEKYLL_UID=`id -u` -v $$PWD:/srv/jekyll jekyll/jekyll:$(JEKYLL_VERSION) jekyll build --incremental

clean:
	docker run --rm -ti -e JEKYLL_UID=`id -u` -v $$PWD:/srv/jekyll jekyll/jekyll:$(JEKYLL_VERSION) jekyll clean


htmlproofer: clean _site
	docker run -ti -e JEKYLL_UID=`id -u` --rm -v $$PWD/_site:/_site/ quay.io/calico/htmlproofer /_site --file-ignore /v1.5/,/v1.6/ --assume-extension --check-html --empty-alt-ignore
	# Rerun htmlproofer across _all_ files, but ignore failure, allowing us to notice legacy docs issues without failing CI
	-docker run -ti -e JEKYLL_UID=`id -u` --rm -v $$PWD/_site:/_site/ quay.io/calico/htmlproofer /_site --assume-extension --check-html --empty-alt-ignore

strip_redirects:
	find -name '*.md' -o -name '*.html' -exec sed -i'' '/redirect_from:/d' '{}' \;


add_redirects_for_latest: strip_redirects
ifndef VERSION
	$(error VERSION is undefined - run using make add_redirects_for_latest VERSION=vX.Y)
endif
	# Check that the VERSION directory already exists
	@test -d $(VERSION)

	# Add the redirect line - look at .md files only and add "redirect_from: XYZ" on a new line after each "title:"
	find $(VERSION) -name '*.md' -o -name '*.html' -exec sed -i 's#^title:.*#&\nredirect_from: {}#' '{}' \;

	# Check the redirect_from lines and update the version to be "latest"
	find $(VERSION) -name '*.md' -o -name '*.html' -exec sed -i 's#^\(redirect_from: \)$(VERSION)#\1latest#' '{}' \;

	# Check the redirect_from lines and strip the .md from the URL
	find $(VERSION) -name '*.md' -o -name '*.html' -exec sed -i 's#^\(redirect_from:.*\)\.md#\1#' '{}' \;

