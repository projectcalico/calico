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
