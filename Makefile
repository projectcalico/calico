# jekyll 3.4 has some permissions issue on semaphore, so stick with 3.2 for now.

serve:
	docker run --rm -p 4000:4000 -v $$PWD:/srv/jekyll jekyll/jekyll:3.2 jekyll serve --incremental -c _config.yml,_config.dev.yml

.PHONY: build
_site build:
	docker run --rm -v $$PWD:/srv/jekyll jekyll/jekyll:3.2 jekyll build --incremental

clean:
	docker run --rm -v $$PWD:/srv/jekyll jekyll/jekyll:3.2 jekyll clean


htmlproofer: clean _site
	docker run --rm -v $$PWD/_site:/_site/ quay.io/calico/htmlproofer /_site --file-ignore /v1.5/,/v1.6/ --assume-extension --check-html --empty-alt-ignore
	# Rerun htmlproofer across _all_ files, but ignore failure, allowing us to notice legacy docs issues without failing CI
	-docker run --rm -v $$PWD/_site:/_site/ quay.io/calico/htmlproofer /_site --assume-extension --check-html --empty-alt-ignore
