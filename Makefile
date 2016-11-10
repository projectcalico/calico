serve:
	docker run --rm -p 4000:4000 -v $$PWD:/srv/jekyll jekyll/jekyll

# Be careful - this doesn't specify all the deps
_site:
	docker run --rm -v $$PWD:/srv/jekyll jekyll/jekyll jekyll build

clean:
	docker run --rm -v $$PWD:/srv/jekyll jekyll/jekyll jekyll clean 
	

htmlproofer: _site
	docker run --rm -v $$PWD/_site:/_site/ quay.io/calico/htmlproofer /_site --assume-extension --check-html --empty-alt-ignore
