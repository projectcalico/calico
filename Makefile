serve:
	docker run --rm -p 4000:4000 -v $$PWD:/srv/jekyll jekyll/jekyll

# Be careful - this doesn't specify all the deps
_site:
	docker run --rm -v $$PWD:/srv/jekyll jekyll/jekyll jekyll build

clean:
	docker run --rm -v $$PWD:/srv/jekyll jekyll/jekyll jekyll clean 
	

htmlproofer: _site
	docker run --rm -v $$PWD/_site:/_site/calico/ 18fgsa/html-proofer /_site --assume-extension --check-html --disable-external --empty-alt-ignore
	docker run --rm -v $$PWD/_site:/_site/calico/ 18fgsa/html-proofer /_site --external-only
