serve:
	docker run --rm -p 4000 -v $$PWD:/srv/jekyll jekyll/jekyll

# Be careful - this doesn't specify all the deps
_site:
	docker run --rm -p 4000 -v $$PWD:/srv/jekyll jekyll/jekyll jekyll build

clean:
	docker run --rm -p 4000 -v $$PWD:/srv/jekyll jekyll/jekyll jekyll clean 
	

htmlproofer: _site
	docker run --rm -v $$PWD:/site 18fgsa/html-proofer /site/_site --assume-extension --check-html --disable-external
	docker run --rm -v $$PWD:/site 18fgsa/html-proofer /site/_site --external-only
