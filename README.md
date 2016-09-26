---
---
# Calico documentation
[Click Here for Demo Site of Master](https://tigera.github.io/calico-docs/)

## Building the docs

First install Jekyll - see [here](https://jekyllrb.com/)

Once installed, from the root of this repo you should be able to run

```
jekyll serve
```

## Changing the version number

The version number of the docs is stored in the default frontmatter build by _config.yml.  When you want to build a new version (or you're rebuilding an old version), change this in the config file - it'll then be reproduced on each page of the docs.

## Building older versions

To build older versions of the docs:

-  Check out the branch you want to build.
-  Update _config.yml with the correct version number (probably not necessary as it should be part of the branch!)
-  run `jekyll build` to build the docs


Having done this, you need to copy the resulting `_site` directory to an appropriate location for hosting.  

One easy way to do this is to copy the _site/* to, say v1_3/* in the master docs.  When you rebuild/serve the master jekyll site, jekyll will just serve up the entire v1_3/ directory as well.

Once you've worked out where you're going to host the docs, though, you'll need to fix up the docs/other_releases pages so that the links to the appropriate versions are correct (both in the old docs you've just built and in the latest docs).

## TOCs and Navigation
The docs are split into 5 sections, with the navigation controlled by _data/globals.yml and an individual yml file for each of the following sections:

- getting-started
- using
- what
- reference
- community

To modify the navigation (e.g. when adding a new file), you should change the yml file for the appropriate section.  The format is, hopefully, pretty obvious.

## Relative and absolute links

You can use relative links in doc pages.  However, if you want to make absolute links (for example, to /images) you should

- include the base.html fie at the top of your markdown

```
{ % include base.html % }
```

- prepend the link or reference with `{{base}}`.  For example `<a href="{{base}}/images"` or `[link]({{base}}/docs/page)`.  The base variable is calculated for each page when served and converts absolute paths to relative (which allows us to not worry about where github pages may host the site, for example).

For reasons related to getting the TOCs working properly with a changing "base" URL, note you shouldn't use "index.md" pages with implicit links to the owning directory as this screws up the calculation of the relative path.


Most of the theming of this site is based on the Kubernetes documentation.  The original Kubernetes Apache license in in [LICENSE](LICENSE).

At least some of this work is based on the basic Jekyll theme from scotch.io - see the license below.

## Developer Notes
- Links to documents in yml sidebar:
  - Must end in `/` if its an `index.md` directory file.
  - Must not end in `/` if its a regular named doc.
