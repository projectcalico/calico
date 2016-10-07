# Project Calico Documentation

This repository is home to documentation, demos, and release information for Project Calico.

**If you are looking for the repository formerly known as `projectcalico/calico`,
it has been renamed to [`projectcalico/felix`](https://github.com/projectcalico/felix).**

If you are looking for the old documentation, see https://docs-archive.projectcalico.org or [view archived documentation for a past calico-containers release](https://github.com/projectcalico/calico-containers/tree/v0.22.0)

## Preview

[Click Here for Live Preview Site](https://projectcalico.github.io/calico/)

## Building

The docs require jekyll, a ruby gem. Install the `github-pages` gem which includes
`jekyll` to ensure you are using the exact version of jekyll that github pages 
is using to serve the live site.

```
gem install github-pages
jekyll serve
```

Alternatively, you can easily volume mount the source files into the official jekyll docker image via using a simple makefile step:

```
make serve
```

As the output states, docs should then be viewable at http://localhost:4000/ .

## Navigation & Sidebar

The docs (currently) are split into 4 sections:

- what
- getting-started
- using
- reference

#### How It Works

The naming and layout of these navbars are stored in `_data/$VERSION/navbars/*`. Jekyll automatically stores information from the `_data` dir in an accessible variable called `site.data`. The toplevel layout (`_layout/docwithnav.html`) will iterate through all the files in `site.data[version].navbars` to construct the sidebar based on which version is being viewed.

> Note: Sidebar paths to index files (see next section) should end in a `/` in the yaml file. Sidebar paths to actual files should not end in a `/` in the yaml file.

## Pathing

URL structure is important. In order to create a toplevel splash page for a URL path, simply name the file `index.md`. See the following example:


| URL                                           | Filepath                                         |
|-----------------------------------------------|--------------------------------------------------|
| `/getting-started/kubernetes/`                | `/getting-started/kubernetes/index.md`           |
| `/getting-started/kubernetes/troubleshooting` | `/getting-started/kubernetes/troubleshooting.md` |


## Linking Content

All links should be absolute links. To link to versioned content, prefix all links with: `{{site.baseurl}}/{{page.version}}/`

> Tip: `page.version` will be inherited from the default set in `_config.yml` for the current page's directory.

## Releases

The following steps detail how to cut a new release:

1. Save off master as a release:

  ```
  cp -R ./master X_Y
  cp -R ./_includes/master ./_includes/X_Y
  cp -R ./_data/master ./_data/X_Y
  ```

2. Add a section in `_config.yaml` so that `page.version` will be set correctly in the new subdirectory:

  ```
  -
    scope:
      path: "X_Y"
    values:
      version: "X_Y"
  ```

3. Add a new `<option>` entry to the `<span class="dropdown">` in `_layouts/docwithnav.html`. (This step should be replaced by automation ASAP.)

## Testing

Print all broken links: `make htmlproofer`

## License

Most of the theming of this site is based on the Kubernetes documentation.  The original Kubernetes Apache license in in [LICENSE](LICENSE).

At least some of this work is based on the basic Jekyll theme from scotch.io - see [scotch.io.github.io license](https://github.com/scotch-io/scotch-io.github.io#mit-license).
