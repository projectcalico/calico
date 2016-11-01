# Project Calico Documentation

![Project Calico logo](http://docs.projectcalico.org/images/felix.png)

This repository contains the source code for [Project Calico](https://www.projectcalico.org/)'s documentation and demos.  

**If you are a Calico user, you probably want [the live documentation site](https://projectcalico.github.io/calico/).**

**If you are looking for the repository formerly known as `projectcalico/calico`,
it has been renamed to [`projectcalico/felix`](https://github.com/projectcalico/felix).**

You can find archives of the previous documentation at:

- https://docs-archive.projectcalico.org (for general information and OpenStack), and
- https://github.com/projectcalico/calico-containers/tree/v0.22.0 (for container integrations)

## Building

The docs require jekyll, a ruby gem. Install the `github-pages` gem which includes
`jekyll` to ensure you are using the exact version of jekyll that github pages
is using to serve the live site.

```
gem install github-pages
jekyll serve -I
```

>Note:As more versioned directories are created, build speeds will increase by a
factor of 2. The `-I` is an optional flag for development that enables
incremental builds, allowing jekyll to only rebuild changed files. This should
keep subsequent builds down to less than one second.


Alternatively, you can easily volume mount the source files into the official jekyll docker image via using a simple makefile step:

```
make serve
```

As the output states, docs should then be viewable at http://localhost:4000/ .

## Versioning & Branches
The live site is generated from the master branch of this repository.

Documentation for past releases is maintained as a folder in the root of this repository.

Most pull requests which modify information in the docs should primarily target
the `/master/` folder, especially if they are describing newly added features.
However, changes should also be applied to past-release directories if they fix
general typos or incorrect information.

##### How to Quickly Back-Apply Master Changes to a Previous Release
Let's say there's a single commit that makes changes to Master which I want
to apply to the v1.5 directory. First, generate a diff:
```
git diff f35c02fe73e6a64d187ee3f6e9298ca47ded91ab^1 f35c02fe73e6a64d187ee3f6e9298ca47ded91ab > my-patch.diff
```

Then, apply that diff to the target version directory.
```
git apply -p2 --directory=v1.5 my-patch.diff
```
- `-p2` strips off /master on the front of the paths.
- `--directory=v1.5` adds "v1.5" to the start of the paths.

Then simply inspect the results (`git status`, `git diff`, etc.) and commit.

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

1. Run the Release Script, which will walk through creation of the necessary release directories,
and will replace references to nightly artifacts with release ones:

  ```
  python release-scripts/do_release.py
  ```

2. Add a section in `_config.yaml` so that `page.version` will be set correctly in the new subdirectory:

  ```
  -
    scope:
      path: vX.Y
    values:
      version: vX.Y
  ```

3. Add a new `<option>` entry to the `<span class="dropdown">` in `_layouts/docwithnav.html`. (This step should be replaced by automation ASAP.)

4. Modify the redirect in `/index.html` to point to your new release.

5. Commit the changes for steps 2-4.

## Testing

Print all broken links: `make htmlproofer`

## License

Most of the theming of this site is based on the Kubernetes documentation.  The original Kubernetes Apache license in in [LICENSE](LICENSE).

At least some of this work is based on the basic Jekyll theme from scotch.io - see [scotch.io.github.io license](https://github.com/scotch-io/scotch-io.github.io#mit-license).
