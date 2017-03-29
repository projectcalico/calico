[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

# Project Calico Documentation

This repository contains the source code for [Project Calico](https://www.projectcalico.org/)'s documentation and demos.  

<blockquote>
Note that the README in this repo is targeted at Calico docs contributors.
<h1>Documentation for Calico users is here:<br><a href="http://docs.projectcalico.org">http://docs.projectcalico.org</a></h1>
</blockquote>

![Project Calico logo](http://docs.projectcalico.org/images/felix.png)

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

The docs (currently) are split into 4 main sections:

- Introduction
- Getting Started
- Using
- Reference

### Introduction

Landing page for new users covering Calico's purpose and high-level topics.

### Getting Started

This should be where new users go. It includes quick-start guides, some basic
tutorials to show off Calico's capabilities, and links to more advanced topics
once users are comfortable with the basics.

Each orchestrator has a landing page that is targeted at people who are coming
to see Calico for the first time. It's a transition from the "marketing" type
material (why is Calico great) to some quick commands people can run to see it
firsthand, and then funnels people off to the usage section for more details.

### Usage

These should all be docs that are a "verb" and task focused. Each doc should
contain why you want to do this, a goal, and a set of steps you can follow to
achieve it. They should not be detailed description of components or tabulated
configuration information.

Examples:

- Configuring BGP Peers
- Enabling IP-in-IP in AWS
- Troubleshooting Calico
- Using calicoctl in a Kubernetes deployment
- Configuring Egress Policy in Kubernetes

### Reference

These docs are complete reference for Calico. If there's a configuration
option you're looking for, it goes here in one of the per-component
references. Not every option has a "how to" guide, but has enough description.
The caveats and considerations when enabling options should be listed here.

Examples:

- Fully tabulated configuration options per-component.
- calicoctl help text.
- Calico API schema reference (policy, ip pool, etcd)
- High-level Calico architecture documentation. (?)

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

See [RELEASING.md](RELEASING.md)

## Testing

Print all broken links: `make htmlproofer`

## License

Most of the theming of this site is based on the Kubernetes documentation.  The original Kubernetes Apache license in in [LICENSE](LICENSE).

At least some of this work is based on the basic Jekyll theme from scotch.io - see [scotch.io.github.io license](https://github.com/scotch-io/scotch-io.github.io#mit-license).
