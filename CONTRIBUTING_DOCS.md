# Contributing to Calico Docs

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

### Faster builds

Jekyll can take a while to render every page. To speed up builds, a supplemental `_config_dev.yml` exists which excludes all
directories except `master`. Include it in your builds:

```
jekyll serve --config _config.yml,_config_dev.yml
```

Or pass enable it in make using the environment variable:

```
DEV=true make serve
```

### Versioning & Branches

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

Calico/node system tests run in a container to ensure all build dependencies are met.

```
make -C calico_node st
```
