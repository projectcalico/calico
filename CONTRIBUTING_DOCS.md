# Contributing to Calico documentation

## Overview

We welcome contributions to the Calico documentation.

Instead of filing a GitHub issue, consider making a PR instead. You are likely to see a much more rapid resolution.

The doc contribution process works as follows.

1. Fork the [Project Calico repo](https://github.com/projectcalico/calico).
1. Create a branch in your fork off of the master branch.
1. Give your branch a short but descriptive name.
1. Preview your changes to make sure they render as expected. You can either [build the site locally](#building-the-doc-site-locally) or go directly to the "submit a pull request" to [build the site with the Project Calico CI/CD system](#previewing-the-changes-from-cicd).
1. Check for broken links. You can either [check for broken links](#checking-for-broken-links) in your local environment or submit a pull request and use the output of the Semaphore job.
1. Submit a pull request (PR) against the master branch of the [Project Calico repo](https://github.com/projectcalico/calico).
1. If you haven't already signed our contributor agreement, GitHub will prompt you to do so (required).
1. Request a review from one or more Calico maintainers.
1. After getting the approval of at least one Calico maintainer, we ask that you [backport the changes in the `master` folder to the folders of the last two releases](#how-to-quickly-apply-changes-in-master-to-a-previous-release), if appropriate.
1. Squash your commits.
1. One of the doc repo maintainers will give the PR a final look and then merge it.
1. The merge into master will kick off a new build of the live site. You should see your changes on the live site shortly after they are merged.

> **Important**: Ensure that your contribution conforms to the [Calico documentation style guide](DOC_STYLE_GUIDE.md).

> **Note**: For contributions that affect just one page, you can use the **Edit this page** buttons in the doc site. This allows you to skip a few steps in the process outlined above, but is suitable only for small contributions.

We also encourage you to review [Doc site organization](#doc-site-organization), [Organizational changes](#organizational-changes), [Link syntax](#link-syntax), and [RELEASING.md](RELEASING.md) for additional information.

## Previewing your changes

### Building the doc site locally

We use GitHub Pages and Jekyll to serve and build our site. While there are [several ways to build the site locally](https://help.github.com/articles/setting-up-your-github-pages-site-locally-with-jekyll/), we recommend using our Docker image and the Makefile in the root of the repo. These will allow you to build the site with a single command.

> **Prerequisite**: [Docker](https://docs.docker.com/engine/installation/).

Navigate into the root of the repo and issue the following command from a terminal prompt.

```
make serve
```

Once the build completes, it returns a URL as the value of `Server address:`. Copy and paste this URL into your browser to view the site.

> **Note**: To view the changes that you've made in the master branch, select **nightly** from the **Releases** page.

> **Pro tip**: Jekyll can take a while to render every page. To speed up builds, a supplemental `_config_dev.yml` exists which excludes all directories except `master`. You can include it in your builds as follows `jekyll serve --config _config.yml,_config_dev.yml`. Alternatively, you can pass enable it in `make` using the following environment variable `DEV=true make serve`.

### Previewing the changes from CI/CD

The Project Calico CI/CD system will generate a site preview automatically with every docs change. An automated response to the PR will indicate "Deploy preview for calico ready!" and provide a link to the preview. If your change is minor and you are not a regular contributor to the project, this method may be easier than building the doc site locally.

**Note** To view the changes you've made to the master branch, select **nightly** from the **Releases** page. 

## Checking for broken links

> **Prerequisite**: [Docker](https://docs.docker.com/engine/installation/).

To check for broken links, navigate into the root of the repo and issue the following command from a terminal prompt.

```
make htmlproofer
```

The submission of a PR kicks off a continuous integration process which includes a `make htmlproofer` command. Any errors from `htmlproofer` will cause your PR to fail the continuous integration test, so it's best to run this locally before submitting your PR.

However, you can also run this after submitting your PR and experiencing an `htmlproofer` failure from the Semaphore job.

## How to quickly apply changes in master to a previous release

Let's say there's a single commit that makes changes to the `master` directory which I want to apply to the `v1.5` directory.

1. Generate a diff. A sample command follows which stores the diff in a file called `my-patch.diff`.

    ```
    git diff f35c02fe73e6a64d187ee3f6e9298ca47ded91ab^1 f35c02fe73e6a64d187ee3f6e9298ca47ded91ab > my-patch.diff
    ```

1. Apply the diff to the target version directory.

    ```
    git apply -p2 --directory=v1.5 my-patch.diff
    ```

    - `-p2` strips off /master on the front of the paths.
    - `--directory=v1.5` adds "v1.5" to the start of the paths.

1. Inspect the results (`git status`, `git diff`, etc.) and commit.

## Doc site organization

The docs are divided into the following sections:

- [Introduction](#introduction)
- [Install](#install)
- [Operations](#operations)
- [Networking](#networking)
- [Security](#security)
- [Reference](#reference)

Except for Introduction and Reference, content should be tasked-based. All top-level titles in topics should use an action verb (e.g. configure, enable, modify) with initial caps. For example:

- Configure BGP peers
- Enable overlay networking
- Troubleshoot Calico
- Use calicoctl in a Kubernetes deployment
- Configure egress policy in Kubernetes

Detailed description of components or tabulated configuration information should go in the [Reference](#reference) section.

### Introduction

This page describes Calico and the primary reasons for using it.

### Install

Calico can be installed in many different deployments including on-premises and cloud providers. This section includes how to install a standalone Calico cluster for workloads, and how to install Calico on non-cluster hosts. This section covers steps to an "up and running" state. Any task beyond "up and running" should be added to other tabs. 

### Operations

This section contains post-install, task-based content.  

### Networking

This section contains task-based content for networking using the Calico CNI and Calico IPAM.

### Security

This section contains task-based content for securing Calico components, workloads, and non-cluster hosts using Calico network policy.

### Reference

This section contain reference content including full details of APIs and Resources. Add configuration options in one of the per-component references, and list any caveats and considerations when enabling options.

Examples:

- Fully tabulated configuration options per-component
- `calicoctl` help text
- Calico API schema reference (policy, ip pool, etcd)

## Organizational changes

### Creating new pages

- To create a top level splash page for a URL path, name the file `index.md`. 

  If the index.md has child topics, copy the following content and update. All name/keys should be lowercase for consistency. Descriptions should be approximately 50-160 words.

  ```
  ---
  title: Install Calico
  description: Install Calico on nodes and hosts for popular orchestrators, and install the calicoctl command line interface (CLI) tool. 
  canonical_url: '/getting-started/index'
  show_read_time: false
  show_toc: false
  ---

  {{ page.description }}

  {% capture content %}{% include index.html %}{% endcapture %}
  {{ content | replace: "    ", "" }}
  ```

- [Add the new page to the side navigation bar](#linking-content).

- Within the copies of the page in the `master` and previous release directories, add a `canonical_url` line below the `title` line in the metadata of the page. This should contain the absolute path to the page in the current latest directory. Example: `canonical_url: 'https://projectcalico.docs.tigera.io/v3.0/getting-started/kubernetes/'`. For more discussion of canonical URLs, refer to the [Canonical URLs](#canonical-urls) section.

### Deleting or renaming pages

If you need to delete or rename a directory or file:

- Ensure that you [adjust the side navigation bar to match](#side-navigation-bar).

- Update any `canonical_url` paths that reference the deleted or renamed page. The `canonical_url` metadata of all previous instances of the page may reference the deleted or renamed page. You must correct these pages to reference the final instance of the page. When you submit your PR, `htmlproofer` will flag these errors.

    - _Deletion example_: If you delete a page from the `master` and `v3.0` directories, you must update the `canonical_url` path of the page in the `v2.6` directory to point to itself. You would also need to update the `canonical_url` paths of any previous instances of the page to point to the copy in the `v2.6` directory. This final copy becomes the new canonical copy.

    - _Renaming example_: If you rename a page from the `master` and `v3.0` directories, you must update the `canonical_url` path of the page in the `v2.6` directory to point to the new path. Also correct any copies in previous directories.

    - For more discussion of canonical URLs, refer to the [Canonical URLs](#canonical-urls) section.

### Side navigation bar

The naming and layout of the side navigation bar is stored in `_data/$VERSION/navbars/*`. Jekyll automatically stores information from the `_data` directory in an accessible variable called `site.data`. The top-level layout (`_layout/docwithnav.html`) will iterate through all the files in `site.data[version].navbars` to construct the sidebar based on which version is being viewed.

> **Note**: Sidebar paths to index files (see [next section](#linking-content)) should end in a `/` in the yaml file. Sidebar paths to actual files should not end in a `/` in the yaml file.

## Link syntax

### Closing slashes

To link to a page not named `index.md`, omit the closing slash. To link to a page named `index.md`, include a closing slash. See the following table for some examples.

| URL                                           | File path                                         |
|-----------------------------------------------|---------------------------------------------------|
| `/getting-started/kubernetes/`                | `/getting-started/kubernetes/index.md`            |
| `/getting-started/kubernetes/troubleshooting` | `/getting-started/kubernetes/troubleshooting.md`  |

### `site.url`, `site.baseurl`, and `absolute_url`

**`site.baseurl`**

To create clickable links to other doc site content, use links prefixed with: `{{ site.baseurl }}`. For example:

```
[Get started]({{ site.baseurl }}/getting-started/)
```

Will render as:

```
<a href="/v3.8/getting-started/">Getting started</a>
```

**`absolute_url`**

The `absolute_url` filter must be used whenever you are not creating a clickable `<a href='...'>` element, but instead are showing the user a URL to copy locally. A common example is downloading manifests or showing a user how to `kubectl apply -f https://...` them.

For absolute links, use `{{ "/path" | absolute_url }}`. For example:

```
kubectl apply -f `{{ "/manifests/calicoctl.yaml" | absolute_url }}`
```

Will render as:

```
kubectl apply -f `https://docs.tigera.io/v3.8/manifests/calicoctl.yaml`
```

**`site.url`**

This renders as the top-level site authority string, without any version prefixes.  Use this when you are showing the user a URL to copy, but want to specify the path portion verbatim, without Jekyll adding any page version information.  For example, if you need to link to a hard-coded version of a page:

```
kubectl apply -f `{{site.url}}/v3.4/manifests/calicoctl.yaml`
```

Will render as:

```
kubectl apply -f `https://docs.tigera.io/v3.4/manifests/calicoctl.yaml`
```
### Syntax for links outside the doc site

Use the following syntax for any link that takes the user outside the docs site; so the link opens in a separate window.

```
{% include open-new-window.html text='NAME' url='URL' %}
```
**Example**

```
{% include open-new-window.html text='Create an AKS cluster and enable network policy' url='https://docs.microsoft.com/en-us/azure/aks/use-network-policies' %}
```

### Case sensitivity

Do not include any uppercase letters in your links.

### Anchor links

An anchor link for each heading is automatically created. It consists of the title of the heading with each word separated by hyphens. Delete any slashes in the title. For example, to reference a heading titled "Working with the calico/kube-controllers container" on a page located at `https://projectcalico.docs.tigera.io/v3.0/reference/kube-controllers/configuration`, you would use the following:

```
/{{page.version}}/reference/kube-controllers/configuration#working-with-the-calicokube-controllers-container
```

## Canonical URLs

Because the documentation site includes content for past versions as well as the latest version, it contains many duplicate pages. When Google indexes the site, it needs to know which copy we prefer. We use [jekyll-seo-tag](https://github.com/jekyll/jekyll-seo-tag) to add [canonical URLs](https://support.google.com/webmasters/answer/139066?hl=en) to each page. This helps us to ensure that the latest copy of the page comes up first when people search for information via Google.

Each page should include a `canonical_url` tag that contains the absolute path to the latest copy of the page, even if the latest copy is the page itself.

You should _not_ need to modify the `canonical_url` metadata unless you are adding, deleting, or renaming a page.

## Code samples

Our site adds a copy button to each code block by default. To ensure that readers can copy and paste the code successfully, follow the [Code samples](https://github.com/projectcalico/calico/blob/master/DOC_STYLE_GUIDE.md#code-samples) recommendations in the DOC_STYLE_GUIDE.

To modify the default behavior for code samples that should not be copied, such as responses, append `{: .no-select-button}`. An example follows.

```
Successfully created 8 resource(s)
{: .no-select-button}
```

## Releases

See [RELEASING.md](RELEASING.md)
