# Contributing to Calico documentation

## Overview

We welcome contributions to the Calico documentation.

Instead of filing a GitHub issue, consider making a PR instead. You are likely to see a much more rapid resolution.

The doc contribution process works as follows.

1. Fork the [Project Calico repo](https://github.com/projectcalico/calico).
1. Create a branch in your fork off of the master branch.
1. Give your branch a short but descriptive name.
1. Make your changes in the `master` folder.
1. [Build the site locally to make sure it renders as expected](#building-the-doc-site-locally).
1. [Check for broken links](#checking-for-broken-links).
1. Submit a pull request (PR) against the master branch of the [Project Calico repo](https://github.com/projectcalico/calico).
1. If you haven't already signed our contributer agreement, GitHub will prompt you to do so (required).
1. Request a review from one or more Calico maintainers.
1. After getting the approval of at least one Calico maintainer, we ask that you [backport the changes in the `master` folder to the folders of the last two releases](#how-to-quickly-apply-changes-in-master-to-a-previous-release), if appropriate.
1. Squash your commits.
1. One of the doc repo maintainers will give the PR a final look and then merge it.
1. The merge into master will kick off a new build of the live site. You should see your changes on the live site shortly after they are merged.

> **Important**: Ensure that your contribution conforms to the [Calico documentation style guide](DOC_STYLE_GUIDE.md).

> **Note**: For contributions that affect just one page, you can use the **Edit this page** buttons in the doc site. This allows you to skip a few steps in the process outlined above, but is suitable only for small contributions.

We also encourage you to review [Doc site organization](#doc-site-organization), [Organizational changes](#organizational-changes), [Link syntax](#link-syntax), and [RELEASING.md](RELEASING.md) for additional information.


## Building the doc site locally

We use GitHub Pages and Jekyll to serve and build our site. While there are [several ways to build the site locally](https://help.github.com/articles/setting-up-your-github-pages-site-locally-with-jekyll/), we recommend using our Docker image and the Makefile in the root of the repo. These will allow you to build the site with a single command.

> **Prerequisite**: [Docker](https://docs.docker.com/engine/installation/).

Navigate into the root of the repo and issue the following command from a terminal prompt.

```
make serve
```

Once the build completes, it returns a URL as the value of `Server address:`. Copy and paste this URL into your browser to view the site.

> **Note**: To view the changes that you've made in the master branch, select **nightly** from the **Version** list box.

> **Pro tip**: Jekyll can take a while to render every page. To speed up builds, a supplemental `_config_dev.yml` exists which excludes all directories except `master`. You can include it in your builds as follows `jekyll serve --config _config.yml,_config_dev.yml`. Alternatively, you can pass enable it in `make` using the following environment variable `DEV=true make serve`.



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

### Overview

The docs (currently) are split into four main sections.

- [Introduction](#introduction)
- [Getting started](#getting-started)
- [Usage](#usage)
- [Reference](#reference)

### Introduction

Landing page for new users covering Calico's purpose and high-level topics.

### Getting started

This should be where new users go. It includes quick-start guides, some basic tutorials to show off Calico's capabilities, and links to more advanced topics once users are comfortable with the basics.

Each orchestrator has a landing page that is targeted at people who are coming to see Calico for the first time. It's a transition from the "marketing" type material (why is Calico great) to some quick commands people can run to see it firsthand, and then funnels people off to the Usage section for more details.

### Usage

This section contains task-based information. All top-level titles in this section should start with a gerund. Each topic should include why you want to perform the task, a goal, and a set of steps you can follow to achieve it.

Examples:

- Configuring BGP peers
- Enabling IP-in-IP in AWS
- Troubleshooting Calico
- Using calicoctl in a Kubernetes deployment
- Configuring egress policy in Kubernetes

Do not include detailed description of components or tabulated
configuration information in this section. This type of content should be located in the [Reference](#reference) section.

### Reference

These docs contain complete reference information for Calico. If there's a configuration option you're looking for, it goes here in one of the per-component references. Not every option has a "how to" guide, but has enough description. The caveats and considerations when enabling options should be listed here.

Examples:

- Fully tabulated configuration options per-component
- `calicoctl` help text
- Calico API schema reference (policy, ip pool, etcd)


## Organizational changes

### Creating new pages

- To create a top level splash page for a URL path, simply name the file `index.md`.


- [Add the new page to the side navigation bar](#linking-content).

- Within the copies of the page in the `master` and previous release directories, add a `canonical_url` line below the `title` line in the metadata of the page. This should contain the absolute path to the page in the current latest directory. Example: `canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/'`. For more discussion of canonical URLs, refer to the [Canonical URLs](#canonical-urls) section.


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


### Relative links and `page.version` variable

To link to other doc site content, use relative links prefixed with: `/{{page.version}}/`. This allows the content to port across documentation versions without link breakage. Example:

```
[Get started](/{{page.version}}/getting-started/)
```

> **Pro tip**: `page.version` will be inherited from the default set in `_config.yml` for the current page's directory.

### Case sensitivity

Do not include any uppercase letters in your links.

### Anchor links

An anchor link for each heading is automatically created. It consists of the title of the heading with each word separated by hyphens. Delete any slashes in the title. For example, to reference a heading titled "Working with the calico/kube-controllers container" on a page located at `https://docs.projectcalico.org/v3.0/reference/kube-controllers/configuration`, you would use the following:

```
/{{page.version}}/reference/kube-controllers/configuration#working-with-the-calicokube-controllers-container
```

## Canonical URLs

Because the documentation site includes content for past versions as well as the latest version, it contains many duplicate pages. When Google indexes the site, it needs to know which copy we prefer. We use [jekyll-seo-tag](https://github.com/jekyll/jekyll-seo-tag) to add [canonical URLs](https://support.google.com/webmasters/answer/139066?hl=en) to each page. This helps us to ensure that the latest copy of the page comes up first when people search for information via Google.

Each page should include a `canonical_url` tag that contains the absolute path to the latest copy of the page, even if the latest copy is the page itself.

You should _not_ need to modify the `canonical_url` metadata unless you are adding, deleting, or renaming a page.

## Code samples

Our site adds a copy button to each code block by default. To ensure that readers can copy and paste the code successfully, follow the [Code samples](https://github.com/emanic/calico/blob/contr-update/DOC_STYLE_GUIDE.md#code-samples) recommendations in the DOC_STYLE_GUIDE.

To modify the default behavior for code samples that should not be copied, such as responses, append `{: .no-select-button}`. An example follows.

```
Successfully created 8 resource(s)
{: .no-select-button}
```

## Releases

See [RELEASING.md](RELEASING.md)
