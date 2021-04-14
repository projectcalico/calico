---
title: Install from an image path in a private registry
description: Install and configure Calico Enterprise using an image path in a private registry.
canonical_url: '/maintenance/image-options/private-registry/private-registry-image-path'
---

{% assign operator = site.data.versions.first.tigera-operator %}

### Big picture

Move {{site.prodname}} container images to an image path in a private registry and configure {{site.prodname}} to pull images from it.

### Value

Install {{site.prodname}} in clusters where pulling from third-party private repos is not an option, and all images are desired to be part of a single directory in the private registry.

### Concepts

A **container image registry** (often referred to as a **registry**) is a service where container images are pushed to, stored, and pulled from. A registry is said to be "private" if it requires users authenticate before accessing images.

An **image path** is a directory in the private registry that contains images required to install {{site.prodname}}.

An **image pull secret** is used in Kubernetes to deploy container images from a private container image registry.

### Before you begin...

- Configure pull access to your private registry

### How to

- [Push {{ site.prodname }} images to your private registry](#push-{{site.prodname | slugify }}-images-to-your-private-registry-image-path)
- [Run the operator using images from your private registry](#run-the-operator-using-images-from-your-private-registry-image-path)
- [Configure the operator to use images from your private registry](#configure-the-operator-to-use-images-from-your-private-registry-image-path)

{% include content/private-registry-image-path.md %}

>**Note:** See [the Installation resource reference page]({{site.baseurl}}/reference/installation/api) for more information on the `imagePullSecrets`, `registry` and `imagePath` fields.
{: .alert .alert-info }
