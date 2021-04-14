---
title: Install from a private registry
description: Install and configure Calico Enterprise in a private registry. 
canonical_url: '/maintenance/image-options/private-registry/private-registry-regular'
---

{% assign operator = site.data.versions.first.tigera-operator %}

### Big picture

Move {{site.prodname}} container images to a private registry and configure {{site.prodname}} to pull images from it.

### Value

Install {{site.prodname}} in clusters where pulling from third-party private repos is not an option, such as airgapped clusters, or clusters with bandwidth constraints or security constraints.

### Concepts

A **container image registry** (often referred to as a **registry**) is a service where container images are pushed to, stored, and pulled from. A registry is said to be "private" if it requires users authenticate before accessing images.

An **image pull secret** is used in Kubernetes to deploy container images from a private container image registry.

### Before you begin...

- Configure pull access to your private registry

### How to

- [Push {{site.prodname}} images to your private registry](#push-{{ site.prodname | slugify }}-images-to-your-private-registry)
- [Run the operator using images from your private registry](#run-the-operator-using-images-from-your-private-registry)
- [Configure the operator to use images from your private registry](#configure-the-operator-to-use-images-from-your-private-registry)

{% include content/private-registry-regular.md %}

>**Note:** See [Install from an image path in a private registry]({{site.baseurl}}/maintenance/image-options/private-registry/private-registry-image-path#big-picture) page for more information on installing using a private registry image path.
{: .alert .alert-info }

>**Note:** See [the Installation resource reference page]({{site.baseurl}}/reference/installation/api) for more information on the `imagePullSecrets` and `registry` fields.
{: .alert .alert-info }
