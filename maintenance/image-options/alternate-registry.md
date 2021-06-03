---
title: Install images using an alternate registry 
description: Configure Calico to pull images from a public or private registry. 
canonical_url: '/maintenance/image-options/alternate-registry'
---

### Big picture

Configure {{site.prodname}} to pull images from a registry (public or private).

### Value

In many deployments, installing {{site.prodname}} in clusters from third-party private repos is not an option. {{site.prodname}} offers these public and private registery options, which can be used in any combination: 

- **Install from a registry** for use cases like airgapped clusters, or clusters with bandwidth or security constraints
- **Install from an image path in a registry** if you have pulled {{site.prodname}} images to a sub path in your registry
- [Install images by registry digest]({site.baseurl}}/maintenance/image-options/imageset)

### Concepts

A **container image registry** (often known as a **registry**), is a service where you can push, pull, and store container images. In Kubernetes, a registry is considered *private* if it is not publicly available.
A **private registery** requires an **image pull secret**.

An **image pull secret** provides authentication for an image registry; this allows you to control access to certain images or give access to higher pull rate limits (like with DockerHub).

An **image path** is a directory in a registry that contains images required to install {{site.prodname}}.

### Before you begin

**Required**

- {{site.prodname}} is managed by the operator
- Configure pull access to your registry
- If you are using a private registry that requires user authentication, ensure that an image pull secret is configured for your registry in the tigera-operator namespace. Set the enviroment variable, `REGISTRY_PULL_SECRET` to the secret name. For help, see `imagePullSecrets` and `registry` fields, in [Installation resource reference]({{site.baseurl}}/reference/installation/api).

### How to

The following examples show the path format for public or private registry, `$REGISTRY/<path>`. If you are using an image path, substitute the format: `$REGISTRY/$IMAGE_PATH/<path>`

{% include content/alternate-registry.md %}
