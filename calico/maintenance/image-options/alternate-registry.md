---
title: Configure use of your image registry
description: Configure Calico to pull images from a public or private registry.
canonical_url: '/maintenance/image-options/alternate-registry'
---

{% assign operator = site.data.versions.first.tigera-operator %}

### Big picture

Configure {{site.prodname}} to pull images from a registry (public or private).

### Value

In many deployments, installing {{site.prodname}} in clusters from third-party private repos is not an option. {{site.prodname}} offers these public and private registry options, which can be used in any combination:

- **Install from a registry** for use cases like airgapped clusters, or clusters with bandwidth or security constraints
- **Install from an image path in a registry** if you have pulled {{site.prodname}} images to a sub path in your registry
- [Install images by registry digest]({{site.baseurl}}/maintenance/image-options/imageset)

### Concepts

A **container image registry** (often known as a **registry**), is a service where you can push, pull, and store container images. In Kubernetes, a registry is considered *private* if it is not publicly available.

A **private registry** requires an **image pull secret**. An **image pull secret** provides authentication for an image registry; this allows you to control access to certain images or give access to higher pull rate limits (like with DockerHub).

An **image path** is a directory in a registry that contains images required to install {{site.prodname}}.

### Before you begin

**Required**

- {{site.prodname}} is managed by the operator
- Configure pull access to your registry
- If you are using a private registry that requires user authentication, ensure that an image pull secret is configured for your registry in the tigera-operator namespace. Set the environment variable, `REGISTRY_PULL_SECRET` to the secret name. For help, see `imagePullSecrets` and `registry` fields, in [Installation resource reference]({{site.baseurl}}/reference/installation/api).

### How to

The following examples show the path format for public and private registry, `$REGISTRY/`. If you are using an image path, substitute the format: `$REGISTRY/$IMAGE_PATH/`.

#### Push {{site.prodname}} images to your registry

To install images from your registry, you must first pull the images from Tigera's registry, retag them with your own registry, and then push the newly-tagged images to your own registry.

1. Use the following commands to pull the required {{site.prodname}} images.

   ```bash
   docker pull {{ operator.registry }}/{{ operator.image }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {%- capture component_name %}{{ component[0] }}{% endcapture -%}

   {%-  if page.imageNames[component_name] %}{% unless component_name contains "flannel" -%}
     {%- assign component_name = page.imageNames[component_name] -%}
   {%-    if component[1].registry %}{% assign registry = component[1].registry | append: "/" %}{% else %}{% assign registry = page.registry -%} {% endif -%}
   docker pull {{ registry }}{{ component_name }}:{{component[1].version}}
   {%   endunless %}{% endif -%}
   {%- endfor -%}
   ```

1. Retag the images with the name of your registry `$REGISTRY`.

   ```bash
   docker tag {{ operator.registry }}/{{ operator.image }}:{{ operator.version }} $REGISTRY/{{ operator.image }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {%- capture component_name %}{{ component[0] }}{% endcapture -%}

   {%-  if page.imageNames[component_name] %}{% unless component_name contains "flannel" -%}
   {%-    assign component_name = page.imageNames[component_name] -%}
   {%     if component[1].registry %}{% assign registry = component[1].registry | append: "/" %}{% else %}{% assign registry = page.registry -%} {% endif -%}
   docker tag {{ registry }}{{ component_name }}:{{component[1].version}} $REGISTRY/{{ component_name }}:{{component[1].version}}
   {%   endunless %}{% endif -%}
   {% endfor -%}
   ```

1. Push the images to your registry.

   ```bash
   docker push $REGISTRY/{{ operator.image }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {%- capture component_name %}{{ component[0] }}{% endcapture -%}

   {%-  if page.imageNames[component_name] %}{% unless component_name contains "flannel" -%}
   {%-    assign component_name = page.imageNames[component_name] -%}
   docker push $REGISTRY/{{ component_name }}:{{component[1].version}}
   {%   endunless %}{% endif -%}
   {% endfor -%}
   ```

#### Run the operator using images from your registry

Before applying `tigera-operator.yaml`, modify registry references to use your custom registry:

**For OpenShift**

Download all manifests first, then modify the following:

```bash
sed -ie "s?quay.io?$REGISTRY?g" manifests/02-tigera-operator.yaml
```

**For all other platforms**

```bash
sed -ie "s?quay.io?$REGISTRY?g" tigera-operator.yaml
```

Next, if you are implementing user authentication to access a private registry, add the image pull secret for your `registry` to the secret `tigera-pull-secret`.

```bash
sed -ie "/serviceAccountName: tigera-operator/a \      imagePullSecrets:\n\      - name: $REGISTRY_PULL_SECRET"  tigera-operator.yaml
```

#### Configure the operator to use images

Set the `spec.registry` field of your Installation resource to the name of your custom registry. For example:

<pre>
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  variant: Calico
  imagePullSecrets:
    - name: tigera-pull-secret
  <b>registry: myregistry.com</b>
</pre>
