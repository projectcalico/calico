#### Push {{ site.prodname }} images to your private registry

In order to install images from your private registry, you must first pull the images from Tigera's registry, re-tag them with your own registry, and then push the newly tagged images to your own registry.

1. Use the following commands to pull the required {{site.prodname}} images.

   ```bash
   docker pull {{ operator.registry }}/{{ operator.image }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {% if component[1].image -%}
   {% if component[1].registry %}{% assign registry = component[1].registry | append: "/" %}{% else %}{% assign registry = page.registry -%} {% endif -%}
   docker pull {{ registry }}{{ component[1].image }}:{{component[1].version}}
   {% endif -%}
   {% endfor -%}
   ```

1. Retag the images with the name of your private registry `$PRIVATE_REGISTRY`.

   ```bash
   docker tag {{ operator.registry }}/{{ operator.image }}:{{ operator.version }} $PRIVATE_REGISTRY/{{ operator.image }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {% if component[1].image -%}
   {% if component[1].registry %}{% assign registry = component[1].registry | append: "/" %}{% else %}{% assign registry = page.registry -%} {% endif -%}
   docker tag {{ registry }}{{ component[1].image }}:{{component[1].version}} $PRIVATE_REGISTRY/{{ component[1].image }}:{{component[1].version}}
   {% endif -%}
   {% endfor -%}
   ```

1. Push the images to your private registry.

   ```bash
   docker push $PRIVATE_REGISTRY/{{ operator.image }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {% if component[1].image -%}
   docker push $PRIVATE_REGISTRY/{{ component[1].image }}:{{component[1].version}}
   {% endif -%}
   {% endfor -%}
   ```

   > **Important**: Do not push the private {{site.prodname}} images to a public registry.
   {: .alert .alert-danger}

#### Run the operator using images from your private registry

Before applying `tigera-operator.yaml`, modify registry references to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}?$PRIVATE_REGISTRY?g" tigera-operator.yaml
{% endif -%}
sed -ie "s?quay.io?$PRIVATE_REGISTRY?g" tigera-operator.yaml
```

Next, ensure that an image pull secret has been configured for your custom registry. Set the enviroment variable `PRIVATE_REGISTRY_PULL_SECRET` to the secret name.
Then add the image pull secret to the operator deployment spec:

```bash
sed -ie "/serviceAccountName: tigera-operator/a \      imagePullSecrets:\n\      - name: $PRIVATE_REGISTRY_PULL_SECRET"  tigera-operator.yaml
```

{% comment %} The second 'sed' should be removed once operator launches Prometheus & Alertmanager {% endcomment %}

If you are installing Prometheus operator as part of {{ site.prodname }}, then before applying `tigera-prometheus-operator.yaml`, modify registry references to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}?$PRIVATE_REGISTRY?g" tigera-prometheus-operator.yaml
{% endif -%}
sed -ie "s?quay.io?$PRIVATE_REGISTRY?g" tigera-prometheus-operator.yaml
sed -ie "/serviceAccountName: calico-prometheus-operator/a \      imagePullSecrets:\n\      - name: $PRIVATE_REGISTRY_PULL_SECRET"  tigera-prometheus-operator.yaml
```
{% comment %} The second 'sed' should be removed once operator launches Prometheus & Alertmanager {% endcomment %}


Before applying `custom-resources.yaml`, modify registry references to use your custom registry:

```bash
sed -ie "s?quay.io?$PRIVATE_REGISTRY?g" custom-resources.yaml
```
{% comment %} This step should be removed once operator launches Prometheus & Alertmanager {% endcomment %}

#### Configure the operator to use images from your private registry.

Set the `spec.registry` field of your Installation resource to the name of your custom registry. For example:

<pre>
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  variant: TigeraSecureEnterprise
  imagePullSecrets:
    - name: tigera-pull-secret
  <b>registry: myregistry.com</b>
</pre>
