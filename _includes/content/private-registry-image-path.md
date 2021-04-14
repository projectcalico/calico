#### Push {{ site.prodname }} images to your private registry image path

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

1. Retag the images with the name of your private registry `$PRIVATE_REGISTRY` and `$IMAGE_PATH`.

   ```bash
   docker tag {{ operator.registry }}/{{ operator.image }}:{{ operator.version }} $PRIVATE_REGISTRY/$IMAGE_PATH/{{ operator.image | split: "/" | last }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {% if component[1].image -%}
   {% if component[1].registry %}{% assign registry = component[1].registry | append: "/" %}{% else %}{% assign registry = page.registry -%} {% endif -%}
   docker tag {{ registry }}{{ component[1].image }}:{{component[1].version}} $PRIVATE_REGISTRY/$IMAGE_PATH/{{ component[1].image | split: "/" | last }}:{{component[1].version}}
   {% endif -%}
   {% endfor -%}
   ```

1. Push the images to your private registry.

   ```bash
   docker push $PRIVATE_REGISTRY/$IMAGE_PATH/{{ operator.image | split: "/" | last }}:{{ operator.version }}
   {% for component in site.data.versions.first.components -%}
   {% if component[1].image -%}
   docker push $PRIVATE_REGISTRY/$IMAGE_PATH/{{ component[1].image | split: "/" | last}}:{{component[1].version}}
   {% endif -%}
   {% endfor -%}
   ```

   > **Important**: Do not push the private {{site.prodname}} images to a public registry.
   {: .alert .alert-danger}

#### Run the operator using images from your private registry image path

Before applying `tigera-operator.yaml`, modify registry references to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" tigera-operator.yaml
{% endif -%}
sed -ie "s?quay.io.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" tigera-operator.yaml
```
{% comment %} The second 'sed' should be removed once operator launches Prometheus & Alertmanager {% endcomment %}

Next, ensure that an image pull secret has been configured for your custom registry. Set the enviroment variable `PRIVATE_REGISTRY_PULL_SECRET` to the secret name.
Then add the image pull secret to the operator deployment spec:

```bash
sed -ie "/serviceAccountName: tigera-operator/a \      imagePullSecrets:\n\      - name: $PRIVATE_REGISTRY_PULL_SECRET"  tigera-operator.yaml
```

If you are installing Prometheus operator as part of {{ site.prodname }}, then before applying `tigera-prometheus-operator.yaml`, modify registry references to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" tigera-prometheus-operator.yaml
{% endif -%}
sed -ie "s?quay.io.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" tigera-prometheus-operator.yaml
sed -ie "/serviceAccountName: calico-prometheus-operator/a \      imagePullSecrets:\n\      - name: $PRIVATE_REGISTRY_PULL_SECRET"  tigera-prometheus-operator.yaml
```
{% comment %} The second 'sed' should be removed once operator launches Prometheus & Alertmanager {% endcomment %}

Before applying `custom-resources.yaml`, modify registry references to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" custom-resources.yaml
{% endif -%}
sed -ie "s?quay.io.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" custom-resources.yaml
```
{% comment %} The second 'sed' should be removed once operator launches Prometheus & Alertmanager {% endcomment %}

For <b>Openshift</b>, after downloading all manifests modify the following to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/02-tigera-operator.yaml
{% endif -%}
sed -ie "s?quay.io.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/02-tigera-operator.yaml

{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/04-deployment-prometheus-operator.yaml
{% endif -%}
sed -ie "s?quay.io.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/04-deployment-prometheus-operator.yaml
sed -ie "s?containers:?imagePullSecrets:\n        - name: tigera-pull-secret \n      containers:?" manifests/04-deployment-prometheus-operator.yaml

{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/01-cr-prometheus.yaml
{% endif -%}
sed -ie "s?quay.io.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/01-cr-prometheus.yaml
sed -ie "s?nodeSelector:?imagePullSecrets:\n    - name: tigera-pull-secret \n  nodeSelector:?" manifests/01-cr-prometheus.yaml

{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/01-cr-alertmanager.yaml
{% endif -%}
sed -ie "s?quay.io.*/?$PRIVATE_REGISTRY/$IMAGE_PATH/?" manifests/01-cr-alertmanager.yaml
sed -ie "s?nodeSelector:?imagePullSecrets:\n    - name: tigera-pull-secret \n  nodeSelector:?" manifests/01-cr-alertmanager.yaml

```
>**Note:** Add the image pull secret for your `registry` to the secret `tigera-pull-secret`
{: .alert .alert-info }

#### Configure the operator to use images from your private registry image path.

Set the `spec.registry` and `spec.imagePath` field of your Installation resource to the name of your custom registry. For example:

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
  <b>imagePath: my-image-path</b>
</pre>
