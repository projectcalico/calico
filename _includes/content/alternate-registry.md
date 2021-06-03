{% assign operator = site.data.versions.first.tigera-operator %}

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

{% tabs %}
  <label: OpenShift,active:true>
  <%
After downloading all manifests, modify the following to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}/?$REGISTRY/?" manifests/02-tigera-operator.yaml
{% endif -%}
sed -ie "s?quay.io/?$REGISTRY/?" manifests/02-tigera-operator.yaml
```
Next, if you are implementing user authentication to access a private registry, add the image pull secret for your `registry` to the secret `tigera-pull-secret`.

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


%>
  <label: All other platforms>
  <%
Before applying `tigera-operator.yaml`, modify registry references to use your custom registry:

```bash
{% if page.registry != "quay.io/" -%}
sed -ie "s?{{ page.registry }}?$REGISTRY?g" tigera-operator.yaml
{% endif -%}
sed -ie "s?quay.io?$REGISTRY?g" tigera-operator.yaml
```

Next, if implementing user authentication to access a private registry, add the image pull secret to the operator deployment spec:

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
%>
  {% endtabs %}
