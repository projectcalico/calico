Download the {{site.prodname}} manifests for OpenShift and add them to the generated manifests directory:

```bash
curl {{ "/manifests/ocp/crds/01-crd-apiserver.yaml" | absolute_url }} -o manifests/01-crd-apiserver.yaml
curl {{ "/manifests/ocp/crds/01-crd-installation.yaml" | absolute_url }} -o manifests/01-crd-installation.yaml
curl {{ "/manifests/ocp/crds/01-crd-imageset.yaml" | absolute_url }} -o manifests/01-crd-imageset.yaml
curl {{ "/manifests/ocp/crds/01-crd-tigerastatus.yaml" | absolute_url }} -o manifests/01-crd-tigerastatus.yaml
{%- for data in site.static_files %}
{%- if data.path contains '/manifests/ocp/crds/calico' %}
curl {{ data.path | absolute_url }} -o manifests/{{data.name}}
{%- endif -%}
{% endfor %}
curl {{ "/manifests/ocp/tigera-operator/00-namespace-tigera-operator.yaml" | absolute_url }} -o manifests/00-namespace-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-rolebinding-tigera-operator.yaml" | absolute_url }} -o manifests/02-rolebinding-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-role-tigera-operator.yaml" | absolute_url }} -o manifests/02-role-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-serviceaccount-tigera-operator.yaml" | absolute_url }} -o manifests/02-serviceaccount-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-configmap-calico-resources.yaml" | absolute_url }} -o manifests/02-configmap-calico-resources.yaml
curl {{ "/manifests/ocp/tigera-operator/02-tigera-operator.yaml" | absolute_url }} -o manifests/02-tigera-operator.yaml
{%- if include.install_type != "upgrade" %}
curl {{ "/manifests/ocp/01-cr-installation.yaml" | absolute_url }} -o manifests/01-cr-installation.yaml
curl {{ "/manifests/ocp/01-cr-apiserver.yaml" | absolute_url }} -o manifests/01-cr-apiserver.yaml
{%- endif %}
```
