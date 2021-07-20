>**Note**: This feature is tech preview. Tech preview features may be subject
to significant changes before they become GA.

The {{site.prodname}} API server installs {{site.prodname}} API. This allows
{{site.prodname}} resources to be available through `oc` or `kubectl`.

```bash
oc apply -f {{ "/manifests/ocp/01-cr-apiserver.yaml" | absolute_url }}
```
