# Calico CRDs

This chart contains the Calico Custom Resource Definitions (CRDs), required for the tigera-operator helm chart to function properly:

- `crd.projectcalico.org/v1` API group
- `operator.tigera.io/v1` API group

The CRDs live in their own chart because Helm does not upgrade or delete CRDs bundled in a chart's `crds/` directory. See [Helm's CRD best practices](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/).

# Installing

Install or upgrade the CRDs before installing or upgrading the `tigera-operator` chart:

```
helm repo add projectcalico https://docs.tigera.io/calico/charts
helm template calico-crds projectcalico/crd.projectcalico.org.v1 | kubectl apply --server-side -f -
```

`helm template | kubectl apply --server-side` is used rather than `helm install` because some Calico CRDs exceed the size limit for client-side apply.
