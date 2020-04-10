## Complete list of Kubernetes API connection configuration

| Configuration file option | Environment variable | Description                                                                                               | Schema
| --------------------------|----------------------| ----------------------------------------------------------------------------------------------------------|
| `datastoreType`           | `DATASTORE_TYPE`     | Indicates the datastore to use. [Default: `etcdv3`]                                                       | `kubernetes`, `etcdv3`
| `kubeconfig`              | `KUBECONFIG`         | When using the Kubernetes datastore, the location of a kubeconfig file to use, e.g. /path/to/kube/config. | string
| `k8sAPIEndpoint`          | `K8S_API_ENDPOINT`   | Location of the Kubernetes API. Not required if using kubeconfig. [Default: `https://kubernetes-api:443`] | string
| `k8sCertFile`             | `K8S_CERT_FILE`      | Location of a client certificate for accessing the Kubernetes API, e.g., `/path/to/cert`.                 | string
| `k8sKeyFile`              | `K8S_KEY_FILE`       | Location of a client key for accessing the Kubernetes API, e.g., `/path/to/key`.                          | string
| `k8sCAFile`               | `K8S_CA_FILE`        | Location of a CA for accessing the Kubernetes API, e.g., `/path/to/ca`.                                   | string
| `k8sToken`                |                      | Token to be used for accessing the Kubernetes API.                                                        | string


> **Note**: All environment variables may also be prefixed with `"CALICO_"`, for
> example `"CALICO_DATASTORE_TYPE"` and `"CALICO_KUBECONFIG"` etc. may be used.
> This is useful if the non-prefixed names clash with existing environment
> variables defined on your system.
{: .alert .alert-info}
