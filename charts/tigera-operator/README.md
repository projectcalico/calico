# Calico

Calico is a widely adopted, battle-tested open source networking and network security solution for Kubernetes, virtual machines, and bare-metal workloads.
Calico provides two major services for Cloud Native applications:

- Network connectivity between workloads.
- Network security policy enforcement between workloads.

Calico’s flexible architecture supports a wide range of deployment options, using modular components and technologies, including:

- Choice of data plane technology, whether it be [eBPF](https://projectcalico.docs.tigera.io/maintenance/ebpf/use-cases-ebpf), standard Linux, [Windows HNS](https://docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/architecture) or [VPP](https://github.com/projectcalico/vpp-dataplane)
- Enforcement of the full set of Kubernetes network policy features, plus for those needing a richer set of policy features, Calico network policies.
- An optimized Kubernetes Service implementation using eBPF.
- Kubernetes [apiserver integration](./apiserver), for managing Calico configuration and Calico network policies.
- Both non-overlay and [overlay (via IPIP or VXLAN)](https://projectcalico.docs.tigera.io/networking/vxlan-ipip) networking options in either public cloud or on-prem deployments.
- [CNI plugins](./cni-plugin) for Kubernetes to provide highly efficient pod networking and IP Address Management (IPAM).
- A [BGP routing stack](https://projectcalico.docs.tigera.io/networking/bgp) that can advertise routes for workload and service IP addresses to physical network infrastructure.

# Installing

1. Add the projectcalico helm repository.

   ```
   helm repo add projectcalico https://projectcalico.docs.tigera.io/charts
   ```

1. Create the tigera-operator namespace.

   ```
   kubectl create namespace tigera-operator
   ```

1. Install the helm chart into the `tigera-operator` namespace.

   ```
   helm install calico projectcalico/tigera-operator --namespace tigera-operator
   ```

# Upgrading

Prior to release v3.23, the Calico helm chart itself deployed the `tigera-operator` namespace and required that the helm release was
installed in the `default` namespace. Newer releases properly defer creation of the `tigera-operator` namespace to the user and allow installation
of the chart into the `tigera-operator` namespace.

When upgrading from a version of Calico v3.22 or lower to a version of Calico v3.23 or greater, you must complete the following steps to migrate
ownership of the helm resources to the new chart location.

## Upgrade from Calico versions prior to v3.23.0

1. Patch existing resources so that the new chart can assume ownership.

   ```
   kubectl patch installation default --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch apiserver default --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch podsecuritypolicy tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch -n tigera-operator deployment tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch -n tigera-operator serviceaccount tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch clusterrole tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch clusterrolebinding tigera-operator tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   ```

1. Install the helm chart in the `tigera-operator` namespace.

   ```
   helm install {{site.prodname | downcase}} projectcalico/tigera-operator --version {{site.data.versions[0].title}} --namespace tigera-operator
   ```

1. Once the install has succeeded, you can delete any old releases in the `default` namespace.

   ```
   kubectl delete secret -n default -l name=calico,owner=helm --dry-run
   ```

> **Note:** The above command uses --dry-run to avoid making changes to your cluster. We recommend reviewing
> the output and then re-running the command without --dry-run to commit to the changes.

## All other upgrades

1. Run the helm upgrade:

   ```bash
   helm upgrade {{site.prodname | downcase}} projectcalico/tigera-operator
   ```

# Values reference

The default values.yaml should be suitable for most basic deployments.

```
# imagePullSecrets is a special helm field which, when specified, creates a secret
# containing the pull secret which is used to pull all images deployed by this helm chart and the resulting operator.
# this field is a map where the key is the desired secret name and the value is the contents of the imagePullSecret.
#
# Example: --set-file imagePullSecrets.gcr=./pull-secret.json
imagePullSecrets: {}

# Configures general installation parameters for Calico. Schema is based
# on the operator.tigera.io/Installation API documented
# here: https://projectcalico.docs.tigera.io/reference/installation/api#operator.tigera.io/v1.InstallationSpec
installation:
  enabled: true
  kubernetesProvider: ""

  # imagePullSecrets are configured on all images deployed by the tigera-operator.
  # secrets specified here must exist in the tigera-operator namespace; they won't be created by the operator or helm.
  # imagePullSecrets are a slice of LocalObjectReferences, which is the same format they appear as on deployments.
  #
  # Example: --set installation.imagePullSecrets[0].name=my-existing-secret
  imagePullSecrets: []

# Configures general installation parameters for Calico. Schema is based
# on the operator.tigera.io/Installation API documented
# here: https://projectcalico.docs.tigera.io/reference/installation/api#operator.tigera.io/v1.APIServerSpec
apiServer:
  enabled: true

# Certificates for communications between calico/node and calico/typha.
# If left blank, will be automatically provisioned.
certs:
  node:
    key:
    cert:
    commonName:
  typha:
    key:
    cert:
    commonName:
    caBundle:

# Resources for the tigera/operator pod itself.
# By default, no resource requests or limits are specified.
resources: {}

# Tolerations for the tigera/operator pod itself.
# By default, will schedule on all possible place.
tolerations:
- effect: NoExecute
  operator: Exists
- effect: NoSchedule
  operator: Exists

# NodeSelector for the tigera/operator pod itself.
nodeSelector:
  kubernetes.io/os: linux

# Custom annotations for the tigera/operator pod itself
podAnnotations: {}

# Custom labels for the tigera/operator pod itself
podLabels: {}

# Configuration for the tigera operator images to deploy.
tigeraOperator:
  image: tigera/operator
  registry: quay.io
calicoctl:
  image: docker.io/calico/ctl

# Configuration for the Calico CSI plugin - setting to None will disable the plugin, default: /var/lib/kubelet
kubeletVolumePluginPath: None   
```
