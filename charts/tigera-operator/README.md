# Calico

Calico is a widely adopted, battle-tested open source networking and network security solution for Kubernetes, virtual machines, and bare-metal workloads.
Calico provides two major services for Cloud Native applications:

- Network connectivity between workloads.
- Network security policy enforcement between workloads.

Calico’s flexible architecture supports a wide range of deployment options, using modular components and technologies, including:

- Choice of data plane technology, whether it be [eBPF](https://docs.tigera.io/calico/latest/operations/ebpf/use-cases-ebpf), standard Linux, [Windows HNS](https://docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/architecture) or [VPP](https://github.com/projectcalico/vpp-dataplane)
- Enforcement of the full set of Kubernetes network policy features, plus for those needing a richer set of policy features, Calico network policies.
- An optimized Kubernetes Service implementation using eBPF.
- Kubernetes [apiserver integration](./apiserver), for managing Calico configuration and Calico network policies.
- Both non-overlay and [overlay (via IPIP or VXLAN)](https://docs.tigera.io/calico/latest/networking/configuring/vxlan-ipip) networking options in either public cloud or on-prem deployments.
- [CNI plugins](https://docs.tigera.io/calico/latest/networking/determine-best-networking#calico-compatible-cni-plugins-and-cloud-provider-integrations) for Kubernetes to provide highly efficient pod networking and IP Address Management (IPAM).
- A [BGP routing stack](https://docs.tigera.io/calico/latest/networking/configuring/bgp) that can advertise routes for workload and service IP addresses to physical network infrastructure.

# Installing

1. Add the projectcalico helm repository.

   ```
   helm repo add projectcalico https://docs.tigera.io/calico/charts
   ```

1. Install the Calico CRDs. As of Calico v3.32, CRDs are no longer bundled in this chart and must be installed separately from the `crd.projectcalico.org.v1` chart. See [Custom Resource Definitions](#custom-resource-definitions) below for why.

   ```
   helm template calico-crds projectcalico/crd.projectcalico.org.v1 | kubectl apply --server-side -f -
   ```

1. Create the tigera-operator namespace.

   ```
   kubectl create namespace tigera-operator
   ```

1. Install the helm chart into the `tigera-operator` namespace.

   ```
   helm install calico projectcalico/tigera-operator --namespace tigera-operator
   ```

# Custom Resource Definitions

This chart does not install the Calico CRDs (the `crd.projectcalico.org` and `operator.tigera.io` API groups). Helm does not upgrade or delete CRDs that live in a chart's `crds/` directory, which makes CRD lifecycle management awkward over the life of a cluster. Following [Helm's CRD best practices](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/), the CRDs are shipped in a separate `crd.projectcalico.org.v1` chart that you install and upgrade yourself.

To install or upgrade the CRDs:

```
helm template calico-crds projectcalico/crd.projectcalico.org.v1 | kubectl apply --server-side -f -
```

`helm template | kubectl apply --server-side` is used rather than `helm install` because some Calico CRDs exceed the size limit for client-side apply.

# Upgrading

## Upgrade OwnerReferences

If you do not use OwnerReferences on resources in the projectcalico.org/v3 API group, you can skip this section.

Starting in Calico v3.28, a change in the way UIDs are generated for projectcalico.org/v3 resources requires that you update any OwnerReferences that refer to projectcalico.org/v3 resources as an owner. After upgrade, the UID for all projectcalico.org/v3 resources will be changed, resulting in any owned resources being garbage collected by Kubernetes.

1. Remove any OwnerReferences from resources in your cluster that have apiGroup: projectcalico.org/v3.
2. Perform the upgrade normally.
3. Add new OwnerReferences to your resources referencing the new UID.

## All other upgrades

1. Update the Calico CRDs. Helm will not do this for you (see [Custom Resource Definitions](#custom-resource-definitions)), so apply them before upgrading the operator chart.

   ```bash
   helm template calico-crds projectcalico/crd.projectcalico.org.v1 | kubectl apply --server-side -f -
   ```

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
# here: https://docs.tigera.io/calico/latest/reference/installation/api#installationspec
installation:
  enabled: true
  kubernetesProvider: ""

  # imagePullSecrets are configured on all images deployed by the tigera-operator.
  # secrets specified here must exist in the tigera-operator namespace; they won't be created by the operator or helm.
  # imagePullSecrets are a slice of LocalObjectReferences, which is the same format they appear as on deployments.
  #
  # Example: --set installation.imagePullSecrets[0].name=my-existing-secret
  imagePullSecrets: []

  # Configure the kubelet volume plugin path used by the CSI driver.
  # Set to "None" to disable the CSI driver. If this field is left unset, /var/lib/kubelet is used and CSI is enabled.
  kubeletVolumePluginPath: "None"

# Configures general installation parameters for Calico. Schema is based
# on the operator.tigera.io/Installation API documented
# here: https://docs.tigera.io/calico/latest/reference/installation/api#operator.tigera.io/v1.APIServerSpec
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
  image: quay.io/calico/calico

# Optionally configure the host and port used to access the Kubernetes API server.
kubernetesServiceEndpoint:
  host: ""
  port: "6443"
```

# Configuration reference

The reference below is auto-generated from the chart's `values.yaml` and the operator CRDs.
Top-level chart keys are listed in the first table; the API reference sections expand the
fields under each CRD-backed key (e.g. `installation`, `apiServer`).

<!-- BEGIN AUTO-GENERATED CHART REFERENCE -->

<!-- Generated by hack/cmd/gen-chart-readme. DO NOT EDIT BETWEEN MARKERS. -->
<!-- Regenerate with `make gen-chart-readme`. -->

## Chart values

Top-level keys accepted by this chart's `values.yaml`. Defaults below match the chart's shipped values.
For keys backed by an operator CRD (e.g. `installation`, `apiServer`), see the API references further down.

| Key | Default | Description |
|-----|---------|-------------|
| `imagePullSecrets` | `{}` | imagePullSecrets is a special helm field which, when specified, creates a secret containing the pull secret which is used to pull all images deployed by this helm chart and the resulting operator. this field is a map where the key is the desired secret name and the value is the contents of the imagePullSecret.  Example: --set-file imagePullSecrets.gcr=./pull-secret.json |
| `installation` | `{...}` | Configures general installation parameters for Calico. Schema is based on the operator.tigera.io/Installation API documented here: https://docs.tigera.io/calico/latest/reference/installation/api#installationspec |
| `apiServer` | `{...}` | apiServer configures the Calico API server, needed for interacting with the projectcalico.org/v3 suite of APIs. |
| `goldmane` | `{...}` | goldmane configures the Calico Goldmane flow aggregator. |
| `whisker` | `{...}` | whisker configures the Calico Whisker observability UI. |
| `defaultFelixConfiguration` | `{...}` |  |
| `certs` | `{...}` |  |
| `manageCRDs` | `true` | Whether or not the tigera/operator should manange CustomResourceDefinitions needed to run itself and Calico. If disabled, you must manage these resources out-of-band. |
| `zapDevel` | `false` | Whether to run the tigera/operator in zap development logging mode. When true, the operator logs at debug level using a human-readable console encoder and emits stacktraces on warnings. Intended for development and debugging; leave disabled in production. |
| `resources` | `{}` | Resource requests and limits for the tigera/operator pod. |
| `additionalLabels` | `{}` | Common labels for all resources created by this chart |
| `tolerations` | `[...]` | Tolerations for the tigera/operator pod. |
| `nodeSelector` | `{...}` | NodeSelector for the tigera/operator pod. |
| `affinity` | `{}` | Affinity for the tigera/operator pod. |
| `priorityClassName` | `""` | PriorityClassName for the tigera/operator pod. |
| `podAnnotations` | `{}` | Custom annotations for the tigera/operator pod. |
| `podLabels` | `{}` | Custom labels for the tigera/operator pod. |
| `dnsConfig` | `{}` | Custom DNS configuration for the tigera/operator pod. |
| `tigeraOperator` | `{...}` | Image and registry configuration for the tigera/operator pod. |
| `calicoctl` | `{...}` |  |
| `kubernetesServiceEndpoint` | `{...}` | Optionally configure the host and port used to access the Kubernetes API server. |

## `installation` reference (Installation)

Installation configures an installation of Calico or Calico Enterprise. At most one instance of this resource is supported. It must be named "default". The Installation API installs core networking and network policy components, and provides general install-time configuration.

Set these fields under `installation:` in your values.yaml.

### `azure`

Azure is used to configure azure provider specific options.

#### `azure.policyMode`

PolicyMode determines whether the "control-plane" label is applied to namespaces. It offers two options: Default and Manual. The Default option adds the "control-plane" label to the required namespaces. The Manual option does not apply the "control-plane" label to any namespace. Default: Default

**Type**: string · **Default**: `Default` · **Valid values**: `Default`, `Manual`

### `calicoKubeControllersDeployment`

CalicoKubeControllersDeployment configures the calico-kube-controllers Deployment. If used in conjunction with the deprecated ComponentResources, then these overrides take precedence.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `calicoNetwork`

CalicoNetwork specifies networking configuration options for Calico.

#### `calicoNetwork.bgp`

BGP configures whether or not to enable Calico's BGP capabilities.

**Type**: string · **Valid values**: `Enabled`, `Disabled`

#### `calicoNetwork.bpfNetworkBootstrap`

BPFNetworkBootstrap manages the initial networking setup required to configure the BPF dataplane. When enabled, the operator tries to bootstraps access to the Kubernetes API Server by using the Kubernetes service and its associated endpoints. This field should be enabled only if linuxDataplane is set to "BPF". If another dataplane is selected, this field must be omitted or explicitly set to Disabled. When disabled and linuxDataplane is BPF, you must manually provide the Kubernetes API Server information via the "kubernetes-service-endpoint" ConfigMap. It is invalid to use both the ConfigMap and have this field set to true at the same time. Default: Disabled

**Type**: string · **Valid values**: `Disabled`, `Enabled`

#### `calicoNetwork.clusterRoutingMode`

ClusterRoutingMode controls how nodes get a route to a workload on another node, when that workload's IP comes from an IP Pool with vxlanMode: Never. When ClusterRoutingMode is BIRD, confd and BIRD program that route. When ClusterRoutingMode is Felix, it is expected that Felix will program that route. Felix always programs such routes for IP Pools with vxlanMode: Always or vxlanMode: CrossSubnet. [Default: BIRD]

**Type**: string · **Valid values**: `BIRD`, `Felix`

#### `calicoNetwork.containerIPForwarding`

ContainerIPForwarding configures whether ip forwarding will be enabled for containers in the CNI configuration. Default: Disabled

**Type**: string · **Valid values**: `Enabled`, `Disabled`

#### `calicoNetwork.hostPorts`

HostPorts configures whether or not Calico will support Kubernetes HostPorts. Valid only when using the Calico CNI plugin. Default: Enabled

**Type**: string · **Valid values**: `Enabled`, `Disabled`

#### `calicoNetwork.ipPools`

IPPools contains a list of IP pools to manage. If nil, a single IPv4 IP pool will be created by the operator. If an empty list is provided, the operator will not create any IP pools and will instead wait for IP pools to be created out-of-band. IP pools in this list will be reconciled by the operator and should not be modified out-of-band.

**Type**: array of object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

#### `calicoNetwork.kubeProxyManagement`

KubeProxyManagement controls whether the operator manages the kube-proxy DaemonSet. When enabled, the operator will manage the DaemonSet by patching it: it disables kube-proxy if the dataplane is BPF, or enables it otherwise. Default: Disabled

**Type**: string · **Valid values**: `Disabled`, `Enabled`

#### `calicoNetwork.linuxDataplane`

LinuxDataplane is used to select the dataplane used for Linux nodes. In particular, it causes the operator to add required mounts and environment variables for the particular dataplane. If not specified, iptables mode is used. Default: Iptables

**Type**: string · **Valid values**: `Iptables`, `BPF`, `VPP`, `Nftables`

#### `calicoNetwork.linuxPolicySetupTimeoutSeconds`

LinuxPolicySetupTimeoutSeconds delays new pods from running containers until their policy has been programmed in the dataplane. The specified delay defines the maximum amount of time that the Calico CNI plugin will wait for policy to be programmed. Only applies to pods created on Linux nodes. * A value of 0 disables pod startup delays. Default: 0

**Type**: integer (int32)

#### `calicoNetwork.mtu`

MTU specifies the maximum transmission unit to use on the pod network. If not specified, Calico will perform MTU auto-detection based on the cluster network.

**Type**: integer (int32)

#### `calicoNetwork.multiInterfaceMode`

MultiInterfaceMode configures what will configure multiple interface per pod. Only valid for Calico Enterprise installations using the Calico CNI plugin. Default: None

**Type**: string · **Valid values**: `None`, `Multus`

#### `calicoNetwork.nodeAddressAutodetectionV4`

NodeAddressAutodetectionV4 specifies an approach to automatically detect node IPv4 addresses. If not specified, will use default auto-detection settings to acquire an IPv4 address for each node.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

#### `calicoNetwork.nodeAddressAutodetectionV6`

NodeAddressAutodetectionV6 specifies an approach to automatically detect node IPv6 addresses. If not specified, IPv6 addresses will not be auto-detected.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

#### `calicoNetwork.sysctl`

Sysctl configures sysctl parameters for tuning plugin

**Type**: array of object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

#### `calicoNetwork.windowsDataplane`

WindowsDataplane is used to select the dataplane used for Windows nodes. In particular, it causes the operator to add required mounts and environment variables for the particular dataplane. If not specified, it is disabled and the operator will not render the Calico Windows nodes daemonset. Default: Disabled

**Type**: string · **Valid values**: `HNS`, `Disabled`

### `calicoNodeDaemonSet`

CalicoNodeDaemonSet configures the calico-node DaemonSet. If used in conjunction with the deprecated ComponentResources, then these overrides take precedence.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `calicoNodeWindowsDaemonSet`

CalicoNodeWindowsDaemonSet configures the calico-node-windows DaemonSet.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `calicoWindowsUpgradeDaemonSet`

Deprecated. The CalicoWindowsUpgradeDaemonSet is deprecated and will be removed from the API in the future. CalicoWindowsUpgradeDaemonSet configures the calico-windows-upgrade DaemonSet.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `certificateManagement`

CertificateManagement configures pods to submit a CertificateSigningRequest to the certificates.k8s.io/v1 API in order to obtain TLS certificates. This feature requires that you bring your own CSR signing and approval process, otherwise pods will be stuck during initialization.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `cni`

CNI specifies the CNI that will be used by this installation.

#### `cni.binDir`

BinDir is the path to the CNI binaries directory. If you have changed the installation directory for CNI binaries in the container runtime configuration, please ensure that this field points to the same directory as specified in the container runtime settings. Default directory depends on the KubernetesProvider. * For KubernetesProvider GKE, this field defaults to "/home/kubernetes/bin". * For KubernetesProvider OpenShift, this field defaults to "/var/lib/cni/bin". * Otherwise, this field defaults to "/opt/cni/bin".

**Type**: string

#### `cni.confDir`

ConfDir is the path to the CNI config directory. If you have changed the installation directory for CNI configuration in the container runtime configuration, please ensure that this field points to the same directory as specified in the container runtime settings. Default directory depends on the KubernetesProvider. * For KubernetesProvider GKE, this field defaults to "/etc/cni/net.d". * For KubernetesProvider OpenShift, this field defaults to "/var/run/multus/cni/net.d". * Otherwise, this field defaults to "/etc/cni/net.d".

**Type**: string

#### `cni.ipam`

IPAM specifies the pod IP address management that will be used in the Calico or Calico Enterprise installation.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

#### `cni.type`

Specifies the CNI plugin that will be used in the Calico or Calico Enterprise installation. * For KubernetesProvider GKE, this field defaults to GKE. * For KubernetesProvider AKS, this field defaults to AzureVNET. * For KubernetesProvider EKS, this field defaults to AmazonVPC. * If aws-node daemonset exists in kube-system when the Installation resource is created, this field defaults to AmazonVPC. * For all other cases this field defaults to Calico. For the value Calico, the CNI plugin binaries and CNI config will be installed as part of deployment, for all other values the CNI plugin binaries and CNI config is a dependency that is expected to be installed separately. Default: Calico

**Type**: string · **Valid values**: `Calico`, `GKE`, `AmazonVPC`, `AzureVNET`

### `componentResources`

Deprecated. Please use CalicoNodeDaemonSet, TyphaDeployment, and KubeControllersDeployment. ComponentResources can be used to customize the resource requirements for each component. Node, Typha, and KubeControllers are supported for installations.

**Type**: array of object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `controlPlaneNodeSelector`

ControlPlaneNodeSelector is used to select control plane nodes on which to run Calico components. This is globally applied to all resources created by the operator excluding daemonsets.

**Type**: object (free-form) · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `controlPlaneReplicas`

ControlPlaneReplicas defines how many replicas of the control plane core components will be deployed. This field applies to all control plane components that support High Availability. Defaults to 2.

**Type**: integer (int32)

### `controlPlaneTolerations`

ControlPlaneTolerations specify tolerations which are then globally applied to all resources created by the operator.

**Type**: array of object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `csiNodeDriverDaemonSet`

CSINodeDriverDaemonSet configures the csi-node-driver DaemonSet.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `fipsMode`

FIPSMode uses images and features only that are using FIPS 140-2 validated cryptographic modules and standards. Only supported for Variant=Calico. Default: Disabled

**Type**: string · **Valid values**: `Enabled`, `Disabled`

### `flexVolumePath`

FlexVolumePath optionally specifies a custom path for FlexVolume. If not specified, FlexVolume will be enabled by default. If set to 'None', FlexVolume will be disabled. The default is based on the kubernetesProvider.

**Type**: string

### `imagePath`

ImagePath allows for the path part of an image to be specified. If specified then the specified value will be used as the image path for each image. If not specified or empty, the default for each image will be used. A special case value, UseDefault, is supported to explicitly specify the default image path will be used for each image. Image format: `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>` This option allows configuring the `<imagePath>` portion of the above format.

**Type**: string

### `imagePrefix`

ImagePrefix allows for the prefix part of an image to be specified. If specified then the given value will be used as a prefix on each image. If not specified or empty, no prefix will be used. A special case value, UseDefault, is supported to explicitly specify the default image prefix will be used for each image. Image format: `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>` This option allows configuring the `<imagePrefix>` portion of the above format.

**Type**: string

### `imagePullSecrets`

ImagePullSecrets is an array of references to container registry pull secrets to use. These are applied to all images to be pulled.

**Type**: array of object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `kubeletVolumePluginPath`

KubeletVolumePluginPath optionally specifies enablement of Calico CSI plugin. If not specified, CSI will be enabled by default. If set to 'None', CSI will be disabled. Default: /var/lib/kubelet

**Type**: string

### `kubernetesProvider`

KubernetesProvider specifies a particular provider of the Kubernetes platform and enables provider-specific configuration. If the specified value is empty, the Operator will attempt to automatically determine the current provider. If the specified value is not empty, the Operator will still attempt auto-detection, but will additionally compare the auto-detected value to the specified value to confirm they match.

**Type**: string · **Valid values**: ``, `EKS`, `GKE`, `AKS`, `OpenShift`, `DockerEnterprise`, `RKE2`, `TKG`, `Kind`

### `logging`

Logging Configuration for Components

#### `logging.cni`

Customized logging specification for calico-cni plugin

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `nodeMetricsPort`

NodeMetricsPort specifies which port calico/node serves prometheus metrics on. By default, metrics are not enabled. If specified, this overrides any FelixConfiguration resources which may exist. If omitted, then prometheus metrics may still be configured through FelixConfiguration.

**Type**: integer (int32)

### `nodeUpdateStrategy`

NodeUpdateStrategy can be used to customize the desired update strategy, such as the MaxUnavailable field.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `nonPrivileged`

Deprecated. NonPrivileged is deprecated and will be removed from the API in a future release. Enabling this field is not supported and will cause errors. NonPrivileged configures Calico to be run in non-privileged containers as non-root users where possible.

**Type**: string

### `proxy`

Proxy is used to configure the HTTP(S) proxy settings that will be applied to Tigera containers that connect to destinations outside the cluster. It is expected that NO_PROXY is configured such that destinations within the cluster (including the API server) are exempt from proxying.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `registry`

Registry is the default Docker registry used for component Docker images. If specified then the given value must end with a slash character (`/`) and all images will be pulled from this registry. If not specified then the default registries will be used. A special case value, UseDefault, is supported to explicitly specify the default registries will be used. Image format: `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>` This option allows configuring the `<registry>` portion of the above format.

**Type**: string

### `serviceCIDRs`

Kubernetes Service CIDRs. Specifying this is required when using Calico for Windows.

**Type**: array of string

### `tlsCipherSuites`

TLSCipherSuites defines the cipher suite list that the TLS protocol should use during secure communication.

**Type**: array of object

#### `tlsCipherSuites[].name`

This should be a valid TLS cipher suite name.

**Type**: string · **Valid values**: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_RSA_WITH_AES_256_GCM_SHA384`, `TLS_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`, `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`, `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`

### `typhaAffinity`

Deprecated. Please use Installation.Spec.TyphaDeployment instead. TyphaAffinity allows configuration of node affinity characteristics for Typha pods.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `typhaDeployment`

TyphaDeployment configures the typha Deployment. If used in conjunction with the deprecated ComponentResources or TyphaAffinity, then these overrides take precedence.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `typhaMetricsPort`

TyphaMetricsPort specifies which port calico/typha serves prometheus metrics on. By default, metrics are not enabled.

**Type**: integer (int32)

### `variant`

Variant is the product to install - one of Calico or CalicoEnterprise. TigeraSecureEnterprise is also accepted as a deprecated alias for CalicoEnterprise. Default: Calico

**Type**: string · **Valid values**: `Calico`, `CalicoEnterprise`, `TigeraSecureEnterprise`

### `windowsNodes`

Windows Configuration

#### `windowsNodes.cniBinDir`

CNIBinDir is the path to the CNI binaries directory on Windows, it must match what is used as 'bin_dir' under [plugins] [plugins."io.containerd.grpc.v1.cri"] [plugins."io.containerd.grpc.v1.cri".cni] on the containerd 'config.toml' file on the Windows nodes.

**Type**: string

#### `windowsNodes.cniConfigDir`

CNIConfigDir is the path to the CNI configuration directory on Windows, it must match what is used as 'conf_dir' under [plugins] [plugins."io.containerd.grpc.v1.cri"] [plugins."io.containerd.grpc.v1.cri".cni] on the containerd 'config.toml' file on the Windows nodes.

**Type**: string

#### `windowsNodes.cniLogDir`

CNILogDir is the path to the Calico CNI logs directory on Windows.

**Type**: string

#### `windowsNodes.vxlanAdapter`

VXLANAdapter is the Network Adapter used for VXLAN, leave blank for primary NIC

**Type**: string

#### `windowsNodes.vxlanMACPrefix`

VXLANMACPrefix is the prefix used when generating MAC addresses for virtual NICs

**Type**: string

## `apiServer` reference (APIServer)

APIServer installs the Tigera API server and related resources. At most one instance of this resource is supported. It must be named "default" or "tigera-secure".

Set these fields under `apiServer:` in your values.yaml.

### `apiServerDeployment`

APIServerDeployment configures the calico-apiserver Deployment. If used in conjunction with ControlPlaneNodeSelector or ControlPlaneTolerations, then these overrides take precedence.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `calicoWebhooksDeployment`

CalicoWebhooksDeployment configures the calico-webhooks Deployment.

#### `calicoWebhooksDeployment.metadata`

Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

#### `calicoWebhooksDeployment.spec`

Spec is the specification of the calico-webhooks Deployment.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `logging`

#### `logging.apiServer`

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

#### `logging.queryServer`

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

## `goldmane` reference (Goldmane)

Set these fields under `goldmane:` in your values.yaml.

### `goldmaneDeployment`

GoldmaneDeployment is the configuration for the goldmane Deployment.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

### `metricsPort`

MetricsPort configures the port that Goldmane uses to serve Prometheus metrics. When set to a non-zero value, Goldmane will expose a /metrics endpoint on the given port. Set to zero to disable metrics. If omitted, metrics are disabled.

**Type**: integer (int32)

## `whisker` reference (Whisker)

Set these fields under `whisker:` in your values.yaml.

### `notifications`

Default: Enabled This setting enables calls to an external API to retrieve notification banner text in the Whisker UI. Allowed values are Enabled or Disabled. Defaults to Enabled.

**Type**: string

### `whiskerDeployment`

WhiskerDeployment is the configuration for the whisker Deployment.

**Type**: object · _See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._

<!-- END AUTO-GENERATED CHART REFERENCE -->
