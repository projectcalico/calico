---
title: Customizing the manifests
canonical_url: 'https://docs.projectcalico.org/v3.7/getting-started/kubernetes/installation/config-options'
---

## About customizing manifests

We provide a number of manifests to make deployment of {{site.prodname}} easy. You can optionally
modify the manifests before applying them. Or you can modify the manifest and reapply it to change
settings as needed.

Refer to the section that corresponds to the manifest you wish to modify for more details.

- [Customizing {{site.prodname}} manifests](#customizing-calico-manifests)

- [Customizing application layer policy manifests](#customizing-application-layer-policy-manifests)


## Customizing {{site.prodname}} manifests

### About customizing {{site.prodname}} manifests

Each manifest contains all the necessary resources for installing {{site.prodname}}
on each node in your Kubernetes cluster.

It installs the following Kubernetes resources:

- Installs the `{{site.nodecontainer}}` container on each host using a DaemonSet.
- Installs the {{site.prodname}} CNI binaries and network config on each host using
  a DaemonSet.
- Runs `calico/kube-controllers` as a deployment.
- The `calico-etcd-secrets` secret, which optionally allows for providing etcd
  TLS assets.
- The `calico-config` ConfigMap, which contains parameters for configuring
  the install.

The sections that follow discuss the configurable parameters in greater depth.

### Configuring the pod IP range

{{site.prodname}} IPAM assigns IP addresses from [IP pools]({{site.baseurl}}/{{page.version}}/reference/resources/ippool).

To change the default IP range used for pods, modify the `CALICO_IPV4POOL_CIDR`
section of the `calico.yaml` manifest.  For more information, see
[Configuring {{site.nodecontainer}}]({{site.baseurl}}/{{page.version}}/reference/node/configuration).

### Configuring IP-in-IP

By default, the manifests enable IP-in-IP encapsulation across subnets. Many users may
want to disable IP-in-IP encapsulation, such as under the following circumstances.

- Their cluster is [running in a properly configured AWS VPC]({{site.baseurl}}/{{page.version}}/reference/public-cloud/aws).
- All their Kubernetes nodes are connected to the same layer 2 network.
- They intend to use BGP peering to make their underlying infrastructure aware of
  pod IP addresses.

To disable IP-in-IP encapsulation, modify the `CALICO_IPV4POOL_IPIP` section of the
manifest.  For more information, see [Configuring {{site.nodecontainer}}]({{site.baseurl}}/{{page.version}}/reference/node/configuration).

### Switching from IP-in-IP to VXLAN

By default, the Calico manifests enable IP-in-IP encapsulation.  If you are on a network that blocks IP-in-IP, such
as Azure, you may wish to switch to [Calico's VXLAN encapsulation mode]({{site.baseurl}}/{{page.version}}/networking/vxlan-ipip).
To do this at install time (so that Calico creates the default IP pool with VXLAN and no IP-in-IP configuration has to
be undone):

- Start with one of the [Calico for policy and networking]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/calico) manifests.
- Replace environment variable name `CALICO_IPV4POOL_IPIP` with`CALICO_IPV4POOL_VXLAN`.  Leave the value of the new variable as "Always".
- Optionally, (to save some resources if you're running a VXLAN-only cluster) completely disable Calico's BGP-based
  networking:
  - Replace `calico_backend: "bird"` with `calico_backend: "vxlan"`.  This disables BIRD.
  - Comment out the line `- -bird-ready` from the calico/node readiness check (otherwise disabling BIRD will cause the
    readiness check to fail on every node):

```yaml
          readinessProbe:
            exec:
              command:
              - /bin/calico-node
              # - -bird-ready
              - -felix-ready
```

For more information on {{site.nodecontainer}}'s configuration variables, including additional VXLAN settings, see
 [Configuring {{site.nodecontainer}}]({{site.baseurl}}/{{page.version}}/reference/node/configuration).

> **Note**: The `CALICO_IPV4POOL_VXLAN` environment variable only takes effect when the first {{site.nodecontainer}} to start
> creates the default IP pool.  It has no effect after the pool has already been created.  To switch to VXLAN mode
> after installation time, use calicoctl to modify the [IPPool]({{site.baseurl}}/{{page.version}}/reference/resources/ippool) resource.
{: .alert .alert-info}

### Configuring etcd

By default, these manifests do not configure secure access to etcd and assume an
etcd proxy is running on each host. The following configuration options let you
specify custom etcd cluster endpoints as well as TLS.

The following table outlines the supported `ConfigMap` options for etcd:

| Option                 | Description    | Default
|------------------------|----------------|----------
| etcd_endpoints         | Comma-delimited list of etcd endpoints to connect to. | http://127.0.0.1:2379
| etcd_ca                | The file containing the root certificate of the CA that issued the etcd server certificate. Configures `{{site.nodecontainer}}`, the CNI plugin, and the Kubernetes controllers to trust the signature on the certificates provided by the etcd server. | None
| etcd_key               | The file containing the private key of the `{{site.nodecontainer}}`, the CNI plugin, and the Kubernetes controllers client certificate. Enables these components to participate in mutual TLS authentication and identify themselves to the etcd server. | None
| etcd_cert              | The file containing the client certificate issued to `{{site.nodecontainer}}`, the CNI plugin, and the Kubernetes controllers. Enables these components to participate in mutual TLS authentication and identify themselves to the etcd server. | None

To use these manifests with a TLS-enabled etcd cluster you must do the following:

1. Download the {{page.version}} manifest that corresponds to your installation method.

   **{{site.prodname}} for policy and networking**
   ```bash
   curl {{site.url}}/{{page.version}}/manifests/calico-etcd.yaml -O
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   curl {{site.url}}/{{page.version}}/manifests/canal.yaml -O
   ```

1. Within the `ConfigMap` section, uncomment the `etcd_ca`, `etcd_key`, and `etcd_cert`
   lines so that they look as follows.

   ```yaml
   etcd_ca: "/calico-secrets/etcd-ca"
   etcd_cert: "/calico-secrets/etcd-cert"
   etcd_key: "/calico-secrets/etcd-key"
   ```
   {: .no-select-button}

1. Ensure that you have three files, one containing the `etcd_ca` value, another containing
   the `etcd_key` value, and a third containing the `etcd_cert` value.

1. Using a command like the following to strip the newlines from the files and
   base64-encode their contents.

   ```bash
   cat <file> | base64 -w 0
   ```

1. In the `Secret` named `calico-etcd-secrets`, uncomment `etcd_ca`, `etcd_key`, and `etcd_cert`
   and paste in the appropriate base64-encoded values.

   ```yaml
   apiVersion: v1
   kind: Secret
   type: Opaque
   metadata:
     name: calico-etcd-secrets
     namespace: kube-system
   data:
     # Populate the following files with etcd TLS configuration if desired, but leave blank if
     # not using TLS for etcd.
     # This self-hosted install expects three files with the following names.  The values
     # should be base64 encoded strings of the entire contents of each file.
     etcd-key: LS0tLS1CRUdJTiB...VZBVEUgS0VZLS0tLS0=
     etcd-cert: LS0tLS1...ElGSUNBVEUtLS0tLQ==
     etcd-ca: LS0tLS1CRUdJTiBD...JRklDQVRFLS0tLS0=
   ```
   {: .no-select-button}

1. Apply the manifest.

   **{{site.prodname}} for policy and networking**
   ```bash
   kubectl apply -f calico.yaml
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   kubectl apply -f canal.yaml
   ```

### Authorization options

{{site.prodname}}'s manifests assign its components one of two service accounts.
Depending on your cluster's authorization mode, you'll want to back these
service accounts with the necessary permissions.

### Configuring service advertisement

{{site.prodname}} supports [advertising Kubernetes services over
BGP](../../../networking/service-advertisement),
so that service cluster IPs are routable from outside the cluster.  To
enable this, add a `CALICO_ADVERTISE_CLUSTER_IPS` variable setting to
the environment for {{site.nodecontainer}} in the `calico.yaml`
manifest, with value equal to the cluster IP range for your Kubernetes
cluster; for example:

```yaml
          env:
            [...]
            - name: CALICO_ADVERTISE_CLUSTER_IPS
              value: "10.96.0.0/12"
```

For more information, see [Configuring
{{site.nodecontainer}}]({{site.baseurl}}/{{page.version}}/reference/node/configuration).

### Other configuration options

The following table outlines the remaining supported `ConfigMap` options.

| Option                 | Description         | Default
|------------------------|---------------------|----------
| calico_backend         | The backend to use. | `bird`
| cni_network_config     | The CNI Network config to install on each node.  Supports templating as described below. |

### CNI network configuration template


The `cni_network_config` configuration option supports the following template fields, which will
be filled in automatically by the `calico/cni` container:

| Field                                 | Substituted with
|---------------------------------------|----------------------------------
| `__KUBERNETES_SERVICE_HOST__`         | The Kubernetes service Cluster IP, e.g `10.0.0.1`
| `__KUBERNETES_SERVICE_PORT__`         | The Kubernetes service port, e.g., `443`
| `__SERVICEACCOUNT_TOKEN__`            | The service account token for the namespace, if one exists.
| `__ETCD_ENDPOINTS__`                  | The etcd endpoints specified in `etcd_endpoints`.
| `__KUBECONFIG_FILEPATH__`             | The path to the automatically generated kubeconfig file in the same directory as the CNI network configuration file.
| `__ETCD_KEY_FILE__`                   | The path to the etcd key file installed to the host. Empty if no key is present.
| `__ETCD_CERT_FILE__`                  | The path to the etcd certificate file installed to the host, empty if no cert present.
| `__ETCD_CA_CERT_FILE__`               | The path to the etcd certificate authority file installed to the host. Empty if no certificate authority is present.


## Customizing application layer policy manifests

### About customizing application layer policy manifests

Instead of installing from our pre-modified Istio manifests, you may wish to
customize your Istio install or use a different Istio version.  This section
walks you through the necessary changes to a generic Istio install manifest to
allow application layer policy to operate.

### Sidecar injector

The standard Istio manifests for the sidecar injector include a ConfigMap that
contains the template used when adding pods to the cluster. The template adds an
init container and the Envoy sidecar.  Application layer policy requires
an additional lightweight sidecar called Dikastes which receives {{site.prodname}} policy
from Felix and applies it to incoming connections and requests.

If you haven't already done so, download an
[Istio release](https://github.com/istio/istio/releases) and untar it to a
working directory.

Open the `install/kubernetes/istio-demo-auth.yaml` file in an
editor, and locate the `istio-sidecar-injector` ConfigMap.  In the existing `istio-proxy` container, add a new `volumeMount`.

```
{% include {{page.version}}/non-helm-manifests/istio-proxy-volume-mounts %}
```

Add a new container to the template.

```
{% include {{page.version}}/non-helm-manifests/dikastes-container %}
```

Add two new volumes.

```
{% include {{page.version}}/non-helm-manifests/istio-volumes %}
```

The volumes you added are used to create Unix domain sockets that allow
communication between Envoy and Dikastes and between Dikastes and
Felix.  Once created, a Unix domain socket is an in-memory communications
channel. The volumes are not used for any kind of stateful storage on disk.

Refer to the
[Calico ConfigMap manifest](/{{page.version}}/manifests/alp/istio-inject-configmap-1.0.7.yaml){:target="_blank"} for an
example with the above changes.
