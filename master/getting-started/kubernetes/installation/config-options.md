---
title: Customizing the manifests
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/config-options'
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

{{site.prodname}} IPAM assigns IP addresses from [IP pools]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).

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

### etcd configuration

By default, these manifests do not configure secure access to etcd and assume an
etcd proxy is running on each host. The following configuration options let you
specify custom etcd cluster endpoints as well as TLS.

The following table outlines the supported `ConfigMap` options for etcd:

| Option                 | Description    | Default
|------------------------|----------------|----------
| etcd_endpoints         | A comma separated list of etcd nodes. | http://127.0.0.1:2379
| etcd_ca                | The location of the CA mounted in the pods deployed by the DaemonSet. | None
| etcd_key               | The location of the client cert mounted in the pods deployed by the DaemonSet. | None
| etcd_cert              | The location of the client key mounted in the pods deployed by the DaemonSet. | None

To use these manifests with a TLS-enabled etcd cluster you must do the following:

- Populate the `calico-etcd-secrets` secret with the contents of the following files:
  - `etcd-ca`
  - `etcd-key`
  - `etcd-cert`

- Populate the following options in the `ConfigMap` which will trigger the various
  services to expect the provided TLS assets:
  - `etcd_ca: /calico-secrets/etcd-ca`
  - `etcd_key: /calico-secrets/etcd-key`
  - `etcd_cert: /calico-secrets/etcd-cert`

### Authorization options

{{site.prodname}}'s manifests assign its components one of two service accounts.
Depending on your cluster's authorization mode, you'll want to back these
service accounts with the necessary permissions.

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

### Pilot webhook

Istio's Pilot must be started with {{site.prodname}}'s Pilot webhook as a
sidecar container. This enables {{site.prodname}} authorization policy in Envoy.

Download an [Istio release](https://github.com/istio/istio/releases) and untar
it to a working directory. Application layer policy requires mutual TLS authentication
(mTLS) to be enabled in the cluster, so open the `install/kubernetes/istio-auth.yaml` file
in an editor.

Locate the `istio-pilot` Deployment in the manifest. In the `args` list of the
`discovery` container, add `"--webhookEndpoint"` and
`"unix:///var/run/calico/webhook.sock"` to the end of the list.

Add a `volumeMount` to the `discovery` container as follows.

```
        - name: webhook
          mountPath: /var/run/calico
```

Add a new container to the podspec as follows.

```
      - name: pilot-webhook
        image: quay.io/calico/pilot-webhook:20180319220721
        imagePullPolicy: Always
        args:
        - /var/run/calico/webhook.sock
        - --debug
        volumeMounts:
        - name: webhook
          mountPath: /var/run/calico
```

Add the `webhook` volume.

```
      - name: webhook
        emptyDir: {}
```

Here is an example of the `istio-pilot` Deployment from Istio v0.6.0 after the
above changes have been made.

	apiVersion: extensions/v1beta1
	kind: Deployment
	metadata:
	  name: istio-pilot
	  namespace: istio-system
	spec:
	  replicas: 1
	  template:
	    metadata:
	      labels:
	        istio: pilot
	      annotations:
	        sidecar.istio.io/inject: "false"
	    spec:
	      serviceAccountName: istio-pilot-service-account
	      containers:
	      - name: discovery
	        image: docker.io/istio/pilot:0.6.0
	        imagePullPolicy: IfNotPresent
	        args: ["discovery", "-v", "2", "--admission-service", "istio-pilot", "--webhookEndpoint", "unix:///var/run/calico/webhook.sock"]
	        ports:
	        - containerPort: 8080
	        - containerPort: 443
	        env:
	        - name: POD_NAME
	          valueFrom:
	            fieldRef:
	              apiVersion: v1
	              fieldPath: metadata.name
	        - name: POD_NAMESPACE
	          valueFrom:
	            fieldRef:
	              apiVersion: v1
	              fieldPath: metadata.namespace
	        - name: PILOT_THROTTLE
	          value: "200"
	        volumeMounts:
	        - name: config-volume
	          mountPath: /etc/istio/config
	        - name: webhook
	          mountPath: /var/run/calico
	      - name: istio-proxy
	        image: docker.io/istio/proxy_debug:0.6.0
	        imagePullPolicy: IfNotPresent
	        ports:
	        - containerPort: 15003
	        args:
	        - proxy
	        - pilot
	        - -v
	        - "2"
	        - --discoveryAddress
	        - istio-pilot:15003
	        - --controlPlaneAuthPolicy
	        - MUTUAL_TLS
	        - --customConfigFile
	        - /etc/istio/proxy/envoy_pilot_auth.json
	        volumeMounts:
	        - name: istio-certs
	          mountPath: /etc/certs
	          readOnly: true
	      - name: pilot-webhook
	        image: quay.io/calico/pilot-webhook:20180319220721
	        imagePullPolicy: Always
	        args:
	        - /var/run/calico/webhook.sock
	        - --debug
	        volumeMounts:
	        - name: webhook
	          mountPath: /var/run/calico
	      volumes:
	      - name: config-volume
	        configMap:
	          name: istio
	      - name: istio-certs
	        secret:
	          secretName: istio.istio-pilot-service-account
	          optional: true
	      - name: webhook
	        emptyDir: {}

### Sidecar injector

The standard Istio manifests for the sidecar injector include a `ConfigMap` that
contains the template used when adding pods to the cluster. The template adds an
init container and the Envoy sidecar.  Application layer policy requires
an additional lightweight sidecar called Dikastes which receives {{site.prodname}} policy
from Felix and applies it to incoming connections and requests.

If you haven't already done so, download an
[Istio release](https://github.com/istio/istio/releases) and untar it to a
working directory.

Open the `install/kubernetes/istio-sidecar-injector-configmap-release.yaml` file in an
editor.  In the existing `istio-proxy` container, add a new `volumeMount`.

```
        - mountPath: /var/run/dikastes
          name: dikastes-sock
```

Add a new container to the template.

```
      - name: dikastes
        image: {{site.imageNames["dikastes"]}}:{{site.data.versions[page.version].first.components["calico/dikastes"].version}}
        args: ["/dikastes", "server", "-l", "/var/run/dikastes/dikastes.sock", "-d", "/var/run/felix/nodeagent/socket", "--debug"]
        volumeMounts:
        - mountPath: /var/run/dikastes
          name: dikastes-sock
        - mountPath: /var/run/felix
          name: felix-sync
```

Add two new volumes.

```
      - name: dikastes-sock
        emptyDir:
          medium: Memory
      - name: felix-sync
        flexVolume:
          driver: nodeagent/uds
```

The volumes you added are used to create Unix domain sockets that allow
communication between Envoy and Dikastes and between Dikastes and
Felix.  Once created, a Unix domain socket is an in-memory communications
channel. The volumes are not used for any kind of stateful storage on disk.

Refer to the
[Calico ConfigMap manifest](./manifests/app-layer-policy/istio-inject-configmap.yaml){:target="_blank"} for an
example with the above changes.
