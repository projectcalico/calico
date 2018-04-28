---
title: Enabling Application Layer Policy
canonical_url: 'https://docs.projectcalico.org/master/getting-started/kubernetes/installation/app-layer-policy'
---

Application layer policy for {{site.prodname}} allows you to write policies that
enforce against both network layer attributes, like IP addresses or ports, and
application layer attributes like HTTP methods or paths. It can also enforce
policy based on cryptographically secure identities, allowing you to reduce
trust in your network.  See Application Layer Policy Introduction for more
information.

# Enable {{site.prodname}} support for application layer policy

Support for application layer policy is not enabled by default in
{{site.prodname}} installs, since it requires extra CPU and memory resources to
operate. After installing {{site.prodname}}, return to this page and continue.

Apply an updated manifest for the `{{site.nodecontainer}}` DaemonSet which enables
application layer policy support.

If you installed {{site.prodname}} for policy and networking with the etcd
datastore:

	kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/etcd/calico-networking/calico-node.yaml

[View this manifest in your browser](manifests/app-layer-policy/etcd/calico-networking/calico-node.yaml)

If you installed {{site.prodname}} for policy and networking with the Kubernetes
API datastore:

	kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/kubernetes-datastore/calico-networking/calico-node.yaml

[View this manifest in your browser](manifests/app-layer-policy/kubernetes-datastore/calico-networking/calico-node.yaml)

If you installed {{site.prodname}} for policy and flannel for networking with the Kubernetes
API datastore:

	kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/kubernetes-datastore/flannel/calico-node.yaml

[View this manifest in your browser](manifests/app-layer-policy/kubernetes-datastore/flannel/calico-node.yaml)

If you installed {{site.prodname}} for policy only

	kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/kubernetes-datastore/policy-only/calico-node.yaml

[View this manifest in your browser](manifests/app-layer-policy/kubernetes-datastore/policy-only/calico-node.yaml)

**Note**: These commands overwrite the `{{site.nodecontainer}}` DaemonSet and will cause
these containers to be restarted.
{: .alert .alert-info}

# Install Istio

Application layer policy requires you to use Istio in your cluster to function
correctly. We support Istio version 0.6.0 or newer.

Install Istio using the following command

	kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/istio.yaml

[View this manifest in your browser](manifests/app-layer-policy/istio.yaml)

If you would like to install a different version of Istio or inspect the changes
we have made to the standard Istio install manifest, see the
[Appendix](#modifying-istio-manifests).

# Enable the Istio Sidecar Injector

The Sidecar Injector automatically modifies pods as they are created to work
with Istio. It adds the Istio Proxy and {{site.prodname}} components as sidecar
containers.

1. Follow the [Automatic Sidecar Injection instructions](https://istio.io/docs/setup/kubernetes/sidecar-injection.html#automatic-sidecar-injection)
   to install the Sidecar Injector and enable it in your chosen namespace(s)
1. Apply the following ConfigMap to enable injection of {{site.prodname}}
   components alongside the Istio Proxy.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/istio-inject-configmap.yaml
```

[View this manifest in your browser](manifests/app-layer-policy/istio-inject-configmap.yaml)

If you would like to install a different version of Istio or inspect the changes
we have made to the standard Sidecar Injector ConfigMap, see the
[Appendix](#modifying-istio-manifests).

# Label namespaces for application layer policy

Application layer policy is only enforced on pods that are started with the
Istio Proxy and Dikastes sidecars.  Pods that do not have these sidecars will
only enforce standard Calico network policy.

You can control this on a per-namespace basis.  To enable Istio and application
layer policy in a namespace, add the label `istio-injection=enabled`.

	kubectl label namespace <your namespace name> istio-injection=enabled

If the namespace already has pods in it, you will have to recreate them for this
to take effect.

**Note**: The Istio Proxy must be able to communicate with the
`istio-pilot.istio-system` Service. If you apply any egress policies to your
pods, you *must* enable access. For example, you could
[apply a NetworkPolicy](manifests/app-layer-policy/allow-istio-pilot.yaml).
{: .alert .alert-info}

# Appendix

## Modifying Istio manifests

Instead of installing from our pre-modified Istio manifests, you may wish to
customize your Istio install or use a different Istio version.  This section
walks you through the necessary changes to a generic Istio install manifest to
allow application layer policy to operate.

### Pilot Webhook

Istio's Pilot must be started with {{site.prodname}}'s Pilot Webhook as a
sidecar container. This enables {{site.prodname}} authorization policy in the
Istio Proxy.

Download an [Istio Release](https://github.com/istio/istio/releases) and untar
it to a working directory. Application layer policy requires mutual TLS (mTLS)
to be enabled in the cluster, so open the `install/kubernetes/istio-auth.yaml`
file in an editor.

Locate the `istio-pilot` Deployment in the manifest. In the `args` list of the
`discovery` container, add `"--webhookEndpoint"` and
`"unix:///var/run/calico/webhook.sock"` to the end of the list.

Add a `volumeMount` to the `discovery` container as follows

```
        - name: webhook
          mountPath: /var/run/calico
```

Add a new container to the podspec as follows

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

Add the `webhook` volume

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

### Sidecar Injector

The standard Istio manifests for the Sidecar Injector include a configmap that
contains the template used when adding pods to the cluster. The template adds an
init container and the Istio Proxy sidecar.  Application layer policy requires
an additional lightweight sidecar called Dikastes which receives Calico policy
from Felix and applies it to incoming connections and requests.


If you haven't already done so, download an
[Istio Release](https://github.com/istio/istio/releases) and untar it to a
working directory.

Open `install/kubernetes/istio-sidecar-injector-configmap-release.yaml` in an
editor.  In the existing `istio-proxy` container, add a new volumeMount.

```
        - mountPath: /var/run/dikastes
          name: dikastes-sock
```

Add a new container to the template

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

Add two new Volumes

```
      - name: dikastes-sock
        emptyDir:
          medium: Memory
      - name: felix-sync
        flexVolume:
          driver: nodeagent/uds
```

The volumes you added are used to create Unix Domain Sockets that allow
communication between the Istio Proxy and Dikastes and between Dikastes and
Felix.  Once created, a Unix Domain Socket is an in-memory communications
channel. The volumes are not used for any kind of stateful storage on disk.

Refer to the
[Calico ConfigMap manifest](./manifests/app-layer-policy/istio-inject-configmap.yaml) for an
example with the above changes.
