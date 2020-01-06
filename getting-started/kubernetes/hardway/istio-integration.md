---
title: Istio integration
canonical_url: '/getting-started/kubernetes/hardway/istio-integration'
---

{{site.prodname}} policy integrates with [Istio](https://istio.io) to allow you to write policies that enforce against
application layer attributes like HTTP methods or paths as well as against cryptographically secure identities. In this
lab we will enable this integration and test it out.

## Install FlexVolume driver

{{site.prodname}} uses a FlexVolume driver to enable secure connectivity between Felix and the Dikastes container
running in each pod.  It mounts a shared volume into which Felix inserts a Unix Domain Socket.

On each node in the cluster, execute the following commands to install the FlexVolume driver binary.

```
sudo mkdir -p /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds
sudo docker run --rm \
  -v /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds:/host/driver \
  calico/pod2daemon-flexvol:v3.8.0
```

Verify the `uds` binary is present

```bash
ls -lh /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds
```

Result

```
total 5.0M
-r-xr-x--- 1 root root 5.0M Jul 25 22:31 uds
```
{: .no-select-button}

## Enable policy sync API

Application layer policy requires the policy sync API to be enabled on Felix. To do this cluster-wide, modify the `default`
FelixConfiguration to set the field `policySyncPathPrefix` to `/var/run/nodeagent`.  The following example uses `sed` to modify your
existing default config before re-applying it.

```bash
calicoctl get felixconfiguration default --export -o yaml | \
sed -e '/  policySyncPathPrefix:/d' \
    -e '$ a\  policySyncPathPrefix: /var/run/nodeagent' > felix-config.yaml
calicoctl apply -f felix-config.yaml
```

## Installing Istio

Install Istio 1.1.7, including mutually authenticated TLS for service to service communication.

```bash
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.1.7 sh -
cd $(ls -d istio-*)
kubectl apply -f install/kubernetes/helm/istio-init/files/
kubectl apply -f install/kubernetes/istio-demo-auth.yaml
```

> **Note**: If an "unable to recognize" error occurs after applying `install/kubernetes/istio-demo-auth.yaml` it is likely a race
> condition between creating an Istio CRD and then a resource of that type. Re-run the `kubectl apply`.
{: .alert .alert-info}

## Updating the Istio sidecar injector

The sidecar injector automatically modifies pods as they are created to work
with Istio. This step modifies the injector configuration to add Dikastes, a
{{site.prodname}} component, as sidecar containers.

Apply the following ConfigMap to enable injection of Dikastes alongside Envoy.

   ```bash
   kubectl apply -f {{site.url}}/v3.8/manifests/alp/istio-inject-configmap-1.1.7.yaml
   ```

## Adding {{site.prodname}} authorization services to the mesh

Apply the following manifest to configure Istio to query {{site.prodname}} for application layer policy authorization decisions

```bash
kubectl apply -f {{site.url}}/v3.8/manifests/alp/istio-app-layer-policy.yaml
```

## Adding namespace labels

Application layer policy is only enforced on pods that are started with the
Envoy and Dikastes sidecars.  Pods that do not have these sidecars will
only enforce standard {{site.prodname}} network policy.

You can control this on a per-namespace basis.  To enable Istio and application
layer policy in a namespace, add the label `istio-injection=enabled`.

Label the default namespace, which you will use for the tutorial.

	kubectl label namespace default istio-injection=enabled


## Test application layer policy

You can test application layer policy by following the [Application Layer Policy tutorial](/security/tutorials/app-layer-policy/enforce-policy-istio).

