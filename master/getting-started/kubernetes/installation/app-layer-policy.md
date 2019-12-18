---
title: Enabling application layer policy (optional)
canonical_url: 'https://docs.projectcalico.org/v3.9/getting-started/kubernetes/installation/app-layer-policy'
---

## About enabling application layer policy

Application layer policy for {{site.prodname}} allows you to write policies that
enforce against application layer attributes like HTTP methods or paths as well as
against cryptographically secure identities.

Support for application layer policy is not enabled by default in
{{site.prodname}} installs, since it requires extra CPU and memory resources to
operate.

## Enabling application layer policy

**Prerequisites**: 

 - [{{site.prodname}} installed](/{{page.version}}/getting-started/kubernetes/installation/)
 - [calicoctl installed](/{{page.version}}/getting-started/calicoctl/install) & [configured](/{{page.version}}/getting-started/calicoctl/configure/)

Application layer policy requires the Policy Sync API to be enabled on Felix. To do this cluster-wide, modify the `default`
FelixConfiguration to set the field `policySyncPathPrefix` to `/var/run/nodeagent`.

```bash
calicoctl patch FelixConfiguration default --patch \
   '{"spec": {"policySyncPathPrefix": "/var/run/nodeagent"}}'
```

## Installing Istio

Application layer policy [requires Istio](../requirements#application-layer-policy-requirements).

Install Istio according to the [Istio project documentation](https://archive.istio.io/v1.3/docs/setup/install/), making sure to enable mutual TLS authentication. For example:

```bash
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.4.2 sh -
cd $(ls -d istio-*)
./bin/istioctl manifest apply --set values.global.mtls.enabled=true --set values.global.controlPlaneSecurityEnabled=true
```


## Updating the Istio sidecar injector

The sidecar injector automatically modifies pods as they are created to work
with Istio. This step modifies the injector configuration to add Dikastes, a
{{site.prodname}} component, as sidecar containers.

1. Follow the [Automatic sidecar injection instructions](https://istio.io/docs/setup/additional-setup/sidecar-injection/#automatic-sidecar-injection)
   to install the sidecar injector and enable it in your chosen namespace(s).

1. Patch the `istio-sidecar-injector` ConfigMap to enable injection of Dikastes alongside Envoy.

   ```bash
   curl {{site.url}}/{{page.version}}/manifests/alp/istio-inject-configmap-1.4.2.yaml -o istio-inject-configmap.yaml
   kubectl patch configmap -n istio-system istio-sidecar-injector --patch "$(cat istio-inject-configmap.yaml)"
   ```

	 > **Note**: You can also
   > [view the manifest in your browser]({{site.url}}/{{page.version}}/manifests/alp/istio-inject-configmap-1.4.2.yaml){:target="_blank"}.
   {: .alert .alert-info}

If you have installed a different version of Istio, substitute `1.4.2` in the above URL for your Istio version. We have
pre-defined `ConfigMaps` for Istio versions 1.1.0 through 1.1.17, 1.2.0 through 1.2.9, 1.3.0 through 1.3.5, and 1.4.0 through 1.4.2. To customize the standard sidecar injector `ConfigMap` or
understand the changes we have made, see
[Customizing the manifests](config-options).

## Adding {{site.prodname}} authorization services to the mesh

Apply the following manifest to configure Istio to query {{site.prodname}} for application layer policy authorization decisions

```bash
kubectl apply -f {{site.url}}/{{page.version}}/manifests/alp/istio-app-layer-policy.yaml
```

> **Note**: You can also
> [view the manifest in your browser]({{site.url}}/{{page.version}}/manifests/alp/istio-app-layer-policy.yaml){:target="_blank"}.
{: .alert .alert-info}

## Adding namespace labels

Application layer policy is only enforced on pods that are started with the
Envoy and Dikastes sidecars.  Pods that do not have these sidecars will
only enforce standard {{site.prodname}} network policy.

You can control this on a per-namespace basis.  To enable Istio and application
layer policy in a namespace, add the label `istio-injection=enabled`.

	kubectl label namespace <your namespace name> istio-injection=enabled

If the namespace already has pods in it, you will have to recreate them for this
to take effect.

**Note**: Envoy must be able to communicate with the
`istio-pilot.istio-system` service. If you apply any egress policies to your
pods, you *must* enable access. For example, you could
[apply a network policy]({{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/allow-istio-pilot.yaml).
{: .alert .alert-info}
