---
title: Enabling application layer policy for Istio
description: Enforce application layer network policy for Istio using Calico network policy.
canonical_url: 'https://docs.projectcalico.org/v3.9/getting-started/kubernetes/installation/app-layer-policy'
---

### Big picture

Enable {{site.prodname}} application layer network policy in Istio service mesh.

### Value

{{site.prodname}} application layer policy lets you enforce application layer attributes like HTTP methods or paths, and cryptographically secure identities for Istio-enabled apps.

### Concepts

#### Mitigate threats with {{site.prodname}} network policy

Although Istio policy is ideal for operational goals, security inside and outside the cluster requires {{site.prodname}} network policy. {{site.prodname}} supports a special integration for Istio, called **application layer policy**. This policy lets you restrict ingress traffic inside and outside pods, and mitigate common threats to Istio-enabled apps.

For a tutorial on how application layer policy provides second-factor authentication for the mythical Yao Bank, see [Enforce network policy using Istio]({{site.url}}/{{page.version}}/security/tutorials/app-layer-policy/enforce-policy-istio).

### Before you begin...

**Required**

- [Calico is installed]({{site.url}}/{{page.version}}/getting-started/)
- [calicoctl is installed and configured]({{site.url}}/{{page.version}}/getting-started/calicoctl/install)
- Kubernetes 1.15 or older (Istio 1.1.7 does not support Kubernetes 1.16+).
See this [issue](https://github.com/projectcalico/calico/issues/2943) for details and workaround.

### How to

1. [Enable application layer policy](#enable-application-layer-policy)
1. [Install Istio](#install-istio)
1. [Update Istio sidecar injector](#update-istio-sidecar-injector)
1. [Add Calico authorization services to the mesh](#add-calico-authorization-services-to-the-mesh)
1. [Add namespace labels](#add-namespace-labels)

#### Enable application layer policy

To enable the application layer policy, you must enable the **Policy Sync API** on Felix cluster-wide.

In the default **FelixConfiguration**, set the field, `policySyncPathPrefix` to `/var/run/nodeagent`:

```bash
calicoctl patch FelixConfiguration default --patch \
   '{"spec": {"policySyncPathPrefix": "/var/run/nodeagent"}}'
```

#### Install Istio

1. Verify [application layer policy requirements]({{site.url}}/{{page.version}}/getting-started/kubernetes/requirements#application-layer-policy-requirements).
1. Install Istio using the [Istio project documentation](https://archive.istio.io/v1.3/docs/setup/install/) making sure to enable mutual TLS authentication. For example:

```bash
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.4.2 sh -
cd $(ls -d istio-*)
./bin/istioctl manifest apply --set values.global.mtls.enabled=true --set values.global.controlPlaneSecurityEnabled=true
```

#### Update Istio sidecar injector

The sidecar injector automatically modifies pods as they are created to work with Istio. This step modifies the injector configuration to add Dikastes (a {{site.prodname}} component), as sidecar containers.

1. Follow the [Automatic sidecar injection instructions](https://archive.istio.io/v1.3/docs/setup/additional-setup/sidecar-injection/#automatic-sidecar-injection) to install the sidecar injector and enable it in your chosen namespace(s).
1. Patch the istio-sidecar-injector `ConfigMap` to enable injection of Dikastes alongside Envoy.

```
curl {{site.url}}/{{page.version}}/manifests/alp/istio-inject-configmap-1.4.2.yaml -o istio-inject-configmap.yaml
kubectl patch configmap -n istio-system istio-sidecar-injector --patch "$(cat istio-inject-configmap.yaml)"
```
[View sample manifest]({{site.url}}/{{page.version}}/manifests/alp/istio-inject-configmap-1.3.5.yaml){:target="_blank"}

If you installed a different version of Istio, substitute 1.4.2 in the above URL for your Istio version. We have predefined `ConfigMaps` for Istio versions 1.1.0 through 1.1.17, 1.2.0 through 1.2.9, 1.3.0 through 1.3.5, and 1.4.0 through 1.4.2. To customize the standard sidecar injector `ConfigMap` or understand the changes we have made, see [Customizing the manifests]({{site.url}}/{{page.version}}/getting-started/kubernetes/installation/config-options).

#### Add Calico authorization services to the mesh

Apply the following manifest to configure Istio to query {{site.prodname}} for application layer policy authorization decisions.

```
kubectl apply -f {{site.url}}/{page.version}}/manifests/alp/istio-app-layer-policy.yaml
```

[View sample manifest]({{site.url}}/{{page.version}}/manifests/alp/istio-app-layer-policy.yaml){:target="_blank"}

#### Add namespace labels

You can control enforcement of application layer policy on a per-namespace basis. However, this only works on pods that are started with the Envoy and {{site.prodname}} Dikastes sidecars (as noted in the step, Update Istio sidecar injector). Pods that do not have the {{site.prodname}} sidecars, enforce only standard {{site.prodname}} network policy.

To enable Istio and application layer policy in a namespace, add the label `istio-injection=enabled`.

```
kubectl label namespace <your namespace name> istio-injection=enabled
```

If the namespace already has pods in it, you must recreate them for this to take effect.

>**Note**: Envoy must be able to communicate with the `istio-pilot.istio-system service`. If you apply any egress policies to your pods, you *must* enable access. For example, you could [apply a network policy]({{site.url}}/{{page.version}}/getting-started/kubernetes/installation/manifests/app-layer-policy/allow-istio-pilot.yaml).
{: .alert .alert-info}

### Above and beyond

- [Enforce network policy using Istio tutorial]({{site.url}}/{{page.version}}/security/tutorials/app-layer-policy/enforce-policy-istio)
- [Enforce network policy using Istio]({{site.url}}/{{page.version}}/security/enforce-policy-istio)
- [Use HTTP methods and paths in policy rules]({{site.url}}/{{page.version}}/security/http-methods)
