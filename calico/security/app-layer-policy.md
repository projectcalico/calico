---
title: Enforce network policy for Istio
description: Enforce network policy for Istio service mesh including matching on HTTP methods and paths.
canonical_url: '/security/app-layer-policy'
---

### Big picture

{{site.prodname}} integrates seamlessly with Istio to enforce network policy within the Istio service mesh.

### Value

{{site.prodname}} network policy for Istio lets you enforce application layer attributes like HTTP methods or paths, and cryptographically secure identities for Istio-enabled apps.

### Concepts

#### Benefits of the Istio integration

The {{site.prodname}} support for Istio service mesh has the following benefits:

- **Pod traffic controls**

  Lets you restrict ingress traffic inside and outside pods and mitigate common threats to Istio-enabled apps.

- **Supports security goals**

  Enables adoption of a zero trust network model for security, including traffic encryption, multiple enforcement points, and multiple identity criteria for authentication.

- **Familiar policy language**

  Kubernetes network policies and {{site.prodname}} network policies work as is; users do not need to learn another network policy model to adopt Istio.

See [Enforce network policy using Istio tutorial]({{site.baseurl}}/security/tutorials/app-layer-policy/enforce-policy-istio) to learn how application layer policy provides second-factor authentication for the mythical Yao Bank.

### Before you begin

**Required**

- [{{site.prodname}} is installed]({{site.baseurl}}/getting-started/kubernetes/)
- [calicoctl is installed and configured]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Istio support**

Following Istio versions have been verified to work with application layer policies:
- Istio v1.10.2
- Istio v1.9.6

Istio v1.7.x and lower are **not** supported.

Although we expect future minor versions to work with the corresponding manifest below (for example, v1.9.7 or v1.10.3), manifest compatibility depends entirely on the upstream changes in the respective Istio release.

### How to

1. [Enable application layer policy](#enable-application-layer-policy)
1. [Install Calico CSI Driver](#install-calico-csi-driver)
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

#### Install Calico CSI Driver

{{site.prodname}} utilizes a Container Storage Interface (CSI) driver to help set up the policy sync API on every node.
Apply the following to install the Calico CSI driver

```bash
kubectl apply -f {{ "/manifests/csi-driver.yaml" | absolute_url }}
```

#### Install Istio

1. Verify [application layer policy requirements]({{site.baseurl}}/getting-started/kubernetes/requirements#application-layer-policy-requirements).
1. Install Istio using {% include open-new-window.html text='installation guide in the project documentation' url='https://istio.io/v1.9/docs/setup/install/' %}.

```bash
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.10.2 sh -
cd $(ls -d istio-* --color=never)
./bin/istioctl install
```

Next, create the following {% include open-new-window.html text='PeerAuthentication' url='https://istio.io/latest/docs/reference/config/security/peer_authentication/' %} policy.

Replace `namespace` below by `rootNamespace` value, if it's customized in your environment.

```bash
kubectl create -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default-strict-mode
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
EOF
```

#### Update Istio sidecar injector

The sidecar injector automatically modifies pods as they are created to work with Istio. This step modifies the injector configuration to add Dikastes (a {{site.prodname}} component), as sidecar containers.

1. Follow the [Automatic sidecar injection instructions](https://archive.istio.io/v1.9/docs/setup/additional-setup/sidecar-injection/#automatic-sidecar-injection){:target="_blank"} to install the sidecar injector and enable it in your chosen namespace(s).
1. Patch the istio-sidecar-injector `ConfigMap` to enable injection of Dikastes alongside Envoy.

{% tabs %}
<label:Istio v1.10.x,active:true>
<%
```bash
curl {{ "/manifests/alp/istio-inject-configmap-1.10.yaml" | absolute_url }} -o istio-inject-configmap.yaml
kubectl patch configmap -n istio-system istio-sidecar-injector --patch "$(cat istio-inject-configmap.yaml)"
```

[View sample manifest]({{ "/manifests/alp/istio-inject-configmap-1.10.yaml" | absolute_url }}){:target="_blank"}
%>
<label:Istio v1.9.x>
<%
```bash
curl {{ "/manifests/alp/istio-inject-configmap-1.9.yaml" | absolute_url }} -o istio-inject-configmap.yaml
kubectl patch configmap -n istio-system istio-sidecar-injector --patch "$(cat istio-inject-configmap.yaml)"
```

[View sample manifest]({{ "/manifests/alp/istio-inject-configmap-1.9.yaml" | absolute_url }}){:target="_blank"}
%>
{% endtabs %}

#### Add Calico authorization services to the mesh

Apply the following manifest to configure Istio to query {{site.prodname}} for application layer policy authorization decisions.

{%tabs%}
<label: Istio v1.10.x and v1.9.x,active:true>
<%
```bash
kubectl apply -f {{ "/manifests/alp/istio-app-layer-policy-envoy-v3.yaml" | absolute_url }}
```
[View sample manifest]({{ "/manifests/alp/istio-app-layer-policy-envoy-v3.yaml" | absolute_url }}){:target="_blank"}
%>
{% endtabs %}

#### Add namespace labels

You can control enforcement of application layer policy on a per-namespace basis. However, this only works on pods that are started with the Envoy and {{site.prodname}} Dikastes sidecars (as noted in the step, Update Istio sidecar injector). Pods that do not have the {{site.prodname}} sidecars, enforce only standard {{site.prodname}} network policy.

To enable Istio and application layer policy in a namespace, add the label `istio-injection=enabled`.

```
kubectl label namespace <your namespace name> istio-injection=enabled
```

If the namespace already has pods in it, you must recreate them for this to take effect.

>**Note**: Envoy must be able to communicate with the `istio-pilot.istio-system service`. If you apply any egress policies to your pods, you *must* enable access. For example, you could [apply a network policy]({{ "/getting-started/kubernetes/installation/manifests/app-layer-policy/allow-istio-pilot.yaml" | absolute_url }}).
{: .alert .alert-info}

### Above and beyond

- [Enforce network policy using Istio tutorial]({{site.baseurl}}/security/tutorials/app-layer-policy/enforce-policy-istio)
- [Use HTTP methods and paths in policy rules]({{site.baseurl}}/security/http-methods)
