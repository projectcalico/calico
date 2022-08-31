---
title: Enable default deny for Kubernetes pods
description: Create a default deny network policy so pods that are missing policy are not allowed traffic until appropriate network policy is defined.
canonical_url: '/security/kubernetes-default-deny'
---

### Big picture

Enable a default deny policy for Kubernetes pods using Kubernetes or {{site.prodname}} network policy.

### Value

A **default deny** network policy provides an enhanced security posture -- so pods without policy (or incorrect policy) are not allowed traffic until appropriate network policy is defined.

### Features

This how-to guide uses the following {{site.prodname}} features:
- **NetworkPolicy**
- **GlobalNetworkPolicy**

### Concepts

#### Default deny/allow behavior

**Default allow** means all traffic is allowed by default, unless otherwise specified. **Default deny** means all traffic is denied by default, unless explicitly allowed. **Kubernetes pods are default allow**, unless network policy is defined to specify otherwise.

For compatibility with Kubernetes, **{{site.prodname}} network policy** enforcement follows the standard convention for Kubernetes pods:
- If no network policies apply to a pod, then all traffic to/from that pod is allowed.
- If one or more network policies apply to a pod with type ingress, then only the ingress traffic specifically allowed by those policies is allowed.
- If one or more network policies apply to a pod with type egress, then only the egress traffic specifically allowed by those policies is allowed.

For other endpoint types (VMs, host interfaces), the default behavior is to deny traffic. Only traffic specifically allowed by network policy is allowed, even if no network policies apply to the endpoint.

#### Best practice: implicit default deny policy

We recommend creating an implicit default deny policy for your Kubernetes pods, regardless if you use {{site.prodname}} or Kubernetes network policy. This ensures that unwanted traffic is denied by default. Note that implicit default deny policy always occurs last; if any other policy allows the traffic, then the deny does not come into effect. The deny is executed only after all other policies are evaluated.

### Before we begin
If you haven't already, you will need to [install calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install) to apply the example {{site.prodname}} network policies from this page.

### How to

Although you can use any of the following policies to create default deny policy for Kubernetes pods, we recommend using the {{site.prodname}} global network policy. A {{site.prodname}} global network policy applies to all workloads (VMs and containers) in all namespaces, as well as hosts (computers that run the hypervisor for VMs, or container runtime for containers). Using a {{site.prodname}} global network policy supports a conservative security stance for protecting resources.

- [Enable default deny {{site.prodname}} global network policy, non-namespaced](#enable-default-deny-calico-global-network-policy-non-namespaced)
- [Enable default deny {{site.prodname}} network policy, namespaced](#enable-default-deny-calico-network-policy-namespaced)
- [Enable default deny Kubernetes policy, namespaced](#enable-default-deny-Kubernetes-policy-namespaced)

#### Enable default deny {{site.prodname}} global network policy, non-namespaced

You can use a {{site.prodname}} global network policy to enable a default deny across your whole cluster. The following example applies to all workloads (VMs and containers) in all namespaces, as well as hosts (computers that run the hypervisor for VMs, or container runtime for containers).

> **Note**: Before applying the following please continue reading the rest of this section to find out why this might not be the best policy to apply to your cluster.
{: .alert .alert-info }

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: all()
  types:
  - Ingress
  - Egress
```

The above policy applies to all pods and host endpoints, including Kubernetes control plane and {{site.prodname}} control plane nodes and pods.
Such policy has the potential to break your cluster if you do not already have the correct "Allow" policies and {{site.prodname}} [failsafe ports]({{site.baseurl}}/reference/felix/configuration) in place to ensure control plane traffic does not get blocked.

As an alternative best practice we recommend to use the following example, which applies a default-deny behaviour to all non-system pods. The policy
also allows access kube-dns, which simplifies per pod policies since you don't need to duplicate the DNS rules in every policy.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-app-policy
spec:
  namespaceSelector: has(projectcalico.org/name) && projectcalico.org/name not in {"kube-system", "calico-system", "calico-apiserver"}
  types:
  - Ingress
  - Egress
  egress:
  # allow all namespaces to communicate to DNS pods
  - action: Allow
    protocol: UDP
    destination:
      selector: 'k8s-app == "kube-dns"'
      ports:
      - 53
```

It is important to note the above policy deliberately excludes the `kube-system`, `calico-system` and `calico-apiserver` namespaces by using a negative `namespaceSelector` to avoid impacting any control plane components. To secure the control plane you can write specific policies for each control plane component, though you should do so with care, ideally at cluster creation time, since getting these wrong can leave your cluster in a broken state. We recommend you always make sure you have the correct {{site.prodname}} [failsafe ports]({{site.baseurl}}/reference/felix/configuration) in place before you start trying to create policies for the control plane. 

#### Enable default deny {{site.prodname}} network policy, namespaced

In the following example, we enable a default deny **NetworkPolicy** for all workloads in the namespace, **engineering**.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: engineering
spec:
  selector: all()
  types:
  - Ingress
  - Egress
```

#### Enable default deny Kubernetes policy, namespaced

In the following example, we enable a default deny **Kubernetes network policy** for all pods in the namespace, **engineering**.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: engineering
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Above and beyond

- [Network policy]({{ site.baseurl }}/reference/resources/networkpolicy)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
