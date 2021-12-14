---
title: Use service accounts rules in policy
description: Use Kubernetes service accounts in policies to validate cryptographic identities and/or manage RBAC controlled high-priority rules across teams.
---

### Big picture

Use {{site.prodname}} network policy to allow/deny traffic for Kubernetes service accounts.

### Value

Using {{site.prodname}} network policy, you can leverage Kubernetes service accounts with RBAC for flexible control over how policies are applied in a cluster. For example, the security team can have RBAC permissions to:

- Control which service accounts the developer team can use within a namespace
- Write high-priority network policies for those service accounts (that the developer team cannot override) 

The network security team can maintain full control of security, while selectively allowing developer operations where it makes sense.  

Using **Istio-enabled apps** with {{site.prodname}} network policy, the cryptographic identity associated with the service account is checked (along with the network identity) to achieve two-factor authentication.

### Features

This how-to guide uses the following {{site.prodname}} features:

**NetworkPolicy** or **GlobalNetworkPolicy** with a service account rule and match criteria.

### Concepts

#### Use smallest set of permissions required

Operations on service accounts are controlled by RBAC, so you can grant permissions only to trusted entities (code and/or people) to create, modify, or delete service accounts. To perform any operation in a workload, clients are required to authenticate with the Kubernetes API server.

If you do not explicitly assign a service account to a pod, it uses the default ServiceAccount in the namespace.

You should not grant broad permissions to the default service account for a namespace. If an application needs access to the Kubernetes API, create separate service accounts with the smallest set of permissions required.

#### Service account labels

Like all other Kubernetes objects, service accounts have labels. You can use labels to create ‘groups’ of service accounts. {{site.prodname}} network policy lets you select workloads by their service account using:

- An exact match on service account name
- A service account label selector expression

### Before you begin...

Configure unique Kubernetes service accounts for your applications.

### How to

- [Limit ingress traffic for workloads by service account name](#limit-ingress-traffic-for-workloads-by-service-account-name)
- [Limit ingress traffic for workloads by service account label](#limit-ingress-traffic-for-workloads-by-service-account-label)
- [Use Kubernetes RBAC to control service account label assignment](#use-kubernetes-rbac-to-control-service-account-label-assignment)

#### Limit ingress traffic for workloads by service account name

In the following example, ingress traffic is allowed from any workload whose service account matches the names **api-service** or **user-auth-service**.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: demo-calico
  namespace: prod-engineering
spec:
  ingress:
    - action: Allow
      source:
        serviceAccounts:
          names:
            - api-service
            - user-auth-service
  selector: 'app == "db"'
```

#### Limit ingress traffic for workloads by service account label

In the following example, ingress traffic is allowed from any workload whose service account matches the label selector, **app == web-frontend**.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-web-frontend
  namespace: prod-engineering
spec:
  ingress:
    - action: Allow
      source:
        serviceAccounts:
          selector: 'app == "web-frontend"'
  selector: 'app == "db"'
```

#### Use Kubernetes RBAC to control service account label assignment

Network policies can be applied to endpoints using selectors that match labels on the endpoint, the endpoint's namespace, or the endpoint's service account. By applying selectors based on the endpoint's service account, you can use Kubernetes RBAC to control which users can assign labels to service accounts. This allows you to separate groups who can deploy pods from those who can assign labels to service accounts.

In the following example, pods with an intern service account can communicate only with pods with service accounts labeled, `role: intern`.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: restrict-intern-access
  namespace: prod-engineering
spec:
  serviceAccountSelector: 'role == "intern"'
  ingress:
    - action: Allow
      source:
        serviceAccounts:
          selector: 'role == "intern"'
  egress:
    - action: Allow
      destination:
        serviceAccounts:
          selector: 'role == "intern"'
```

### Above and beyond

- [Network policy]({{ site.baseurl }}/reference/resources/networkpolicy)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
