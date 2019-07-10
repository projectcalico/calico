---
title: Use service accounts in policy rules
---

### Big picture

Use Calico network policy to allow/deny traffic for Kubernetes service accounts. 

### Value

Kubernetes RBAC allows you to control which users are allowed to create and use service accounts. Combined with Calico network policy, you can control the security boundary between users who can provision service accounts, and those who use them.

For example, using Kubernetes RBAC, you can restrict permissions to provision service accounts to only the network security team, who can then write high-priority network policies that reference those service accounts.

Additionally, when using Istio-enabled apps with Calico network policy, the cryptographic identity associated with the service account is checked (along with the network identity) to achieve two-factor authentication.

### Features

This how-to guide uses the following Calico features:

**NetworkPolicy** or **GlobalNetworkPolicy** with a service account rule and match criteria.

### Concepts

#### Use smallest set of permissions required

Operations on service accounts are controlled by RBAC, so you can grant permissions only to trusted entities (code and/or people) to create, modify, or delete service accounts. To perform any operation in a workload, clients are required to authenticate with the Kubernetes API server. 

If you do not explicitly assign a service account to a pod, it uses the default ServiceAccount in the namespace. 

You should not grant broad permissions to the default service account for a namespace. If an application needs access to the Kubernetes API, create separate service accounts with the smallest set of permissions required. 

#### Service account labels

Like all other Kubernetes objects, service accounts have labels. You can use labels to create ‘groups’ of service accounts. Calico network policy lets you select workloads by their service account using:

- An exact match on service account name
- A service account label selector expression

### Before you begin...

Configure unique Kubernetes service accounts for your applications.

### How to

- [Limit ingress traffic for workloads by service account name](#limit-ingress-traffic-for-workloads-by-service-account-name)
- [Limit ingress traffic for workloads by service account label](#limit-ingress-traffic-for-workloads-by-service-account-label)

#### Limit ingress traffic for workloads by service account name

In the following example, ingress traffic is allowed from any workload whose service account matches the names **api-service** or **user-auth-service**.

```
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

```
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
          selector: 'app == "web-frontend"'
  selector: 'app == "db"'
```

### Above and beyond

- [Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy) 
- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy) 
