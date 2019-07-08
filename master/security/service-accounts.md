---
title: Use service accounts in policy rules
---

### Big picture

Use Calico network policy to allow/deny traffic for Kubernetes services. 

### Value

Using Calico network policy, you can leverage Kubernetes service accounts with RBAC for flexible control over how policies are applied in a cluster. For example, the network security can have RBAC permissions to:

- Control which service accounts the developer team can use within a namespace
- Write high-priority network policies for those service accounts (that the developer team cannot override) 

The network security team can maintain full control of security, while selectively allowing developer operations where it makes sense.  

Using **Istio-enabled apps** with Calico network policy, the cryptographic identity associated with the service account is checked (along with the network identity) to achieve two-factor authentication.

### Features

This how-to guide uses the following Calico features:

**NetworkPolicy** or **GlobalNetworkPolicy** with a service account rule and match criteria.


### Concepts

#### Use smallest set of permissions required

Service accounts are controlled by RBAC so you can grant permissions to trusted entities (code and/or people). To perform any operation in a workload, clients are required to authenticate with the Kubernetes API server. 

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
