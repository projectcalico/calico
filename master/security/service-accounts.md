---
title: Use service accounts in policy rules
---

### Big picture

Use Calico network policy to allow/deny traffic for Kubernetes services. 

### Value

Using Calico network policy, you can leverage Kubernetes service accounts with RBAC for flexible control over how policies are applied in a cluster. For example, the Network Security can have RBAC permissions to:

- Control which service accounts the Developer team can use within a namespace
- Write high-priority network policies for those service accounts (that the Developer team cannot override) 

The Network Security team can maintain full control of security, while selectively allowing Developer operations where it makes sense.  

Using **Istio-enabled apps** with Calico network policy, the cryptographic identity associated with the service account is checked (along with the network identity) to achieve two-factor authentication.

### Features

This how-to guide uses the following Calico features:

**NetworkPolicy** or **GlobalNetworkPolicy** with a service account rule and match criteria.


### Concepts

#### Use smallest set of permissions required

Service accounts are controlled by RBAC so you can grant permissions to trusted entities (code and/or people). To perform any operation in a workload, clients are required to authenticate with the Kubernetes API server. If you do not explicitly assigned a service account to a pod, it uses the default ServiceAccount in the namespace. You should not grant broad permissions to the default service account for a namespace. If an application needs access to the Kubernetes API, create separate service accounts with the smallest set of permissions required. 

#### Service account labels

Like all other Kubernetes objects, service accounts have labels. So you can use labels to create ‘groups’ of service accounts. For Calico network policy, you can limit access to workloads by matching:

- Endpoints in a service account (additionally, with a positive match on a namespace)
- Service account names and selectors

### Before you begin...

Configure unique Kubernetes service accounts for your applications

### How to

- [Limit ingress traffic for workloads by service account name](#limit-ingress-traffic-for-workloads-by-service-account-name)
- [Limit ingress traffic for workloads by service account label](#limit-ingress-traffic-for-workloads-by-service-account-label)

#### Limit ingress traffic for workloads by service account name

In the following example, ingress traffic is allowed from any workload in the **prod-engineering** namespace, whose service account has the names **ingress-sa-in-calico** or **ingress-w-in-calico**.

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
        namespaceselector: 'ingress == "prod-engineering"'
        selector: 'app == "db"'
        serviceAccounts: 
          names: 
            - ingress-sa-in-calico
            - ingress-w-in-calico
  selector: 'app == "front-end"'
```

#### Limit ingress traffic for workloads by service account label

In the following example, ingress traffic is allowed from any workload in the **prod-engineering** namespace, whose service account has the label **app == db**.

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
          selector: 'app == "db"'
  selector: 'app == "web-frontend"'
```

### Above and beyond

- [Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/networkpolicy) 
- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy) 
