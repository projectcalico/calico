---
title: Get started with Calico network policy for OpenStack
description: Extend OpenStack security groups by applying Calico network policy and using labels to identify VMs within network policy rules.
---

### Big picture

Use {{site.prodname}} network policy to extend security beyond OpenStack security groups.

### Value

For **deployment users**, OpenStack security groups provides enough features and flexibility. But for **deployment administrators**, limited labeling in VM security groups makes it difficult to address all security use cases that arise. {{site.prodname}} network policy provides special VM labels so you can identify VMs and impose additional restrictions that cannot be bypassed by users’ security group configuration. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- {{site.prodname}} predefined **OpenStack VM endpoint labels**
- **GlobalNetworkPolicy** or **NetworkPolicy**

### Concepts

#### Multi-region deployments

Using the OpenStack API, it is difficult to apply policy to cross-region network traffic because security groups are local to a single region. In {{site.prodname}}, each region in your OpenStack deployment becomes a separate {{site.prodname}} namespace in a single etcd datastore. With regions mapped to namespaces, you can easily define {{site.prodname}} network policy for communications between VMs in different regions. 

#### Labels: more flexibility, greater security

{{site.prodname}} provides predefined [VM endpoint labels]({{ site.baseurl }}/networking/openstack/labels) (projects, security groups, and namespaces) for OpenStack deployments. You can use these labels in selector fields in {{site.prodname}} network policy to identify the VMs for allow/deny policy.

#### Policy ordering and enforcement

{{site.prodname}} network policy is always enforced before OpenStack security groups, and cannot be overridden by user-level security group configuration. 

### Before you begin...

- [Set up {{site.prodname}} for OpenStack]({{ site.baseurl }}/networking/openstack/dev-machine-setup)
- If you are using a multi-region VM deployment, [follow these extra steps]({{ site.baseurl }}/networking/openstack/multiple-regions)

### How to

- [Restrict all ingress traffic between specific security groups](#restrict-all-ingress-traffic-between-specific-security-groups)
- [Allow specific traffic between VMs in different regions](#allow-specific-traffic-between-vms-in-different-regions)

#### Restrict all ingress traffic between specific security groups

In the following example, we create a **GlobalNetworkPolicy** that is applied before any OpenStack security group policy. It prevents all ingress communication between the OpenStack **superman** and **lexluthor** projects. We use the predefined {{site.prodname}} VM endpoint label, **openstack-project-name**, to identify projects.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-lexluthor-to-superman
spec:
  order: 10
  selector: "projectcalico.org/openstack-project-name == 'superman'"
  types:
  - Ingress
  ingress:
  - action: Deny
    source:
      selector: "projectcalico.org/openstack-project-name == 'lexluthor'"
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-superman-to-lexluthor
spec:
  order: 10
  selector: "projectcalico.org/openstack-project-name == 'lexluthor'"
  types:
  - Ingress
  ingress:
  - action: Deny
    source:
      selector: "projectcalico.org/openstack-project-name == 'superman'"
```

#### Allow specific traffic between VMs in different regions

In the following example, we use the predefined VM endpoint label, **openstack-security_group_ID**. Traffic is allowed to VMs with the label, **openstack-a773…** on port 80, from VMs in any region with the label, **openstack-85cc…**.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-tcp-80
spec:
  selector: "has(sg.projectcalico.org/openstack-a7734e61-b545-452d-a3cd-0189cbd9747a)"
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: "has(sg.projectcalico.org/openstack-85cc3048-abc3-43cc-89b3-377341426ac5)"
    destination:
      ports:
      - 80
```

### Above and beyond

- For additional {{site.prodname}} network policy features, see [{{site.prodname}} network policy]({{ site.baseurl }}/reference/resources/networkpolicy) and [Calico global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
- For details on the OpenStack integration with {{site.prodname}}, see [{{site.prodname}} for OpenStack]({{ site.baseurl }}/networking/openstack/dev-machine-setup)
