---
title: Basic rules
description: Define network connectivity for Calico endpoints using policy rules and label selectors. 
---

### Big picture

Use Calico policy rules and label selectors that match Calico endpoints (pods, OpenStack VMs, and host interfaces) to define network connectivity.

### Value

Using label selectors to identify the endpoints (pods, OpenStack VMs, host interfaces) that a policy applies to, or that should be selected by policy rules, means you can define policy without knowing the IP addresses of the endpoints. This is ideal for handling dynamic workloads with ephemeral IPs (such as Kubernetes pods).

### How to

Read [Get started with Calico policy]({{ site.baseurl }}/security/calico-network-policy) and [Kubernetes policy]({{ site.baseurl }}/security/kubernetes-network-policy), which cover all the basics of using label selectors in policies to select endpoints the policies apply to, or in policy rules. 

### Above and beyond

- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
- [Network policy]({{ site.baseurl }}/reference/resources/networkpolicy)
- {% include enterprise_icon.html %}[Advanced egress access controls with Calico Enterprise]({{ site.baseurl }}/security/calico-enterprise/egress-access-controls)
- {% include enterprise_icon.html %}[Federation]({{ site.baseurl }}/security/calico-enterprise/federation)
- {% include enterprise_icon.html %}[Calico Enterprise user console]({{ site.baseurl }}/security/calico-enterprise/user-console)
