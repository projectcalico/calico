---
title: Basic rules
description: Define network connectivity for Calico endpoints using policy rules and label selectors. 
---

### Big picture

Use Calico policy rules and label selectors that match Calico endpoints (pods, OpenStack VMs, and host interfaces) to define network connectivity.

### Value

If you've read [Get started with Calico policy]({{ site.baseurl }}/security/calico-network-policy) and [Kubernetes policy]({{ site.baseurl }}/security/kubernetes-network-policy), you already know how to use label selectors to apply policy rules. This section provides more examples of using Calico policy rules. For all policy rules, see: 

- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
- [Network policy]({{ site.baseurl }}/reference/resources/networkpolicy)

### Above and beyond

- {% include enterprise_icon.html %}[Advanced egress access controls with Calico Enterprise]({{ site.baseurl }}/security/calico-enterprise/egress-access-controls)
- {% include enterprise_icon.html %}[Federation]({{ site.baseurl }}/security/calico-enterprise/federation)
- {% include enterprise_icon.html %}[Calico Enterprise user console]({{ site.baseurl }}/security/calico-enterprise/user-console)