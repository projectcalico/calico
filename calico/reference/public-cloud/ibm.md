---
title: IBM Cloud
description: Calico integration with IBM Cloud.
canonical_url: '/reference/public-cloud/ibm'
---

{{site.prodname}} is installed and configured automatically in your {% include open-new-window.html text='IBM Cloud Kubernetes Service' url='https://www.ibm.com/cloud/container-service/' %}.  Default policies are created to protect your Kubernetes cluster, with the option to create your own policies to protect specific services.

## IP-in-IP encapsulation

[IP-in-IP encapsulation]({{site.baseurl}}/networking/vxlan-ipip) is automatically configured to only encapsulate packets traveling across subnets, and uses NAT for outgoing connections from your containers.

## Enabling workload-to-WAN traffic

This is also handled automatically in the {% include open-new-window.html text='IBM Cloud Kubernetes Service' url='https://www.ibm.com/cloud/container-service/' %}.  No additional configuration of Calico is necessary.