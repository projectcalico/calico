---
title: Calico Configured Automatically in IBM Cloud
canonical_url: https://docs.projectcalico.org/master/reference/public-cloud/ibm
---

{{site.prodname}} is installed and configured automatically in your [IBM Cloud Kubernetes Service][IBMKUBE].  Default policies are created to protect your Kubernetes cluster, with the option to create your own policies to protect specific services.

## IP-in-IP encapsulation

[IP-in-IP encapsulation][IPIP] is automatically configured to only encapsulate packets traveling across subnets, and uses NAT for outgoing connections from your containers.

## Enabling Workload-to-WAN Traffic

This is also handled automatically in the [IBM Cloud Kubernetes Service][IBMKUBE].  No additional configuration of Calico is necessary.

[IPIP]: {{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip
[IBMKUBE]: https://www.ibm.com/cloud/container-service/
