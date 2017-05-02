---
title: Deploying Calico and Kubernetes on GCE
---

There are several tools for deploying a Kubernetes cluster on Google Compute
Engine and with minimal adjustments Calico can be [installed](.) too.
The information on this page describes Calico's requirements to operate
successfully on Google Compute Engine.

### Setting up GCE networking

In addition to the standard [GCE firewall rules required by kubernetes][default-GCE-networking],
Calico will need a firewall rule to allow IP-in-IP traffic between hosts.
The following command allows IP-in-IP traffic to flow between containers on
different hosts (where the source-ranges parameter assumes you have created
your project with the default GCE network parameters - modify the address
range if yours is different):

**Note**: The [gcloud tool][gcloud-instructions] must be installed and configured before using the commands below.

```shell
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.128.0.0/9"
```

You can verify the rule with this command:

```shell
gcloud compute firewall-rules list
```

[default-GCE-networking]: https://kubernetes.io/docs/getting-started-guides/gce/#networking
[gcloud-instructions]: https://cloud.google.com/sdk/
