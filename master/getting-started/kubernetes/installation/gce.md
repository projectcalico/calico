---
title: Deploying Calico and Kubernetes on GCE
---

There are several possibilities for [deploying Kubernetes on GCE][running-GCE-on-K8s]
and with minimal adjustments Calico can be [installed](.) too.
The information on this page provides the customization needed.

### Setting up GCE networking

Setting up Kubernetes will require [some GCE firewall rules][default-GCE-networking]
for communication to be allowed between hosts in the cluster, in addition to
those rules a rule is required that allows IP-in-IP traffic between the
hosts in the cluster.  The following command allows IP-in-IP traffic to
flow between containers on different hosts (where the source-ranges parameter
assumes you have created your project with the default GCE network
parameters - modify the address range if yours is different):

**Note**: The [gcloud tool][gcloud-instructions] must be installed and configured before using the commands below.

```shell
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.128.0.0/9"
```

You can verify the rule with this command:

```shell
gcloud compute firewall-rules list
```

[running-GCE-on-K8s]: https://kubernetes.io/docs/getting-started-guides/gce/
[default-GCE-networking]: https://kubernetes.io/docs/getting-started-guides/gce/#networking
[gcloud-instructions]: https://cloud.google.com/sdk/
