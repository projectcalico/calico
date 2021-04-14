---
title: Install from a private registry
description: Install and configure Calico Enterprise in a private registry. 
layout: null
---

[//]: #  This is used in manifests archive, though it doesn't appear on the website

{% assign operator = site.data.versions.first.tigera-operator %}

### Before you begin...

- Configure pull access to your private registry
- [Configure pull access to Tigera's private container registry]({{ "/getting-started/calico-enterprise#get-private-registry-credentials-and-license-key" | absolute_url }} ).


{% include content/private-registry-regular.md %}

>**Note:** See [the Installation resource reference page]( {{ "/reference/installation/api" | absolute_url }} ) for more information on the `imagePullSecrets` and `registry` fields.

