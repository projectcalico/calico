---
title: Use a specific MAC address for a pod
canonical_url: '/networking/pod-mac-address'
description: Specify the MAC address for a pod instead of allowing the operating system to assign one
---

### Big picture

Choose the MAC address for a pod instead of allowing the operating system to assign one.

### Value

Some applications bind software licenses to networking interface MAC addresses.

### Features

This how-to guide uses the following features: 

- Kubernetes Pod annotations

### Concepts

#### Container MAC address

The MAC address configured by the annotation described here will be visible from within the container on the eth0 interface. Since it is isolated to the container it will not collide with any other MAC addresses assigned to other pods on the same node.

### Before you begin...

Your cluster must be using Calico CNI in order to use this feature.

[Configuring the Calico CNI Plugins]({{ site.baseurl }}/reference/cni-plugin/configuration)

### How to

Annotate the pod with cni.projectcalico.org/hwAddr set to the desired MAC address. For example:

<pre>
  "cni.projectcalico.org/hwAddr": "1c:0c:0a:c0:ff:ee"
</pre>

The annotation must be present when the pod is created; adding it later has no effect.
