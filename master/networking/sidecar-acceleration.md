---
title: Accelerating Istio network performance
---

### Big picture

Use Calico to accelerate network performance of routing network traffic via Istio Envoy sidecar.

> **Warning!** This feature is experimental and should not be used in production clusters. It uses a recent Linux kernel feature (eBPF SOCKMAP), which our testing confirms requires upstream kernel enhancements to reliably and securely support production clusters. We are contributing fixes to the kernel where needed.
{: .alert .alert-danger }

### Value

Istio directs all application network traffic through an Envoy sidecar in each pod, which introduces network overhead for all traffic. Calico can greatly reduce this network overhead by automatically optimizing the Linux network path for this traffic.

### Features

This how-to guide uses the following Calico features:

**Felix configuration** with **SidecarAccelerationEnabled** configuration option. 


### Concepts

#### Sidecar acceleration

The Sidecar acceleration process bypasses several layers of kernel networking, allowing data to flow between the sockets unobstructed. This makes the Envoy proxy (sidecar) to container network path as fast and efficient as possible. 


### Before you begin...

- [Enable application layer policy]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy)
- Verify that hosts installed with Calico are using Linux kernel 4.19 and above

#### Sidecar acceleration: experimental technology

The sidecar app acceleration feature is disabled by default in Calico because the technology is currently not production ready. Use only in test environments until the technology is hardened for production security.

### How to

To enable sidecar acceleration for Istio-enabled apps using Calico:

1. Get the default Felix configuration. 

    `$ calicoctl get felixconfiguration default --export -o yaml > felix-config.yaml`

2. Edit felix-config.yaml and add the option, `SidecarAccelerationEnabled: true` to the end.  

   ```
   apiVersion: projectcalico.org/v3
   kind: FelixConfiguration
   metadata:
     creationTimestamp: null
     name: default
   spec:
     XDPRefreshInterval: null
     ipipEnabled: true
     logSeverityScreen: Info
     policySyncPathPrefix: /var/run/nodeagent
     reportingInterval: 0s
     sidecarAccelerationEnabled: true
   ``` 

3. Apply the updated configuration.  

   ```
   $ calicoctl apply -f felix-config.yaml 
   Successfully applied 1 'FelixConfiguration' resource(s)
   ```

That’s it!  Network traffic that is routed between apps and the Envoy sidecar is automatically accelerated at this point. Note that if you have an existing Istio/Calico implementation and you enable sidecar acceleration, existing connections do not benefit from acceleration.
