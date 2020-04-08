---
title: Protect Kubernetes nodes
description: Protect Kubernetes nodes with host endpoints.
---

### Big picture

Secure Kubernetes nodes with automatically-created host endpoints and global network policy.

### Value

{{site.prodname}} can automatically create host endpoints for your Kubernetes nodes. The lifecycle of these host endpoints are managed by {{site.prodname}} in order to ensure policy selecting these host endpoints is enforced.

### Features

This how-to guide uses the following Calico features:
- **HostEndpoint**
- **Profile**
- **KubeControllersConfiguration**
- **GlobalNetworkPolicy**

### Concepts

### Host endpoints

Each host has one or more network interfaces that it uses to communicate externally. You can use {{site.prodname}} network policy to secure these interfaces (called host endpoints). {{site.prodname}} host endpoints can have labels, and they work the same as labels on workload endpoints. The network policy rules can apply to both workload and host endpoints using label selectors.

Host endpoints come in two flavors: `named` and `wildcard`. `Named` host endpoints secure a specific interface such as "eth0", and are created by setting `interfaceName: <name-of-that-interface>` -- for example, `interfaceName: eth0`.
`Wildcard` host endpoints secure _all_ of the hosts interfaces non-workload interfaces.

### Profiles

Profiles are similar to network policy in that you can specify ingress and egress rules. But they are very limited and are deprecated for specifying policy rules; namespaced and global network policy are much more flexible. 
However, profiles can be used in conjunction with host endpoints to modify default behavior of external traffic to/from the host in the absence of network policy.

#### Default behavior of external traffic to/from host

If a `named` host endpoint is added and network policy is not in place, the {{site.prodname}} default is to deny traffic to/from that endpoint (except for traffic allowed by failsafe rules). For `named` host endpoints, {{site.prodname}} blocks traffic only to/from interfaces that it’s been explicitly told about in network policy. Traffic to/from other interfaces is ignored.

If a `wildcard` host endpoint is added and network policy is not in place, the {{site.prodname}} default is to deny traffic to/from _all_ non-workload interfaces on the host (except for traffic allowed by failsafe rules).

The default behavior of external traffic to/from host endpoints can be changed by adding a [profile]({{ site.baseurl }}/reference/resources/profile) to the host endpoints.
{{site.prodname}} provides a profile named `projectcalico-allow-all` that contains ingress and egress rules that allow all traffic.
By adding this profile to your host endpoint, the host endpoint will allow traffic to/from it in the absence of policy that selects it.

### Before you begin...

Have a running {{site.prodname}} cluster and have calicoctl installed.

### How to

- [Enable automatic host endpoints](#enable-automatic-host-endpoints)

#### Enable automatic host endpoints

Before beginning, we will first apply a network policy that will allow all traffic. Create a new file named `allow-all.yaml` and paste in the following manifest:

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-all-heps
spec:
  ingress:
    - action: Allow
  egress:
    - action: Allow
  selector: has(kubernetes.io/hostname)
```

(TODO: check whether this label is always there in a k8s cluster)

Now apply the policy:

```bash
calicoctl apply -f - < allow-all.yaml
```

Now that this policy is in place, we can continue enabling automatic host endpoints.
In order to enable automatic host endpoints, we need to edit the `default` KubeControllersConfiguration instance. First, get the running instance's yaml:

```bash
calicoctl get kubecontrollersconfiguration default --export -oyaml > kcc.yaml
```

If you view the manifest, you may see something like:

```yaml
apiVersion: projectcalico.org/v3
kind: KubeControllersConfiguration
metadata:
  creationTimestamp: null
  name: default
spec:
  controllers:
    namespace:
      reconcilerPeriod: 5m0s
    node:
      reconcilerPeriod: 5m0s
      syncLabels: Enabled
    policy:
      reconcilerPeriod: 5m0s
    serviceAccount:
      reconcilerPeriod: 5m0s
    workloadEndpoint:
      reconcilerPeriod: 5m0s
  etcdV3CompactionPeriod: 10m0s
  healthChecks: Enabled
  logSeverityScreen: Info
status:
  environmentVars:
    DATASTORE_TYPE: kubernetes
    ENABLED_CONTROLLERS: node
  runningConfig:
    controllers:
      node:
        hostEndpoint:
          autoCreate: Disabled
        syncLabels: Disabled
    etcdV3CompactionPeriod: 10m0s
    healthChecks: Enabled
    logSeverityScreen: Info
```

Now edit the kubecontrollersconfiguration manifest. We will be setting `spec.controllers.node.hostEndpoint.autoCreate` to `true`.
Open `kcc.yaml` in your editor and modify it so it looks like this:

```yaml
apiVersion: projectcalico.org/v3
kind: KubeControllersConfiguration
metadata:
  creationTimestamp: null
  name: default
spec:
  controllers:
    namespace:
      reconcilerPeriod: 5m0s
    node:
      reconcilerPeriod: 5m0s
      syncLabels: Enabled
        hostEndpoint:
          autoCreate: Enabled
    policy:
      reconcilerPeriod: 5m0s
    serviceAccount:
      reconcilerPeriod: 5m0s
    workloadEndpoint:
      reconcilerPeriod: 5m0s
  etcdV3CompactionPeriod: 10m0s
  healthChecks: Enabled
  logSeverityScreen: Info
status:
  environmentVars:
    DATASTORE_TYPE: kubernetes
    ENABLED_CONTROLLERS: node
  runningConfig:
    controllers:
      node:
        hostEndpoint:
          autoCreate: Disabled
        syncLabels: Disabled
    etcdV3CompactionPeriod: 10m0s
    healthChecks: Enabled
    logSeverityScreen: Info
```

Now apply the updated `kcc.yaml` manifest to update the cluster's kubecontrollersconfiguration:

```bash
calicoctl apply -f - < kcc.yaml
```

If the apply was successful, we should see host endpoints created for each of your cluster's nodes:

```bash
calicoctl get heps -owide
```

The output may look similar to this:

```
$ calicoctl get heps -owide
NAME                                                    NODE                                           INTERFACE   IPS                              PROFILES
ip-172-16-101-147.us-west-2.compute.internal-auto-hep   ip-172-16-101-147.us-west-2.compute.internal   *           172.16.101.147,192.168.228.128
ip-172-16-101-54.us-west-2.compute.internal-auto-hep    ip-172-16-101-54.us-west-2.compute.internal    *           172.16.101.54,192.168.107.128
ip-172-16-101-79.us-west-2.compute.internal-auto-hep    ip-172-16-101-79.us-west-2.compute.internal    *           172.16.101.79,192.168.91.64
ip-172-16-101-9.us-west-2.compute.internal-auto-hep     ip-172-16-101-9.us-west-2.compute.internal     *           172.16.101.9,192.168.71.192
ip-172-16-102-63.us-west-2.compute.internal-auto-hep    ip-172-16-102-63.us-west-2.compute.internal    *           172.16.102.63,192.168.108.192
```


### Above and beyond

- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) 
- [Host endpoints]({{ site.baseurl }}/reference/resources/hostendpoint)
