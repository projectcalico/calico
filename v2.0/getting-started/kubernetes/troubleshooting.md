---
title: Troubleshooting Calico for Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.4/getting-started/kubernetes/troubleshooting'
---

This article contains Kubernetes specific troubleshooting advice for Calico and 
frequently asked questions. 
See also the [main Calico troubleshooting](../../usage/troubleshooting) pages.

## Frequently Asked Questions

#### Why isn't Calico working on CoreOS Container Linux / hyperkube?

Calico hosted install places the necessary CNI binaries and config on each
Kubernetes node in a directory on the host as specified in the manifest.  By 
default it places binaries in /opt/cni/bin and config /etc/cni/net.d.

When running the kubelet as a container using hyperkube as is common on CoreOS Container Linux,
you need to make sure that the containerized kubelet can see the CNI network
plugins and config that have been installed by mounting them into the kubelet container.

For example add the following arguments to the kubelet-wrapper service: 

```
--volume /etc/cni/net.d:/etc/cni/net.d \
--volume /opt/cni/bin:/opt/cni/bin \
```

Without the above volume mounts, the kubelet will not call the Calico CNI binaries, and so
Calico [workload endpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint) will 
not be created, and Calico policy will not be enforced.

#### How do I view Calico CNI logs?

The Calico CNI plugin emits logs to stderr, which are then logged out by the kubelet.  Where these logs end up
depend on how your kubelet is configured.  For deployments using `systemd`, you can do this via `journalctl`.

The log level can be configured via the CNI network configuration file, by changing the value of the 
key `log_level`.  See [the configuration guide]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration) for more information.
