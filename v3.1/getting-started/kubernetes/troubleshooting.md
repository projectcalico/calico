---
title: Troubleshooting Calico for Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/troubleshooting'
---

This article contains Kubernetes specific troubleshooting advice for {{site.prodname}} and
frequently asked questions.
See also the [main troubleshooting](../../usage/troubleshooting) pages.

## Frequently Asked Questions

#### Why isn't {{site.prodname}} working on CoreOS Container Linux / hyperkube?

{{site.prodname}} hosted install places the necessary CNI binaries and config on each
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

Without the above volume mounts, the kubelet will not call the {{site.prodname}} CNI binaries, and so
{{site.prodname}} [workload endpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint) will
not be created, and {{site.prodname}} policy will not be enforced.

#### How do I view {{site.prodname}} CNI logs?

The {{site.prodname}} CNI plugin emits logs to stderr, which are then logged out by the kubelet.  Where these logs end up
depend on how your kubelet is configured.  For deployments using `systemd`, you can do this via `journalctl`.

The log level can be configured via the CNI network configuration file, by changing the value of the
key `log_level`.  See [the configuration guide]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration) for more information.

#### How do I configure the Pod IP range?

When using {{site.prodname}} IPAM, IP addresses are assigned from [IP Pools]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).

By default, all enabled IP Pool are used. However, you can specify which IP Pools to use for IP address management in the [CNI network config]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration#ipam),
or on a per-Pod basis using [Kubernetes annotations]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration#ipam-manipulation-with-kubernetes-annotations).

#### How do I assign a specific IP address to a pod?

For most use-cases it's not necessary to assign specific IP addresses to a Kubernetes Pod, and it's recommended to use Kubernetes Services instead.
However, if you do need to assign a particular address to a Pod, {{site.prodname}} provides two ways of doing this:

- You can request an IP that is available in {{site.prodname}} IPAM using the `cni.projectcalico.org/ipAddrs` annotation.
- You can request an IP using the `cni.projectcalico.org/ipAddrsNoIpam` annotation. Note that this annotation bypasses the configured IPAM plugin, and thus in most cases it is recommended to use the above annotation.

See the [Requesting a Specific IP address]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration#requesting-a-specific-ip-address) section in the CNI plugin reference documentation for more details.