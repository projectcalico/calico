---
title: Troubleshooting Calico for Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/troubleshooting'
---

This article contains Kubernetes specific troubleshooting advice for Calico.  
See also the [main Calico troubleshooting](../../usage/troubleshooting) pages.

## Viewing Logs

The Calico CNI plugin emits logs to stderr, which are then logged out by the kubelet.  Where these logs end up
depend on how your kubelet is configured.  For deployments using `systemd`, you can do this via `journalctl`.

The log level can be configured via the CNI network configuration file, by changing the value of the key `log_level`.
By default, the plugin will only emit "info" level and higher.  Valid log levels are `debug`, `info`, `warn`, and
`error`.
