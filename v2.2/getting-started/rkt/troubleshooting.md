---
title: Troubleshooting Calico for rkt
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/rkt/troubleshooting'
---

This article contains rkt specific troubleshooting advice for Calico and
frequently asked questions.
See also the [main Calico troubleshooting](../../usage/troubleshooting) pages.

## Frequently Asked Questions

#### Why am I seeing Calico errors deleting a rkt container

There were known issues with earlier versions of rkt that prevent clean
tidyup of IP addresses when deleting a container.

If you are seeing errors that only occur during container deletion, check your
rkt version.  We recommend a version of rkt 1.20.0 and higher.
