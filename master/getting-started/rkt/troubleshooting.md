---
title: Troubleshooting Calico for rkt
---

This article contains rkt specific troubleshooting advice for Calico and 
frequently asked questions. 
See also the [main Calico troubleshooting](../../usage/troubleshooting) pages.

## Frequently Asked Questions

#### Why am I seeing Calico errors deleting a rkt container

There were known issues with earlier versions of rkt that prevent clean
tidyup of IP addresses when deleting a container.  The version of rkt used in
the tutorial is >1.20.0 which addresses this problem.

If you are seeing errors that only occur during container deletion, check your
rkt version.


