---
title: Network Architecture
---

The following overview is only valid for **container** deployments:

![network architecture](/images/container-networking.layout.png)

- container gets single interface
- host is its L3 nexthop
  - containers on same host are still L3 hop away
