---
title: Network Architecture
---

The following overview is only valid for **container** deployments:

![network architecture](/images/container-networking.layout.png)

Each container is given a veth pair, with one end in the host namespace and the other
pushed into the container namespace.
Containers on the same host are still a layer-3 hop away from one another.
