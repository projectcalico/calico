---
title: Running calico/node with an init system
canonical_url: '/getting-started/as-service'
---

This guide explains how to run `{{site.nodecontainer}}` with an init system like
systemd, inside either of the following container types:
- [Docker](#running-caliconode-in-a-docker-container)
- [rkt](#running-caliconode-in-a-rkt-container)

## Running {{site.nodecontainer}} in a Docker container
{% include content/docker-container-service.md %}

## Running {{site.nodecontainer}} in a rkt container
{% include content/rkt-container-service.md %}
