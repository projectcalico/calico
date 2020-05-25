---
title: Install calicoctl
description: Install the CLI for Calico.
canonical_url: '/getting-started/clis/calicoctl/install'
---

## About installing calicoctl

`calicoctl` allows you to create, read, update, and delete {{site.prodname}} objects
from the command line.

You can run `calicoctl` on any host with network access to the
{{site.prodname}} datastore as either a binary or a container.
For step-by-step instructions, refer to the section that
corresponds to your desired deployment.

- [As a binary on a single host](#installing-calicoctl-as-a-binary-on-a-single-host)

- [As a container on a single host](#installing-calicoctl-as-a-container-on-a-single-host)

- [As a Kubernetes pod](#installing-calicoctl-as-a-kubernetes-pod)


## Installing calicoctl as a binary on a single host

{% include content/ctl-binary-install.md %}

**Next step**:

[Configure `calicoctl` to connect to your datastore](configure).

{% include content/ctl-container-install.md %}
