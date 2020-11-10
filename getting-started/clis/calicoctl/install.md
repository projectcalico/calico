---
title: Install calicoctl
description: Install the CLI for Calico.
canonical_url: '/getting-started/clis/calicoctl/install'
---

## About installing calicoctl

`calicoctl` allows you to create, read, update, and delete {{site.prodname}} objects
from the command line. {{site.prodname}} objects are stored in one of two datastores,
either etcd or Kubernetes. The choice of datastore is determined at the time Calico
is installed. Typically for Kubernetes installations the Kubernetes datastore is the
default.

You can run `calicoctl` on any host with network access to the
{{site.prodname}} datastore as either a binary or a container.
For step-by-step instructions, refer to the section that
corresponds to your desired deployment.

- [As a binary on a single host](#install-calicoctl-as-a-binary-on-a-single-host)

- [As a container on a single host](#install-calicoctl-as-a-container-on-a-single-host)

- [As a Kubernetes pod](#install-calicoctl-as-a-kubernetes-pod)

- [As a kubectl plugin](#install-calicoctl-as-a-kubectl-plugin-on-a-single-host)


{% include content/ctl-binary-install.md %}

{% include content/ctl-container-install.md %}

{% include content/ctl-kubectl-plugin-install.md cli="calicoctl" codepath="/calicoctl" %}
