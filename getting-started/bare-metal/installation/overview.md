---
title: Installing Calico on host endpoints
description: Choose a method to install Calico on hosts
canonical_url: '/getting-started/bare-metal/installation/index'
---

You will need to install calicoctl and configure it to connect to your etcd datastore.

-  [Install calicoctl as a binary](../../calicoctl/install#installing-calicoctl-as-a-binary-on-a-single-host).

-  [Configure calicoctl to connect to etcd](../../calicoctl/configure/etcd).

Then you can use any of the following methods to install and run Felix, on each bare metal
host where you want {{site.prodname}} host protection.

- [Binary from package manager](binary-mgr): On Red Hat Enterprise Linux (RHEL), Ubuntu,
  and CentOS hosts, use the package manager to install and run Felix as a binary.

- [Container](container): On hosts equipped with Docker, you can run `{{site.nodecontainer}}`,
  which includes Felix and all of its dependencies.

- [Binary without package manager](binary): If you prefer not to run Docker on all of your
  hosts, you can use Docker in one place to extract the `{{site.noderunning}}` binary from a
  `{{site.nodecontainer}}` container image, then copy that binary to each of your hosts and
  run it as `{{site.noderunning}} -felix`.
