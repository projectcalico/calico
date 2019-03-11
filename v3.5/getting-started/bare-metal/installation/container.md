---
title: Container install
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/bare-metal/installation/container'
---

If you want to run under Docker, you can use `calicoctl node run --node-image={{page.registry}}{{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}` 
to start the `{{site.nodecontainer}}` container image. This container packages 
up the core {{site.prodname}} components to provide both {{site.prodname}} 
networking and network policy. Running the container automatically pre-initializes 
the etcd database (which the other installations methods do not). See the
[`calicoctl node run`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/run)
guide for details.
