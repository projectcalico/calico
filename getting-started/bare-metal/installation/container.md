---
title: Container install
canonical_url: '/getting-started/bare-metal/installation/container'
---

## Running under Docker
If you want to run `{{site.nodecontainer}}` under Docker, you can use `calicoctl node run` command. It automatically pre-initializes the etcd database (which the other installation methods do not). See the
[`calicoctl node run`]({{ site.url }}/reference/calicoctl/node/run)
guide for details. This container packages up the core {{site.prodname}} components to provide both {{site.prodname}}
networking and network policy.

```bash
ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> ./calicoctl node run --node-image={{page.registry}}{{page.imageNames["calico/node"]}}:{{site.data.versions[page.version].first.title}}
```
> **Note**: Add the `ETCD_ENDPOINTS` Env and replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration when etcd isn't running locally.
{: .alert .alert-info}


## Create a start-up script
Felix should be started at boot time by your init system and the init system must be configured to restart Felix if it stops. Felix relies on that behavior for certain configuration changes.
{% include content/docker-container-service.md %}
