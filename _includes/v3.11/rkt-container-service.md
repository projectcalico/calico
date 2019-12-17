Each {{site.prodname}}-rkt enabled node requires the `{{site.nodecontainer}}` container to be running.

The `{{site.nodecontainer}}` container can be run directly through rkt and needs to be run as
as a fly stage-1 container.

```shell
sudo rkt run --stage1-path=/usr/share/rkt/stage1-fly.aci \
  --set-env=ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> \
  --set-env=IP=autodetect \
  --insecure-options=image \
  --volume=birdctl,kind=host,source=/var/run/calico,readOnly=false \
  --mount=volume=birdctl,target=/var/run/calico \
  --volume=mods,kind=host,source=/lib/modules,readOnly=false  \
  --mount=volume=mods,target=/lib/modules \
  --volume=logs,kind=host,source=/var/log/calico,readOnly=false \
  --mount=volume=logs,target=/var/log/calico \
  --net=host \
  {{page.registry}}{{page.imageNames["calico/node"]}}:{{site.data.versions[page.version].first.title}} &
```

> **Note**: Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration. The `ETCD_ENDPOINTS`
> environment may contain a comma separated list of endpoints of your etcd cluster.
{: .alert .alert-info}

Check that it's running.

```shell
sudo rkt list
```

An example response follows.

```bash
UUID      APP	IMAGE NAME                  STATE   CREATED         STARTED         NETWORKS
b52bba11  node  {{page.registry}}{{page.imageNames["calico/node"]}}:{{site.data.versions[page.version].first.title}}  running 10 seconds ago  10 seconds ago
```
{: .no-select-button}
