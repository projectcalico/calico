---
title: Installing Calico for Docker
---

{{site.prodname}} runs as a Docker container on each host. The `calicoctl` command line tool can be used to launch the `calico/node` container.

> **Important**: Before following the steps here ensure that you have satisfied these
[requirements]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/requirements).
{: .alert .alert-danger}


## Using calicoctl

1. Download the calicoctl binary:

   ```
   sudo wget -O /usr/local/bin/calicoctl {{site.data.versions[page.version].first.components.calicoctl.download_url}}
   sudo chmod +x /usr/local/bin/calicoctl
   ```

2. Configure access to your etcd cluster, [calicoctl - etcd datastore](/{{page.version}}/reference/calicoctl/setup/etcdv3).
3. Launch `calico/node`:

   ```
   sudo calicoctl node run --node-image={{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}
   ```

Check that `calico/node` is now running:

```
vagrant@calico-01:~$ docker ps
CONTAINER ID        IMAGE                        COMMAND             CREATED             STATUS              PORTS               NAMES
408bd2b9ba53        {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}   "start_runit"       About an hour ago   Up About an hour                        calico-node
```

Furthermore, check that the `calico/node` container is functioning properly
with the following command:

```
sudo calicoctl node status
```

## Using "docker run"

For more control over the {{site.prodname}} startup process, and to simplify binding
startup to an init system, `calicoctl` can print the command it uses
to launch `calico/node`.

To print the command `calicoctl node run` uses to launch {{site.prodname}} on this host,
run the command with the `--init-system` and `--dry-run` flags:

```
$ calicoctl node run --init-system --dryrun --node-image={{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}
Use the following command to start the calico/node container:

docker run --net=host --privileged --name=calico-node --rm -e ETCD_AUTHORITY=127.0.0.1:2379 -e ETCD_SCHEME=http -e ETCD_ENDPOINTS= -e NODENAME=calico -e CALICO_NETWORKING_BACKEND=bird -e NO_DEFAULT_POOLS= -e CALICO_LIBNETWORK_ENABLED=true -e CALICO_LIBNETWORK_IFPREFIX=cali -v /var/run/calico:/var/run/calico -v /lib/modules:/lib/modules -v /var/log/calico:/var/log/calico -v /run/docker/plugins:/run/docker/plugins -v /var/run/docker.sock:/var/run/docker.sock {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}

Use the following command to stop the calico/node container:

docker stop calico-node

```

Pair the printed command with your favorite init system to ensure {{site.prodname}} is
always running on each host.

See [additional information on binding to an init system
]({{site.baseurl}}/{{page.version}}/usage/configuration/as-service).

## Next Steps

With `calico/node` running, you are ready to start using {{site.prodname}} by following
[Security using {{site.prodname}} Profiles]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-calico-profiles).
