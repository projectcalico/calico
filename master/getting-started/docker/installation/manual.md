---
title: Installing Calico for Docker
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/installation/manual'
---

{{site.prodname}} runs as a Docker container on each host. The `calicoctl` command line tool can be used to launch the `{{site.nodecontainer}}` container.

## Before you begin 

- Ensure that you have satisfied these
[requirements]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/requirements).

- [Install `calicoctl` as a binary](/{{page.version}}/usage/calicoctl/install#installing-calicoctl-as-a-binary-on-a-single-host).

- [Configure `calicoctl` to connect to your datastore](/{{page.version}}/usage/calicoctl/configure/).


## Using calicoctl


1. Launch `{{site.nodecontainer}}`:

   ```
   sudo calicoctl node run --node-image={{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}
   ```

1. Check that `{{site.noderunning}}` is now running:

   ```
   vagrant@calico-01:~$ docker ps
   CONTAINER ID        IMAGE                        COMMAND             CREATED             STATUS              PORTS               NAMES
   408bd2b9ba53        {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}   "start_runit"       About an hour ago   Up About an hour                        {{site.noderunning}}
   ```

1. Furthermore, check that the `{{site.nodecontainer}}` container is functioning properly
with the following command:

   ```
   sudo calicoctl node status
   ```

## Using "docker run"

For more control over the {{site.prodname}} startup process, and to simplify binding
startup to an init system, `calicoctl` can print the command it uses
to launch `{{site.nodecontainer}}`.

To print the command `calicoctl node run` uses to launch {{site.prodname}} on this host,
run the command with the `--init-system` and `--dry-run` flags:

```
$ calicoctl node run --init-system --dryrun --node-image={{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}
Use the following command to start the {{site.nodecontainer}} container:

docker run --net=host --privileged --name={{site.noderunning}} --rm -e ETCD_AUTHORITY=127.0.0.1:2379 -e ETCD_SCHEME=http -e ETCD_ENDPOINTS= -e NODENAME=calico -e CALICO_NETWORKING_BACKEND=bird -e NO_DEFAULT_POOLS= -e CALICO_LIBNETWORK_ENABLED=true -e CALICO_LIBNETWORK_IFPREFIX=cali -v /var/run/calico:/var/run/calico -v /lib/modules:/lib/modules -v /var/log/calico:/var/log/calico -v /run/docker/plugins:/run/docker/plugins -v /var/run/docker.sock:/var/run/docker.sock {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}

Use the following command to stop the {{site.nodecontainer}} container:

docker stop {{site.noderunning}}

```

Pair the printed command with your favorite init system to ensure {{site.prodname}} is
always running on each host.

See [additional information on binding to an init system
]({{site.baseurl}}/{{page.version}}/usage/configuration/as-service).

## Next Steps

With `{{site.noderunning}}` running, you are ready to start using {{site.prodname}} by following
[Security using {{site.prodname}} Profiles]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-calico-profiles).
