---
title: Docker Cluster-Store
---

Docker multi-host networking requires a daemon configured with a cluster-store
so that docker daemon's across multiple hosts can keep track of configured networks.

Calico additionally needs a cluster store to track state.

Because of both requirements, we often suggest setting up an instance of etcd
and pointing both docker and calico at it.

After installing docker, set a `--cluster-store` to it.

In docker 1.10+, daemon settings can easily be set by editing / creating
`/etc/docker/daemon.json` as follows:

```
{
  "cluster-store": "etcd://<etcd-ip>:2379"
}
```

For earlier versions of docker, add `--cluster-store` to your `dockerd` params
or set `$DOCKER_CLUSTER_STORE` in your docker service environment.

Then reboot the docker daemon to pick up the new settings.
Check it has been configured correctly by searching for the setting
in `docker info` output:

```
$ docker info | grep -i cluster
Cluster Store: etcd://localhost:2379
```
