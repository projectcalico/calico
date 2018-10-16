---
title: Requirements for Calico with Mesos
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/installation/prerequisites'
---

#### 1. etcd

{{site.prodname}} uses etcd as its datastore. Ensure you have an instance of etcd running,
and that it is accessible from all agents in your cluster.

In order to maximize availability, use [etcd's clustering guide](https://coreos.com/os/docs/latest/cluster-architectures.html)
and run etcd across the masters or other dedicated hosts.

For simplicity, you can quickly get started by running a single instance of etcd
using Docker. Run the following command on a master, ensure you've correctly set
or replaced `$ETCD_IP` and `$ETCD_PORT`:

```shell
docker run --detach \
	--net=host \
	--name etcd quay.io/coreos/etcd:v3.1.10 \
	etcd --advertise-client-urls "http://$ETCD_IP:$ETCD_PORT" \
	--listen-client-urls "http://$ETCD_IP:$ETCD_PORT,http://127.0.0.1:$ETCD_PORT"
```

Check that etcd is up and running:

```shell
$ curl http://$ETCD_IP:$ETCD_PORT/version
{"etcdserver":"2.2.5","etcdcluster":"2.2.0"}
```

#### 2. Docker Configured with Cluster Store

Under the covers, {{site.prodname}} networks Docker tasks for Mesos with its Docker CNM
plugin. Multihost Networking in Docker requires that each Agent's Docker daemon
be configured with a cluster store.

Though Docker's configured cluster-store does not have to be the same as
{{site.prodname}}'s, for simplicity, users can configure Docker to use the same datastore
as {{site.prodname}} by setting the following flag when starting the docker daemon:

```shell
--cluster-store=etcd://$ETCD_IP:$ETCD_PORT
```

> **Note**: Set or replace `$ETCD_IP` and `$ETCD_PORT` with the appropriate 
> address of your etcd cluster.
{: .alert .alert-info}


Restart Docker, then ensure it has picked up the changes:

```
$ docker info | grep -i "cluster store"
Cluster Store: etcd://10.0.0.1:2379
```

#### 3. Docker Containerizer Enabled for Mesos Agents

By default, Mesos only enables the "Mesos" Containerizer. Ensure
the Docker Containerizer is also enabled on each Agent.

> **Note**: You may skip this step if you do not plan on using the Docker 
> Containerizer.
{: .alert .alert-info}


If you are using the default `mesos-init-wrapper` from the official Mesos package,
you can enable the Docker Containerizer with the following command:

```shell
$ sh -c 'echo docker > /etc/mesos-slave/containerizers'
$ systemctl restart mesos-slave.service
```

#### 4. CNI Isolator Enabled for Mesos Agents

If you are planning to use {{site.prodname}} with the Unified containerizer,
[enable the CNI Isolator on each agent](http://mesos.apache.org/documentation/latest/cni/#usage)

> **Note**: You may skip this step if you do not plan on using the 
> Unified Containerizer.
{: .alert .alert-info}

When enabling CNI, you will have specified a `network_cni_config_dir`
and `network_cni_plugins_dir`. We'll refer to these going forward as
`$NETWORK_CNI_CONFIG_DIR` and `$NETWORK_CNI_PLUGINS_DIR`, respectively.

## Next Steps

Once you have met the prerequisites, view the [Integration Guide](./integration)

[slack]: https://slack.projectcalico.org
