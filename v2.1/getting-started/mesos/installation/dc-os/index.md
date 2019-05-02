---
title: Overview of Calico for DC/OS
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/installation/dc-os/index'
---

The following information details Calico's installation and runtime dependencies
in DC/OS, and looks at how to leverage Calico-DC/OS Framework to get up and running.

## Overview

Calico provides multi-host networking for DC/OS, giving each task its own IP
address and isolated networking namespace, with highly flexible policy configuration.

Calico has the following prerequisites in DC/OS:

- An available etcd store
- Docker configured with a cluster-store (if networking Docker Tasks)

Since many default DC/OS clusters do not meet these basic requirements, Calico
maintains a simple Universe package for DC/OS that can get Calico
installed and running in one-click. The package performs the following
steps on every agent in the cluster:

1. Run etcd (in proxy mode)
2. Configure docker with a cluster store
3. Install Calico CNI binaries and configs (for Unified Containerizer networking)
4. Run calico-libnetwork (for Docker Containerizer networking)
5. Run calico-node.

The framework is flexible, allowing users to enable, disable, or customize each step.
Below, we'll see what each step does, and how it can be modified.

The framework runs Calico (and its configuration) **within DC/OS.**
This means it registers as a Mesos Framework, and uses Mesos Resource offers
to run and configure the cluster with Calico. Alternative to this approach,
Calico can be manually installed directly onto Agents as a daemon service integrated
with the OS (using systemd) to ensure it is available when tasks are eventually
provisioned.

### Note on rp_filter in DC/OS

Containers with permission `CAP_NET_RAW` can spoof their IP address if the
`rp_filter` kernel setting is set to 'loose'. Typically, `rp_filter` is
configured to 'strict', preventing this behavior.
[DC/OS, however, arbitrarily sets `rp_filter` to 'loose' across all interfaces](https://dcosjira.atlassian.net/browse/DCOS-265), including the interfaces
Calico creates and uses. By default, [Felix notices this and refuses to launch](https://github.com/projectcalico/calicoctl/issues/1082#issue-168163079). In DC/OS, however, we configure Felix to ignore this by setting
[IgnoreLooseRPF](https://github.com/projectcalico/felix/blob/ab8799eaea66627e5db7717e62fca61fd9c08646/python/calico/felix/config.py#L198) to true. As a result, be cautious when granting containers `CAP_NET_RAW` since, if compromised, these
containers will be able to spoof their IP address, potentially allowing them to bypass firewall restrictions.

Next, we'll dive into each task the Framework performs.

### etcd

Calico uses etcd as its central database. There are two popular ways to run
etcd in DC/OS:

1. **Use the Universe etcd package**

    The Universe etcd package launches a Mesos Framework that uses Mesos resource
    offers to spawn a multi-node etcd cluster.
    The endpoint endpoint address can be resolved via a SRV lookup of
    `_etcd-server._tcp.etcd.mesos`.

    Calico doesn't support connections to etcd via
    SRV record, so the Calico-DC/OS Framework first runs its own instance
    of etcd in proxy mode on every agent, which it relies on to forward requests
    made to `localhost:2379` onwards to the actual etcd cluster.

2. **Manually running etcd**

    Running the etcd cluster manually across all masters can be considered more
    stable than the previous option, as the endpoint address is static.
    Users launching etcd in this way can skip running etcd in proxy mode, and
    can simply change `ETCD_ENDPOINTS` to point directly at their static
    etcd cluster.

### Docker Cluster Store

Calico networks Docker Containerizer tasks at the Docker-engine layer.
To do multi-host networking in Docker, each docker engine must be configured
to use the same cluster-store.

By default, the Calico-DC/OS Framework will parse the value set for `ETCD_ENDPOINTS`,
configure Docker to use it by adding it to `/etc/docker/daemon.json`,
and finally restart Docker.

Users can set `override-docker-cluster-store` to manually choose a different
cluster store (e.g. the existing zookeeper on master), or, if they are only
planning to use Calico for Unified Containerizer networking,
can disable modification of the docker daemon altogether.

### Calico CNI Installation

To perform networking on Unified Containerizer tasks, Calico's CNI binaries and
configuration file must be installed on every agent, and the slave process must
be restarted to pick up the change. The Framework then performs the following steps:

1. Download [`calico`]({{site.data.versions[page.version].first.components["calico/cni"].download_calico_url}}) to `/opt/mesosphere/active/cni/`
2. Download [`calico-ipam`]({{site.data.versions[page.version].first.components["calico/cni"].download_calico_ipam_url}}) to `/opt/mesosphere/active/cni/`
3. Create the following JSON file at `/opt/mesosphere/etc/dcos/network/cni/calico.cni`:

   ```json
   {
       "name": "calico",
       "type": "calico",
       "etcd_endpoints": "http://localhost:2379",
       "ipam": {
           "type": "calico-ipam"
       }
   }
   ```
   >Note: If not running etcd in proxy mode, be sure to change `etcd_endpoints`
   to your correct etcd endpoint address.

4. Restart the slave process with `systemctl restart dcos-mesos-slave`

### Run Calico Node

This task ensures the Calico's core process `calico/node` is running.

## Next Steps: Installing

For installation instructions, see [The Calico DC/OS Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/dc-os/framework)
