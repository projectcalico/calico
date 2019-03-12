---
title: Integration Guide
canonical_url: 'https://docs.projectcalico.org/v3.6/getting-started/kubernetes/installation/integration'
---


This document explains the components necessary to install Calico on Kubernetes for integrating
with custom configuration management.

The [self-hosted installation method](hosted/) will perform these steps automatically for you and is *strongly* recommended
for most users.  These instructions should only be followed by users who have a specific need that cannot be met by the self-hosted
installation method.

* TOC
{:toc}

## Requirements

- An existing Kubernetes cluster running Kubernetes >= v1.1.  To use network policy, Kubernetes >= v1.3.0 is required.
- An `etcd` cluster accessible by all nodes in the Kubernetes cluster
  - Calico can share the etcd cluster used by Kubernetes, but in some cases it's recommended that a separate cluster is set up.
    A number of production users do share the etcd cluster between the two, but separating them gives better performance at high scale.

> **Note**: Calico can also be installed
> [without a dependency on etcd](hosted/kubernetes-datastore/),
> but that is not covered in this document.
{: .alert .alert-info}


## About the Calico Components

There are three components of a Calico / Kubernetes integration.

- The Calico per-node docker container, [calico/node](https://quay.io/repository/calico/node?tab=tags)
- The [cni-plugin](https://github.com/projectcalico/cni-plugin) network plugin binaries.
  - This is the combination of two binary executables and a configuration file.
- When using Kubernetes network policy, you must also deploy the Calico Kubernetes controllers.

The `calico/node` docker container must be run on the Kubernetes master and each
Kubernetes node in your cluster.  It contains the BGP agent necessary for Calico routing to occur,
and the Felix agent which programs network policy rules.

The `cni-plugin` plugin integrates directly with the Kubernetes `kubelet` process
on each node to discover which pods have been created, and adds them to Calico networking.

The `calico/kube-controllers` container runs as a pod on top of Kubernetes and keeps {{site.prodname}}
in-sync with Kubernetes.

## Installing `calico/node`

### Run `calico/node` and configure the node.

The Kubernetes master and each Kubernetes node require the `calico/node` container.
Each node must also be recorded in the Calico datastore.

The calico/node container can be run directly through docker, or it can be
done using the `calicoctl` utility.

```
# Download and install `calicoctl`
wget {{site.data.versions[page.version].first.components.calicoctl.download_url}}
sudo chmod +x calicoctl

# Run the calico/node container
sudo ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> ./calicoctl node run --node-image=quay.io/calico/node:{{site.data.versions[page.version].first.title}}
```

See the [`calicoctl node run` documentation]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/)
for more information.

### Example systemd unit file (calico-node.service)

If you're using systemd as your init system then the following service file can be used.

```bash
[Unit]
Description=calico node
After=docker.service
Requires=docker.service

[Service]
User=root
Environment=ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT>
PermissionsStartOnly=true
ExecStart=/usr/bin/docker run --net=host --privileged --name=calico-node \
  -e ETCD_ENDPOINTS=${ETCD_ENDPOINTS} \
  -e NODENAME=${HOSTNAME} \
  -e IP= \
  -e NO_DEFAULT_POOLS= \
  -e AS= \
  -e CALICO_LIBNETWORK_ENABLED=true \
  -e IP6= \
  -e CALICO_NETWORKING_BACKEND=bird \
  -e FELIX_DEFAULTENDPOINTTOHOSTACTION=ACCEPT \
  -v /var/run/calico:/var/run/calico \
  -v /lib/modules:/lib/modules \
  -v /run/docker/plugins:/run/docker/plugins \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/log/calico:/var/log/calico \
  quay.io/calico/node:{{site.data.versions[page.version].first.title}}
ExecStop=/usr/bin/docker rm -f calico-node
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.

> **Note**: To ensure reasonable dataplane programming latency on a system under load,
> `calico/node` requires a CPU reservation of at least 0.25 cores with additional
> benefits up to 0.5 cores.
{: .alert .alert-info}


## Installing the Calico CNI plugins

The Kubernetes `kubelet` should be configured to use the `calico` and `calico-ipam` plugins.

### Install the Calico plugins

Download the binaries and make sure they're executable

```bash
wget -N -P /opt/cni/bin {{site.data.versions[page.version].first.components["calico/cni"].download_calico_url}}
wget -N -P /opt/cni/bin {{site.data.versions[page.version].first.components["calico/cni"].download_calico_ipam_url}}
chmod +x /opt/cni/bin/calico /opt/cni/bin/calico-ipam
```

The Calico CNI plugins require a standard CNI config file.  The `policy` section is only required when
running the `calico/kube-controllers` container .

```bash
mkdir -p /etc/cni/net.d
cat >/etc/cni/net.d/10-calico.conf <<EOF
{
    "name": "calico-k8s-network",
    "cniVersion": "0.1.0",
    "type": "calico",
    "etcd_endpoints": "http://<ETCD_IP>:<ETCD_PORT>",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam"
    },
    "policy": {
        "type": "k8s"
    },
    "kubernetes": {
        "kubeconfig": "</PATH/TO/KUBECONFIG>"
    }
}
EOF
```

Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.
Replace `</PATH/TO/KUBECONFIG>` with your kubeconfig file. See [kubernetes kubeconfig](http://kubernetes.io/docs/user-guide/kubeconfig-file/) for more information about kubeconfig.

For more information on configuring the Calico CNI plugins, see the [configuration guide]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration)

### Install standard CNI lo plugin

In addition to the CNI plugin specified by the CNI config file, Kubernetes requires the standard CNI loopback plugin.

Download the file `loopback` and cp it to CNI binary dir.

```bash
wget https://github.com/containernetworking/cni/releases/download/v0.3.0/cni-v0.3.0.tgz
tar -zxvf cni-v0.3.0.tgz
sudo cp loopback /opt/cni/bin/
```

## Installing the Calico Kubernetes controllers

The `calico/kube-controllers` container keeps {{site.prodname}}'s datastore in-sync with Kubernetes.
It runs as a single pod managed by a Deployment.

> **Note**: The `calico/kube-controllers` container is required even if policy is not in use.
{: .alert .alert-info}

To install the controllers:

- Download the [Calico Kubernetes controllers manifest](calico-kube-controllers.yaml).
- Modify `<ETCD_ENDPOINTS>` to point to your etcd cluster.
- Install it using `kubectl`.

```shell
$ kubectl create -f calico-kube-controllers.yaml
```

After a few moments, you should see the controllers enter `Running` state:

```shell
$ kubectl get pods --namespace=kube-system
NAME                                     READY     STATUS    RESTARTS   AGE
calico-kube-controllers                  1/1       Running   0          1m
```

For more information on how to configure the controllers,
see the [configuration guide]({{site.baseur}}/{{page.version}}/reference/kube-controllers/configuration).

## Role-based access control (RBAC)

When installing Calico on Kubernetes clusters with RBAC enabled, it is necessary to provide Calico access to some Kubernetes
APIs.  To do this, subjects and roles must be configured in the Kubernetes API and Calico components must be provided with the appropriate
tokens or certificates to presnt which identify it as the configured API user.

Detailed instructions for configuring Kubernetes RBAC are outside the scope of this document.  For more information,
please see the [upstream Kubernetes documentation](https://kubernetes.io/docs/admin/authorization/rbac/) on the topic.

The following yaml file defines the necessary API permissions required by Calico
when using the etcd datastore.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/rbac.yaml
```

[Click here to view the above yaml directly.](rbac.yaml)

## Configuring Kubernetes

### Configuring the Kubelet

The Kubelet needs to be configured to use the Calico network plugin when starting pods.

The `kubelet` can be configured to use Calico by starting it with the following options

- `--network-plugin=cni`
- `--cni-conf-dir=/etc/cni/net.d`
- `--cni-bin-dir=/opt/cni/bin`

For Kubernetes versions prior to v1.4.0, the `cni-conf-dir` and `cni-bin-dir` options are
not supported.  Use `--network-plugin-dir=/etc/cni/net.d` instead.

### Configuring the kube-proxy

In order to use Calico policy with Kubernetes, the `kube-proxy` component must
be configured to leave the source address of service bound traffic intact.
This feature is first officially supported in Kubernetes v1.1.0 and is the default mode starting
in Kubernetes v1.2.0.

We highly recommend using the latest stable Kubernetes release, but if you're using an older release
there are two ways to enable this behavior.

- Option 1: Start the `kube-proxy` with the `--proxy-mode=iptables` option.
- Option 2: Annotate the Kubernetes Node API object with `net.experimental.kubernetes.io/proxy-mode` set to `iptables`.
