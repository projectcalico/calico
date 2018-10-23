---
title: Integration Guide
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/integration'
---


This document explains the components necessary to install {{site.prodname}} on
Kubernetes for integrating with custom configuration management.

The manifests we provide in [Installing {{site.prodname}} for policy and networking](calico),
[Installing {{site.prodname}} for policy and flannel for networking](flannel), and
[Installing {{site.prodname}} for policy](other) will perform these steps automatically
for you and are *strongly* recommended for most users. These instructions should only
be followed by users who have a specific need that cannot be met by using manifests.

* TOC
{:toc}

## Before you begin

Ensure that your cluster meets the {{site.prodname}} [system requirements](../requirements).


## About the {{site.prodname}} components

There are three components of a {{site.prodname}} / Kubernetes integration.

- The {{site.prodname}} per-node Docker container `{{site.nodecontainer}}`.
- The [cni-plugin](https://github.com/projectcalico/cni-plugin) network plugin binaries. This is the combination of two binary executables and a configuration file.
- The {{site.prodname}} Kubernetes controllers, which run in a single-instance pod.  These components monitor the Kubernetes API to keep {{site.prodname}} in sync.

The `{{site.nodecontainer}}` docker container must be run on the Kubernetes master and each
Kubernetes node in your cluster.  It contains the BGP agent necessary for {{site.prodname}} routing to occur,
and the Felix agent which programs network policy rules.

The `cni-plugin` plugin integrates directly with the Kubernetes `kubelet` process
on each node to discover which pods have been created, and adds them to {{site.prodname}} networking.

The `calico/kube-controllers` container runs as a pod on top of Kubernetes and keeps {{site.prodname}}
in-sync with Kubernetes.

## Installing {{site.nodecontainer}}

### Run {{site.nodecontainer}} and configure the node.

The Kubernetes master and each Kubernetes node require the `{{site.nodecontainer}}` container.
Each node must also be recorded in the {{site.prodname}} datastore.

The `{{site.nodecontainer}}` container can be run directly through Docker, or it can be
done using the `calicoctl` utility.

```
# Download and install calicoctl
wget {{site.data.versions[page.version].first.components.calicoctl.download_url}}
sudo chmod +x calicoctl

# Run the {{site.nodecontainer}} container
sudo ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> ./calicoctl node run --node-image={{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}
```

See the [`calicoctl node run` documentation]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/)
for more information.

### Example systemd unit file ({{site.noderunning}}.service)

If you're using systemd as your init system then the following service file can be used.

```bash
[Unit]
Description={{site.noderunning}}
After=docker.service
Requires=docker.service

[Service]
User=root
Environment=ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT>
PermissionsStartOnly=true
ExecStart=/usr/bin/docker run --net=host --privileged --name={{site.noderunning}} \
  -e ETCD_ENDPOINTS=${ETCD_ENDPOINTS} \
  -e NODENAME=${HOSTNAME} \
  -e IP= \
  -e IP6= \
  -e AS= \
  -e NO_DEFAULT_POOLS= \
  -e CALICO_NETWORKING_BACKEND=bird \
  -e FELIX_DEFAULTENDPOINTTOHOSTACTION=ACCEPT \
  -v /lib/modules:/lib/modules \
  -v /run/docker/plugins:/run/docker/plugins \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/run/calico:/var/run/calico \
  -v /var/lib/calico:/var/lib/calico \
  -v /var/log/calico:/var/log/calico \
  {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}
ExecStop=/usr/bin/docker rm -f {{site.noderunning}}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.

> **Note**: To ensure reasonable dataplane programming latency on a system under load,
> `{{site.nodecontainer}}` requires a CPU reservation of at least 0.25 cores with additional
> benefits up to 0.5 cores.
{: .alert .alert-info}


## Installing the {{site.prodname}} CNI plugins

The Kubernetes `kubelet` should be configured to use the `calico` and `calico-ipam` plugins.

### Install the {{site.prodname}} plugins

Download the binaries and make sure they're executable.

```bash
wget -N -P /opt/cni/bin {{site.data.versions[page.version].first.components["calico/cni"].download_calico_url}}
wget -N -P /opt/cni/bin {{site.data.versions[page.version].first.components["calico/cni"].download_calico_ipam_url}}
chmod +x /opt/cni/bin/calico /opt/cni/bin/calico-ipam
```

The {{site.prodname}} CNI plugins require a standard CNI config file.  The `policy` section is only required when
running the `calico/kube-controllers` container .

```bash
mkdir -p /etc/cni/net.d
cat >/etc/cni/net.d/10-calico.conf <<EOF
{
    "name": "calico-k8s-network",
    "cniVersion": "0.6.0",
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
Replace `</PATH/TO/KUBECONFIG>` with your kubeconfig file. See [Kubernetes kubeconfig](http://kubernetes.io/docs/user-guide/kubeconfig-file/) for more information about kubeconfig.

For more information on configuring the {{site.prodname}} CNI plugins, see the [configuration guide]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration)

### Install standard CNI loopback plugin

In addition to the CNI plugin specified by the CNI config file, Kubernetes requires the standard CNI loopback plugin.

Download the file `loopback` and copy it to the CNI binary directory.

```bash
wget https://github.com/containernetworking/cni/releases/download/v0.6.0/cni-v0.6.0.tgz
tar -zxvf cni-v0.6.0.tgz
sudo cp loopback /opt/cni/bin/
```

## Installing the {{site.prodname}} Kubernetes controllers

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

When installing {{site.prodname}} on Kubernetes clusters with RBAC enabled, it is necessary to provide {{site.prodname}} access to some Kubernetes
APIs.  To do this, subjects and roles must be configured in the Kubernetes API and {{site.prodname}} components must be provided with the appropriate
tokens or certificates to present which identify it as the configured API user.

Detailed instructions for configuring Kubernetes RBAC are outside the scope of this document.  For more information,
please see the [upstream Kubernetes documentation](https://kubernetes.io/docs/admin/authorization/rbac/) on the topic.

The following YAML file defines the necessary API permissions required by {{site.prodname}}
when using the etcd datastore.

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/rbac.yaml
```

[Click here to view the above yaml directly.](rbac.yaml)
