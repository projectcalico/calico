---
title: Adding Calico to an Existing Kubernetes Cluster
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/'
---


This document describes the steps required to install Calico on an existing
Kubernetes cluster.

This document explains an installation of Calico that includes Kubernetes NetworkPolicy support.  Older versions
of Calico include annotation-based policy support.  While this is no longer recommended, the documentation
for annotation-based policy can still be found in [an older release](https://github.com/projectcalico/calico-containers/blob/v0.20.0/docs/cni/kubernetes/AnnotationPolicy.md)

## Requirements
- An existing Kubernetes cluster running Kubernetes >= v1.1.  To use NetworkPolicy, Kubernetes >= v1.3.0 is required.
- An `etcd` cluster accessible by all nodes in the Kubernetes cluster
  - Calico can share the etcd cluster used by Kubernetes, but it's recommended
  that a separate cluster is set up.

## About the Calico Components

There are three components of a Calico / Kubernetes integration.

- The Calico per-node docker container, [calico/node](https://hub.docker.com/r/calico/node/)
- The [calico-cni](https://github.com/projectcalico/calico-cni) network plugin binaries.
  - This is the combination of two binary executables and a configuration file.
- When using Kubernetes NetworkPolicy, the Calico policy controller is also required.

The `calico/node` docker container must be run on the Kubernetes master and each
Kubernetes node in your cluster, as it contains the BGP agent necessary for Calico routing to occur.

The `calico-cni` plugin integrates directly with the Kubernetes `kubelet` process
on each node to discover which pods have been created, and adds them to Calico networking.

The `calico/kube-policy-controller` container runs as a pod on top of Kubernetes and implements
the NetworkPolicy API.  This component requires Kubernetes >= 1.3.0.

## Installing Calico Components
There are currently two methods of installing the Calico components.

1. [Manual installation](#manual-installation)
2. [Kubernetes-hosted installation](#kubernetes-hosted-installation) (supported in Kubernetes >= v1.4.0)

Manual Installation
-------------------

### 1. Run `calico/node` and configure the node.
The Kubernetes master and each Kubernetes node require the `calico/node` container.
Each node must also be recorded in the Calico datastore.

This can be done using the `calicoctl` utility.

```
# Download and install `calicoctl`
wget https://github.com/projectcalico/calico-containers/releases/download/v0.22.0/calicoctl
sudo chmod +x calicoctl

# Run the calico/node container
sudo ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> ./calicoctl node
```

See the [`calicoctl node` documentation]({{site.baseurl}}/{{page.version}}/reference/calicoctl/node)
for more information.

#### Example systemd unit file (calico-node.service)

If you're using systemd as your init system then the following service file can be used.

```bash
[Unit]
Description=calicoctl node
After=docker.service
Requires=docker.service

[Service]
User=root
Environment=ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT>
PermissionsStartOnly=true
ExecStartPre=/usr/bin/wget -N -P /opt/bin https://github.com/projectcalico/calico-containers/releases/download/v0.22.0/calicoctl
ExecStartPre=/usr/bin/chmod +x /opt/bin/calicoctl
ExecStart=/opt/bin/calicoctl node --detach=false
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
> Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.

### 2. Download and configure the Calico CNI plugins
The Kubernetes `kubelet` calls out to the `calico` and `calico-ipam` plugins.

Download the binaries and make sure they're executable

```bash
wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.4.2/calico
wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.4.2/calico-ipam
chmod +x /opt/cni/bin/calico /opt/cni/bin/calico-ipam
```

It's recommended that this is done as part of job that manages the `kubelet` process (see below)

The Calico CNI plugins require a standard CNI config file.  The `policy` section is only required when
deploying the `calico/kube-policy-controller` for NetworkPolicy.

```bash
mkdir -p /etc/cni/net.d
cat >/etc/cni/net.d/10-calico.conf <<EOF
{
    "name": "calico-k8s-network",
    "type": "calico",
    "etcd_endpoints": "http://<ETCD_IP>:<ETCD_PORT>",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam"
    },
    "policy": {
        "type": "k8s"
    }
}
EOF
```

Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.

For more information on configuring the Calico CNI plugins, see the [configuration guide](https://github.com/projectcalico/calico-cni/blob/v1.4.2/configuration.md)

### 3. Deploy the Calico network policy controller
The `calico/kube-policy-controller` implements the Kubernetes NetworkPolicy API by watching the Kubernetes API for Pod, Namespace, and
NetworkPolicy events and configuring Calico in response.  It runs as a single pod managed by a ReplicaSet.

To install the policy controller:

- Download the [policy controller manifest](policy-controller.yaml).
- Modify `<ETCD_ENDPOINTS>` to point to your etcd cluster.
- Install it using `kubectl`.

```shell
$ kubectl create -f policy-controller.yaml
```

After a few moments, you should see the policy controller enter `Running` state:

```shell
$ kubectl get pods --namespace=kube-system
NAME                                     READY     STATUS    RESTARTS   AGE
calico-policy-controller                 2/2       Running   0          1m
```

Kubernetes Hosted Installation
------------------------------
This method of installation uses Kubernetes to install Calico.  This method is only supported
in Kubernetes >= v1.4.0, and is currently considered experimental.

Since this method uses Kubernetes to install Calico, you must first deploy a standard Kubernetes cluster
with CNI networking enabled. There are a number of ways to do this and we won't cover them here, but make sure that it meets the
[desired configuration for installing Calico](#configuring-kubernetes).

Download the Calico self-hosted manifest, [`calico.yaml`](hosted/calico.yaml).

Edit the provided ConfigMap at the top of the file in order to configure Calico
for your deployment.  Then install the manifests using Kubernetes.

```
kubectl create -f calico.yaml
```

You should see the Calico services start in the `kube-system` Namespace.

For more information, see the Calico [self-hosted documentation](hosted).

## Configuring Kubernetes

### Configuring the Kubelet

The Kubelet needs to be configured to use the Calico network plugin when starting pods.

The `kubelet` can be configured to use Calico by starting it with the following options

- `--network-plugin=cni`
- `--network-plugin-dir=/etc/cni/net.d`

See the [`kubelet` documentation](https://kubernetes.io/docs/reference/generated/kubelet/)
for more details.

#### Example systemd unit file (kubelet.service)
```
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=calico-node.service
Requires=calico-node.service

[Service]
ExecStartPre=/usr/bin/wget -N -P /opt/bin https://storage.googleapis.com/kubernetes-release/release/v1.4.0/bin/linux/amd64/kubelet
ExecStartPre=/usr/bin/chmod +x /opt/bin/kubelet
ExecStartPre=/usr/bin/wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.4.2/calico
ExecStartPre=/usr/bin/chmod +x /opt/cni/bin/calico
ExecStartPre=/usr/bin/wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.4.2/calico-ipam
ExecStartPre=/usr/bin/chmod +x /opt/cni/bin/calico-ipam
ExecStart=/opt/bin/kubelet \
--address=0.0.0.0 \
--allow-privileged=true \
--cluster-dns=10.100.0.10 \
--cluster-domain=cluster.local \
--config=/etc/kubernetes/manifests \
--hostname-override=$private_ipv4 \
--api-servers=http://<API SERVER IP>:8080 \
--network-plugin-dir=/etc/cni/net.d \
--network-plugin=cni \
--logtostderr=true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

This unit file ensures that the `kubelet` binary and the `calico` plugin are present.

### Configuring the Kube-Proxy
In order to use Calico policy with Kubernetes, the `kube-proxy` component must
be configured to leave the source address of service bound traffic intact.
This feature is first officially supported in Kubernetes v1.1.0 and is the default mode starting
in Kubernetes v1.2.0.

We highly recommend using the latest stable Kubernetes release, but if you're using an older release
there are two ways to enable this behavior.

- Option 1: Start the `kube-proxy` with the `--proxy-mode=iptables` option.
- Option 2: Annotate the Kubernetes Node API object with `net.experimental.kubernetes.io/proxy-mode` set to `iptables`.

See the [kube-proxy documentation](http://kubernetes.io/docs/admin/kube-proxy/)
for more details.
