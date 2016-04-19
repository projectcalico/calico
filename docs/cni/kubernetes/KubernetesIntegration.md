<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Add Calico to an Existing Kubernetes Cluster

This document describes the steps required to install Calico on an existing
Kubernetes cluster.

## Requirements
- An existing Kubernetes cluster running Kubernetes >= v1.1
- An `etcd` cluster accessible by all nodes in the Kubernetes cluster
  - Calico can share the etcd cluster used by Kubernetes, but it's recommended
  that a separate cluster is set up.

## About the Calico Components

There are two components of a Calico / Kubernetes integration.
- The Calico per-node docker container, [`calico/node`](https://hub.docker.com/r/calico/node/)
- The [calico-cni](https://github.com/projectcalico/calico-cni) network plugin.
 - This is the combination of a binary executable and a configuration file.

The `calico/node` docker container must be run on the Kubernetes master and each
Kubernetes node in your cluster, as it contains the BGP agent necessary for Calico routing to occur.

The `calico-cni` plugin integrates directly with the Kubernetes `kubelet` process
on each node to discover which pods have been created, and adds them to Calico networking.

## Installing Calico Components
### 1. Run `calico/node` and configure the node.
The Kubernetes master and each Kubernetes node require the `calico/node` container.
Each node must also be recorded in the Calico datastore. Running the container and
storing the required information can be achieved using the `calicoctl` utility.

```
# Download and install `calicoctl`
wget http://www.projectcalico.org/builds/calicoctl
sudo chmod +x calicoctl

# Run the calico/node container
sudo ETCD_AUTHORITY=<ETCD_IP>:<ETCD_PORT> ./calicoctl node
```

See the [`calicoctl node` documentation](../../calicoctl/node.md#calicoctl-node)
for more information.

#### Example systemd unit file (calico-node.service)
If you're using systemd as your init system then the following service file can be used.
```
[Unit]
Description=calicoctl node
After=docker.service
Requires=docker.service

[Service]
User=root
Environment=ETCD_AUTHORITY=<ETCD_IP>:<ETCD_PORT>
PermissionsStartOnly=true
ExecStartPre=/usr/bin/wget -N -P /opt/bin http://www.projectcalico.org/builds/calicoctl
ExecStartPre=/usr/bin/chmod +x /opt/bin/calicoctl
ExecStart=/opt/bin/calicoctl node --detach=false
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
> Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.

### 2. Download and configure the `calico-cni` plugin
The Kubernetes `kubelet` calls out to the `calico-cni` plugin.

Download it and make sure it's executable
```
wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.0.0/calico
chmod +x /opt/cni/bin/calico
```
It's recommended that this is done as part of job that manages the `kubelet` process (see below)

The `calico-cni` plugin requires a standard CNI config file.

```
mkdir -p /etc/cni/net.d
$ cat >/etc/cni/net.d/10-calico.conf <<EOF
{
    "name": "calico-k8s-network",
    "type": "calico",
    "etcd_authority": "<ETCD_IP>:<ETCD_PORT>",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF
```
> Replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration.

## Configuring Kubernetes
### Configuring the Kubelet
The Kubelet needs to be configured to use the Calico network plugin when starting pods.

The `kubelet` can be configured to use Calico by starting it with the following options
- `--network-plugin=cni`
- `--network-plugin-dir=/etc/cni/net.d`

See the [`kubelet` documentation](http://kubernetes.io/docs/admin/kubelet/)
for more details.

#### Example systemd unit file (kubelet.service)
```
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=calico-node.service
Requires=calico-node.service

[Service]
ExecStartPre=/usr/bin/wget -N -P /opt/bin https://storage.googleapis.com/kubernetes-release/release/v1.1.4/bin/linux/amd64/kubelet
ExecStartPre=/usr/bin/chmod +x /opt/bin/kubelet
ExecStartPre=/usr/bin/wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.0.0/calico
ExecStartPre=/usr/bin/chmod +x /opt/cni/bin/calico
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
This feature is first officially supported in Kubernetes v1.1.0.

We highly recommend using the latest stable Kubernetes release, but if you're using an older release
there are two ways to enable this behavior.
- Option 1: Start the `kube-proxy` with the `--proxy-mode=iptables` option.
- Option 2: Annotate the Kubernetes Node API object with
`net.experimental.kubernetes.io/proxy-mode` set to `iptables`.

See the [kube-proxy documentation](http://kubernetes.io/docs/admin/kube-proxy/)
for more details.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/KubernetesIntegration.md?pixel)](https://github.com/igrigorik/ga-beacon)
