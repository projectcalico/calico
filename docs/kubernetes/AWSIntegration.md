<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.11.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Integration with an AWS Kubernetes cluster
This guide will walk you through how to use Calico Networking with an existing AWS Kubernetes cluster.

## Requirements
* A working Kubernetes Deployment on AWS with a Kubernetes master and one or more nodes (minions)
    - We recommend the [Kubernetes instructions for AWS](https://github.com/kubernetes/kubernetes/blob/release-1.0/docs/getting-started-guides/aws.md). This guide was created with the `kube-up` script in mind.
* SSH access to your Kubernetes master and nodes
    - Unless otherwise specified, the `kube-up` script will create a `kube_aws_rsa` private key in the `~/.ssh` folder which you can use to access your AWS Instances.
    - SSH in with the following command `ssh -i </path/to/key> ubuntu@<PUBLIC_IP>`

## Installing Calico
On each of your AWS Instances, you will need to download and install the `calicoctl` binary
```
wget https://github.com/projectcalico/calico-docker/releases/download/v0.9.0/calicoctl
chmod +x calicoctl
sudo mv calicoctl /usr/bin/
```

## Configuring the Master
On your master, you will need to setup an etcd instance specifically for Calico. To do so, you will need to download our etcd manifest
```
wget https://raw.githubusercontent.com/projectcalico/calico-kubernetes/master/config/master/calico-etcd.manifest 
```

Replace all instances of `<PRIVATE_IPV4>` with your master's IP. Then, place the manifest file in the `/etc/kubernetes/manifests/` directory. 
```
sudo mv calico-etcd.manifest /etc/kubernetes/manifests/
```

After a short delay, the kubelet on your master will automatically create a container for the new etcd which can be accessed on port 6666 of your master.

Next, use `calicoctl` to spin up the `calico/node` container and install the Calico [network plugin](https://github.com/projectcalico/calico-kubernetes) for Kubernetes. 
```
sudo ETCD_AUTHORITY=<MASTER_IPV4>:6666 calicoctl node --kubernetes --kube-plugin-version=v0.4.0
```

Then you will need to set up an IP pool with IP-in-IP enabled. This is a [necessary step](../FAQ.md#can-i-run-calico-in-a-public-cloud-environment) in any public cloud environment.

```
sudo ETCD_AUTHORITY=<MASTER_IPV4>:6666 calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing
```

### Authentication for the API Server

In default configurations, the apiserver requires authentication to access its resources. The Calico plugin supports tokens from Kubernetes Service Accounts.

On a fresh cluster, there will be a single default service token for the cluster on your master. You can extract the token with the following command:

```
TOKEN=$(kubectl describe secret default-token | grep token: | cut -f 2)
```

For stronger security, you can create a new Service Account specifically for Calico, and use that account's token:

```
kubectl create -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico
EOF
TOKEN=$(kubectl describe secret calico-token | grep token: | cut -f 2)
```

Hold on to this token, as you will need it to configure your nodes.

## Configuring the Nodes
On each node, use `calicoctl` to spin up the `calico/node` container and install the Calico [network plugin](https://github.com/projectcalico/calico-kubernetes) for Kubernetes. 
```
sudo ETCD_AUTHORITY=<MASTER_IPV4>:6666 calicoctl node --kubernetes --kube-plugin-version=v0.4.0
```

To start using the Calico network plugin, we will need to modify the existing kubelet process on each of your nodes.

First, you will need to create a file, `/etc/network-environment`, with the following contents:
```
ETCD_AUTHORITY=<MASTER_IPV4>:6666
KUBE_API_ROOT=https://<MASTER_IPV4>:443/api/v1/
KUBE_AUTH_TOKEN=<TOKEN>
CALICO_IPAM=true
```

In your kubelet service systemd unit file (default: `/lib/systemd/system/kubelet.service`), add the following line to the `[Service]` section, just before the `ExecStart` line.
```
EnvironmentFile=/etc/network-environment
```
You will also need to append the `--network-plugin=calico` flag to the `ExecStart` command.

Restart the kubelet.
```
sudo systemctl daemon-reload
sudo systemctl restart kubelet
```

### Node connectivity workaround

As a temporary workaround to issue [projectcalico/calico-docker#426](https://github.com/projectcalico/calico-docker/issues/426), the following manual steps must be run on each node:

```
mkdir -p /etc/iproute2
echo '8    docker' >> /etc/iproute2/rt_tables
ip rule add from <Calico pool CIDR> table docker
ip route add <nodes subnet> table docker dev tunl0
```

Where `<Calico pool CIDR>` is the CIDR assigned to the Calico IP pool, in this example `192.168.0.0/16`, and `<nodes subnet>` is the network that the node interfaces are on (e.g. the eth0 subnet). Note that the `<nodes subnet>` and `<Calico pool CIDR>` may not overlap; the node IPs must be in a different CIDR than the container IP range.

## Now you are ready to begin using Calico Networking!

To test your Calico setup, you can create a simple pod manifest:
```
# busybox.yaml
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
  - image: busybox
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: busybox
  restartPolicy: Always
```

Create the pod with `kubectl create -f busybox.yaml`

And check its Calico endpoint with `ETCD_AUTHORITY=<MASTER_IPV4>:6666 calicoctl endpoint show --detailed`.  You should see that both an IP address and a profile have been assigned to the pod.

For more information on programming Calico Policy in Kubernetes, see our [Kubernetes Policy docs](KubernetesPolicy.md).
