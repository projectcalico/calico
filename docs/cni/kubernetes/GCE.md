<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Deploying Calico and Kubernetes on GCE

These instructions allow you to set up a Kubernetes cluster with Calico networking on GCE using the [Calico CNI plugin][calico-cni]. This guide does not setup TLS between Kubernetes components or on the Kubernetes API.

## 1. Getting started with GCE
These instructions describe how to set up two CoreOS hosts on GCE.  For more general background, see
[the CoreOS on GCE documentation][coreos-gce].

### 1.1 Install the gcloud tool
If you already have the `gcloud` utility installed, and a GCE project configured, you may skip this step.

Download and install GCE, then restart your terminal:
```
curl https://sdk.cloud.google.com | bash
```
For more information, see Google's [gcloud install instructions][gcloud-instructions].

Log into your account:
```
gcloud auth login
```

In the GCE web console, create a project and enable the Compute Engine API.
Set the project as the default for gcloud:
```
gcloud config set project PROJECT_ID
```
And set a default zone
```
gcloud config set compute/zone us-central1-a
```

### 1.2 Setting up GCE networking
GCE blocks traffic between hosts by default; run the following command to allow Calico traffic to flow between
containers on different hosts:
```
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.240.0.0/16"
```
You can verify the rule with this command:
```
gcloud compute firewall-rules list
```

<!--- master only -->
### 1.3 Clone this project

    git clone https://github.com/projectcalico/calico-containers.git
<!--- else
### 1.3 Clone this project, and checkout the **release** release

    git clone https://github.com/projectcalico/calico-containers.git
    git checkout tags/**release**
<!--- end of master only -->

## 2. Deploy the VMs
Change into the directory for this guide.
```
cd calico-containers/docs/cni/kubernetes/
```

Deploy the Kubernetes master node using the following command:
```
gcloud compute instances create \
  kubernetes-master \
  --image-project coreos-cloud \
  --image coreos-stable-835-9-0-v20151208 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=cloud-config/master-config-ipip.yaml
```

Deploy at least one worker node using the following command:
```
gcloud compute instances create \
  kubernetes-node-1 \
  --image-project coreos-cloud \
  --image coreos-stable-835-9-0-v20151208 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=cloud-config/node-config.yaml
```

You should have SSH access to your machines using the following command:
```
gcloud compute ssh <INSTANCE NAME>
```

## 3. Using your cluster
### 3.1 Configuring kubectl
The following steps configure remote kubectl access to your cluster.

Download `kubectl`
```
wget https://storage.googleapis.com/kubernetes-release/release/v1.1.4/bin/linux/amd64/kubectl
chmod +x ./kubectl
```

The following command sets up SSH forwarding of port 8080 to your master node so that you can run `kubectl` commands on your local machine.
```
gcloud compute ssh kubernetes-master --quiet --ssh-flag="-nNT" --ssh-flag="-L 8080:localhost:8080" &
```

Verify that you can access the Kubernetes API.  The following command should return a list of Kubernetes nodes.
```
./kubectl get nodes
```

>If successful, the above command shoud output something like this:
```
NAME       LABELS                            STATUS AGE
10.240.0.3 kubernetes.io/hostname=10.240.0.3 Ready  14m
```

### 3.2 Deploying SkyDNS
You now have a basic Kubernetes cluster deployed using Calico networking.  Most Kubernetes deployments use SkyDNS for Kubernetes service discovery.  The following steps configure the SkyDNS service.

Deploy the SkyDNS application using the provided Kubernetes manifest.
```
./kubectl create -f manifests/skydns.yaml
```

Check that the DNS pod is running. It may take up to two minutes for the pod to start, after which the following command should show the `kube-dns-v9-xxxx` pod in `Running` state.
```
./kubectl get pods --namespace=kube-system
```
> Note: The kube-dns-v9 pod is deployed in the `kube-system` namespace.  As such, we we must include the `--namespace=kube-system` option when using kubectl.

>The output of the above command should resemble the following table.  Note the `Running` status:
```
NAMESPACE     NAME                READY     STATUS    RESTARTS   AGE
kube-system   kube-dns-v9-3o2rw   4/4       Running   0          2m
```

### 3.3 Deploying the guestbook application
You're now ready to deploy applications on your Cluster.  The following steps describe how to deploy the Kubernetes [guestbook application][guestbook].

Create the guestbook application pods and services using the provided manifest.
```
./kubectl create -f manifests/guestbook.yaml
```

Check that the redis-master, redis-slave, and frontend pods are running correctly.  After a few minutes, the following command should show all pods in `Running` state.
```
./kubectl get pods
```
> Note: The guestbook demo relies on a number of docker images which may take up to 5 minutes to download.

The guestbook application uses a NodePort service to expose the frontend outside of the cluster.  You'll need to allow this port outside of the cluster with a firewall-rule.
```
gcloud compute firewall-rules create allow-kubectl --allow tcp:30001
```
> In a production deployment, it is recommended to use a GCE [LoadBalancer][loadbalancers] service which automatically deploys a GCE load-balancer and configures a public IP address for the service.

You can find your master's public IP with the following command:
```
gcloud compute instances describe kubernetes-master | grep natIP
```

You should now be able to access the guestbook application from a browser at `http://<MASTER_IP>:30001`.

### 3.4 Next Steps

Now that you have a verified working Kubernetes cluster with Calico, you can continue [deploying applications on Kubernetes][examples].

You can also take a look at how you can use Calico [network policy on Kubernetes](NetworkPolicy.md).


[calico-cni]: https://github.com/projectcalico/calico-cni
[coreos-gce]: https://coreos.com/docs/running-coreos/cloud-providers/google-compute-engine/
[gcloud-instructions]: https://cloud.google.com/compute/docs/gcloud-compute/
[guestbook]: https://github.com/kubernetes/kubernetes/blob/master/examples/guestbook/README.md
[loadbalancers]: http://kubernetes.io/v1.0/docs/user-guide/services.html#type-loadbalancer
[examples]: https://github.com/kubernetes/kubernetes/tree/master/examples


[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/GCE.md?pixel)](https://github.com/igrigorik/ga-beacon)
