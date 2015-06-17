# Running calico-docker on GCE
Calico runs on the Google Compute Engine (GCE), but there are a few tweaks required to the main Getting Started instructions.  The following instructions show the full power of the Calico routing and security model on GCE (and allow GCE to be used for testing).

## Getting started
These instructions assume a total of three GCE hosts running CoreOS. Documentation on running CoreOS on GCE is [here](https://coreos.com/docs/running-coreos/cloud-providers/google-compute-engine/)

Download and install GCE and login to your account. Full documentation on how to install gcloud are given [here](https://cloud.google.com/compute/docs/gcloud-compute/).
```
curl https://sdk.cloud.google.com | bash
gcloud auth login
```
Also, create a project through the GCE console and set that as the default for gcloud.
```
gcloud config set project PROJECT
```
And set a default zone
```
gcloud config set compute/zone us-central1-a
```
## Setting up GCE networking
GCE blocks traffic between hosts by default, which prevents Calico traffic from flowing.  Run the following command to allow traffic to flow between containers:
```
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.240.0.0/16"
```
You can verify the rule with this command:
```
gcloud compute firewall-rules list
```

## Spinning up the VMs
etcd needs to be running on the Calico hosts.  The easiest way to bootstrap etcd is with a discovery URL.  Choose an etcd cluster size that is equal to or less than the number of Calico nodes (an odd number in the range 3-9 works well).  We'll use 3 for the size of the etcd cluster and the Calico nodes in the instructions below.  Use `curl` to get a fresh discovery URL (replace size=3 with your cluster size if desired):
```
curl https://discovery.etcd.io/new?size=3
```
You need to grab a fresh URL each time you bootstrap a cluster.

Create a file `cloud-config.yaml` with the following contents; **replace `<discovery URL>` with the URL retrieved above**:
```
#cloud-config
coreos:
  update:
    reboot-strategy: etcd-lock
  etcd2:
    name: $private_ipv4
    discovery: <discovery URL>
    advertise-client-urls: http://$private_ipv4:2379
    initial-advertise-peer-urls: http://$private_ipv4:2380
    listen-client-urls: http://0.0.0.0:2379,http://0.0.0.0:4001
    listen-peer-urls: http://$private_ipv4:2380,http://$private_ipv4:7001
  units:
    - name: etcd2.service
      command: start

```
Note: we disable automated reboots for this demo to avoid interrupting the instructions.

Then create the cluster with the following command ("calico-1 calico-2 calico-3" is the list of nodes to create):
```
gcloud compute instances create \
  calico-1 calico-2 calico-3 \
  --image https://www.googleapis.com/compute/v1/projects/coreos-cloud/global/images/coreos-alpha-709-0-0-v20150611 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=cloud-config.yaml
```

## Installing calicoctl on each node
On each node, run these commands to set up Calico:
```
# Download calicoctl and make it executable:
wget https://github.com/Metaswitch/calico-docker/releases/download/v0.4.5/calicoctl
chmod +x ./calicoctl

# Grab our private IP from the metadata service:
export metadata_url="http://metadata.google.internal/computeMetadata/v1/"
export private_ip=$(curl "$metadata_url/instance/network-interfaces/0/ip" -H "Metadata-Flavor: Google")

# Start the calico node service:
sudo ./calicoctl node --ip=$private_ip

# Work-around a [BIRD routing issue](http://marc.info/?l=bird-users&m=139809577125938&w=2)
# This tells BIRD that it's directly connected to the upstream GCE router.
sudo ip addr add $private_ip peer 10.240.0.1 dev ens4v1
```
Then, on any one of the hosts, run this command to enable IP-in-IP on the default IP pool:
```
./calicoctl pool add 192.168.0.0/16 --ipip
```

## Create a couple of containers and check connectivity
On one host, run:
```
export DOCKER_HOST=localhost:2377
docker run -e CALICO_IP=192.168.1.1 --name container-1 -tid busybox
./calicoctl profile add TEST
./calicoctl profile TEST member add container-1
```
On another host, run:
```
export DOCKER_HOST=localhost:2377
docker run -e CALICO_IP=192.168.1.2 --name container-2 -tid busybox
./calicoctl profile TEST member add container-2
```
Then, the two containers should be able to ping each other:
```
docker exec container-2 ping -c 4 192.168.1.1
```
## Running containers
Now, follow the standard [getting started instructions for creating workloads](https://github.com/Metaswitch/calico-docker/blob/master/docs/GettingStarted.md#creating-networked-endpoints).

Note that etcd should already be running on the master, core1 and core2 nodes, with data stored on the master node, and core1 and core2 run etcd in proxy mode, so no clustering is required.  Check this by running ```etcdctl ls /``` on each node.  If it is not running, then restart it by running ```docker start etcd```.

## (Optional) Enabling traffic from containers to the internet
The test endpoints will be unable to access the internet - that is because the internal range we are using is not routable. Hence to get external connectivity, SNAT is called for using the following `iptables` rule (on both hosts).

```
iptables -t nat -A POSTROUTING -s 192.168.0.0/16 ! -d 192.168.0.0/16 -j MASQUERADE
```

## (Optional) Enabling traffic from the internet to containers
Services running on containers in GCE can be exposed to the internet using Calico using port mapping iptables NAT rules and an appropriate Calico security profile.  For example, you have a container that you've assigned the CALICO_IP of 192.168.7.4 to, and you have NGINX running on port 80 inside the container. If you want to expose this on port 8000, then you should follow the instructions at https://github.com/Metaswitch/calico-docker/blob/master/docs/AdvancedNetworkPolicy.md to expose port 80 on the container and then run the following command to add the port mapping:

```
iptables -A PREROUTING -t nat -i ens4v1 -p tcp --dport 8000 -j DNAT  --to 172.168.7.4:80
```
