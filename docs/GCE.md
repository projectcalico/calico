# Running calico-docker on GCE
Calico is designed to provide high performance massively scalable virtual networking for private data centers. But you can also run Calico within a public cloud such as Google Compute Engine (GCE). The following instructions show how to network containers using Calico routing and the Calico security model on GCE.

## Getting started
These instructions describe how to set up two CoreOS hosts on GCE.  For more general background, see [the CoreOS on GCE documentation](https://coreos.com/docs/running-coreos/cloud-providers/google-compute-engine/).

Download and install GCE, then restart your terminal: 
```
curl https://sdk.cloud.google.com | bash
```
For more information, see Google's [gcloud install instructions](https://cloud.google.com/compute/docs/gcloud-compute/).

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
## Setting up GCE networking
GCE blocks traffic between hosts by default; run the following command to allow Calico traffic to flow between containers on different hosts:
```
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.240.0.0/16"
```
You can verify the rule with this command:
```
gcloud compute firewall-rules list
```

## Spinning up the VMs
etcd needs to be running on the Calico hosts.  The easiest way to bootstrap etcd is with a discovery URL.  We'll use a cluster size of 1 for this demo.  For an actual deployment, choose an etcd cluster size that is equal to or less than the number of Calico nodes (an odd number in the range 3-9 works well).  For more details on etcd clusters, see the [CoreOS Cluster Discovery Documentation](https://coreos.com/docs/cluster-management/setup/cluster-discovery/).
Use `curl` to get a fresh discovery URL:
```
curl https://discovery.etcd.io/new?size=1
```
You need to grab a fresh URL each time you bootstrap a cluster.

Create a file `cloud-config.yaml` with the following contents; **replace `<discovery URL>` with the URL retrieved above**:
```
#cloud-config
coreos:
  update:
    reboot-strategy: off
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
Note: we disable CoreOS updates for this demo to avoid interrupting the instructions.

Then create the cluster with the following command, where calico-1 and calico-2 are the names for the two nodes to create:
```
gcloud compute instances create \
  calico-1 calico-2 \
  --image-project coreos-cloud \
  --image coreos-alpha-709-0-0-v20150611 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=cloud-config.yaml
```

## Installing calicoctl on each node
SSH into each node using gcloud (names are calico-1 and calico-2):
```
gcloud compute ssh <instance name>
```

On each node, run these commands to set up Calico:
```
# Download calicoctl and make it executable:
wget https://github.com/Metaswitch/calico-docker/releases/download/v0.4.7/calicoctl
chmod +x ./calicoctl

# Grab our private IP from the metadata service:
export metadata_url="http://metadata.google.internal/computeMetadata/v1/"
export private_ip=$(curl "$metadata_url/instance/network-interfaces/0/ip" -H "Metadata-Flavor: Google")

# Start the calico node service:
sudo ./calicoctl node --ip=$private_ip
```
Then, on any one of the hosts, create the IP pool Calico will use for your containers:
```
./calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing
```

## Create a couple of containers and check connectivity
On the first host, run:
```
export DOCKER_HOST=localhost:2377
docker run -e CALICO_IP=192.168.1.1 -e CALICO_PROFILE=test --name container-1 -tid busybox
```
On the second host, run:
```
export DOCKER_HOST=localhost:2377
docker run -e CALICO_IP=192.168.1.2 -e CALICO_PROFILE=test --name container-2 -tid busybox
```
Then, run the following on the second host to see the that two containers are able to ping each other:
```
docker exec container-2 ping -c 4 192.168.1.1
```
## Next steps
Now, you may wish to follow the [getting started instructions for creating workloads](https://github.com/Metaswitch/calico-docker/blob/master/docs/GettingStarted.md#creating-networked-endpoints).

## (Optional) Enabling traffic from the internet to containers
Services running on a Calico host's containers in GCE can be exposed to the internet.  Since the containers have IP addresses in the private IP range, traffic to the container must be routed using a NAT and an appropriate Calico security profile.

Let's create a new security profile and look at the default rules.
```
./calicoctl profile add WEB
./calicoctl profile WEB rule show
```
You should see the following output.
```
Inbound rules:
   1 allow from tag WEB 
Outbound rules:
   1 allow
```

Let's modify this profile to make it more appropriate for a public webserver by allowing TCP traffic on ports 80 and 443:
```
./calicoctl profile WEB rule add inbound allow tcp to ports 80,443
```

Now, we can list the rules again and see the changes:
```
./calicoctl profile WEB rule show
```
should print
```
Inbound rules:
   1 allow from tag WEB 
   2 allow tcp to ports 80,443
Outbound rules:
   1 allow
```

After creating the WEB profile, run the following command on one of your GCE Calico hosts to create a Calico container under this profile, running a basic NGINX http server:
```
docker run -e CALICO_IP=192.168.2.1 -e CALICO_PROFILE=WEB --name mynginx1 -P -d nginx
```

On the same host, create a NAT that forwards port 80 traffic to the new container.
```
sudo iptables -A PREROUTING -t nat -i ens4v1 -p tcp --dport 80 -j DNAT  --to 192.168.2.1:80
```

Lastly, the GCE's firewall rules must be updated for any ports you want to expose. Run this gcloud command to allow incoming traffic to port 80:
```
gcloud compute firewall-rules create allow-http \
  --description "Incoming http allowed." --allow tcp:80
```

You should now be able to access the NGINX http server using the public ip address of your GCE host on port 80 by visiting http://<host public ip>:80 or running:
```
curl http://<host public ip>:80
```
