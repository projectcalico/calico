# Running calico-docker on AWS
Calico runs on the Amazon Web Services (AWS), but there are a few tweaks required to the main Getting Started instructions.  The following instructions show the full power of the Calico routing and security model on AWS (and allow AWS to be used for testing).

## Getting started
These instructions describe how to set up three CoreOS hosts on AWS.  For more general background, see [the CoreOS on AWS documentation](https://coreos.com/docs/running-coreos/cloud-providers/ec2/).

Download and install AWS Command Line Interface: 
```
curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
unzip awscli-bundle.zip
sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
```
For more information, see Amazon's [Installing the AWS Command Line Interface](http://docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os).

Configure the AWS CLI with your User keys:
```
aws configure
  AWS Access Key ID: <User Access Key>
  AWS Secret Access Key: <User Secret Access Key>
  Default region name: us-west-2
  Default output format: <json, text, or table>
```
For more information on configuration and keys, see Amazon's [Configuring the AWS Command Line Interface](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html).

## Setting up AWS networking
The AWS machines will require a login by default.  Create a Key Pair instead to use when SSHing into the instances.  
```
# Create Key Pair and save locally as calicokey.pem
aws ec2 create-key-pair --key-name calicokey --output text > calicokey.pem

chmod 400 calicokey.pem
```

A Security Group is required on the instances to control allowed traffic.  Create a Security Group and allow any machine to SSH, but restrict all other traffic that is not within the Security Group.
```
# Create Security Group to allow certain incoming traffic to the Calico nodes
aws ec2 create-security-group --group-name CalicoSG --description CalicoSecurityGroup
aws ec2 authorize-security-group-ingress --group-name CalicoSG --protocol tcp --port 22 --source-group 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-name CalicoSG --protocol all --port all --source-group CalicoSG
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
Note: we disable automated reboots for this demo to avoid interrupting the instructions.

Then create the cluster with the following command:
```
aws ec2 run-instances \
  --count 3 \
  --image-id ami-29734819 \
  --instance-type t1.micro \
  --key-name calicokey \
  --security-groups CalicoSG \
  --user-data file://cloud-config.yaml
```

## Installing calicoctl on each node
##### NEED TO SPECIFY HOW TO GET IP
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
Then, on any one of the hosts, run this command to create an IP pool with IP-in-IP and NAT enabled:
```
./calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing
```
IP-in-IP alows Calico to route traffic between containers.  NAT allows the containers to make outgoing connections to the internet.

## Create a couple of containers and check connectivity
On one host, run:
```
export DOCKER_HOST=localhost:2377
docker run -e CALICO_IP=192.168.1.1 -e CALICO_PROFILE=test --name container-1 -tid busybox
```
On another host, run:
```
export DOCKER_HOST=localhost:2377
docker run -e CALICO_IP=192.168.1.2 -e CALICO_PROFILE=test --name container-2 -tid busybox
```
Then, the two containers should be able to ping each other:
```
docker exec container-2 ping -c 4 192.168.1.1
```
## Next steps
Now, you may wish to follow the [getting started instructions for creating workloads](https://github.com/Metaswitch/calico-docker/blob/master/docs/GettingStarted.md#creating-networked-endpoints).

## (Optional) Enabling traffic from the internet to containers
Services running on containers in GCE can be exposed to the internet using Calico using port mapping iptables NAT rules and an appropriate Calico security profile.  For example, you have a container that you've assigned the CALICO_IP of 192.168.7.4 to, and you have NGINX running on port 80 inside the container. If you want to expose this on port 8000, then you should follow the instructions at https://github.com/Metaswitch/calico-docker/blob/master/docs/AdvancedNetworkPolicy.md to expose port 80 on the container and then run the following command to add the port mapping:

```
iptables -A PREROUTING -t nat -i ens4v1 -p tcp --dport 8000 -j DNAT  --to 172.168.7.4:80
```