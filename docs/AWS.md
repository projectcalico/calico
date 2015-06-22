# Running calico-docker on AWS
Calico is designed to provide high performance massively scalable virtual networking for private data centers. But you can also run Calico within a public cloud such as Amazon Web Services (AWS).  The following instructions show how to network containers using Calico routing and the Calico security model on AWS.

## Getting started
These instructions describe how to set up two CoreOS hosts on AWS.  For more general background, see [the CoreOS on AWS documentation](https://coreos.com/docs/running-coreos/cloud-providers/ec2/).

Download and install AWS Command Line Interface: 
```
curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
unzip awscli-bundle.zip
sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
```
For more information, see Amazon's [Installing the AWS Command Line Interface](http://docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os).

Run the AWS configure command, which will prompt you to set your User keys.
```
aws configure
>  AWS Access Key ID: <User Access Key>
>  AWS Secret Access Key: <User Secret Access Key>
>  Default region name: us-west-2
>  Default output format: <json, text, or table>
```
Your AWS user needs to have the policy AmazonEC2FullAccess or be in a group with this policy in order to run the ec2 commands.  This can be set in the Services>IAM>Users User configuration page of the web console.
For more information on configuration and keys, see Amazon's [Configuring the AWS Command Line Interface](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html).

## Setting up AWS networking
Before you can use Calico to network your containers, you first need to configure AWS to allow your hosts to talk to each other.

Create a Key Pair to use for ssh access to the instances. The following command will generate a key for you.
```
aws ec2 create-key-pair --key-name mykey --output text
```

Copy the output into a new file called mykey.pem.  The file should include ```-----BEGIN RSA PRIVATE KEY-----```, ```-----END RSA PRIVATE KEY-----```, and everything in between.  Then, set appropriate permissions for your key file.
```
chmod 400 mykey.pem
```

A Security Group is required on the instances to control allowed traffic.  Create a security group that allows all traffic between instances within the group but only SSH access from the internet.
```
# Create Security Group 
aws ec2 create-security-group \
  --group-name MySG \
  --description MySecurityGroup

# Allow SSH traffic to hosts in the security group 
aws ec2 authorize-security-group-ingress \
  --group-name MySG \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Allow hosts in the security group to communicate with each other
aws ec2 authorize-security-group-ingress \
  --group-name MySG \
  --protocol all \
  --port all \
  --source-group MySG
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

Next, you will create the 2 Calico Docker hosts:
```
aws ec2 run-instances \
  --count 2 \
  --image-id ami-29734819 \
  --instance-type t1.micro \
  --key-name mykey \
  --security-groups MySG \
  --user-data file://cloud-config.yaml
```
The "ami-########" represents the CoreOS alpha image type.
Note: it may take a couple of minutes for AWS to boot the machines after creating them.

## Installing calicoctl on each node
Get the public IP addresses of the new instances from the AWS Web Console or by running:
```
aws ec2 describe-instances --filter "Name=key-name,Values=mykey" | grep PublicIpAddress
```

Run the following commands to SSH into each node and set up Calico:
```
# SSH into a node with the mykey.pem and username core
ssh -i mykey.pem core@<instance IP>

# Download calicoctl and make it executable:
wget http://projectcalico.org/latest/calicoctl
chmod +x ./calicoctl

# Grab our private IP from the metadata service:
export metadata_url="http://169.254.169.254/latest/meta-data"
export private_ip=$(curl "$metadata_url/local-ipv4")

# Start the calico node service:
sudo ./calicoctl node --ip=$private_ip
```
Then on either of the hosts, create the IP pool Calico will use for your containers:
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
Services running on a Calico host's containers in AWS can be exposed to the internet.  Since the containers have IP addresses in the private IP range, traffic to the container must be routed using a NAT and an appropriate Calico security profile.

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

After creating the WEB profile, run the following command on one of your AWS Calico hosts to create a Calico container under this profile, running a basic NGINX http server:
```
docker run -e CALICO_IP=192.168.2.1 -e CALICO_PROFILE=WEB --name mynginx -P -d nginx
```

On the same host, create a NAT that forwards port 80 traffic to the new container.
```
sudo iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT --to 192.168.2.1:80
```

Lastly, the AWS host's security group must be updated for any ports you want to expose.  Run this command from your aws CLI machine to allow incoming traffic to port 80:
```
aws ec2 authorize-security-group-ingress \
  --group-name MySG \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0
```

You should now be able to access the NGINX http server using the public ip address of your AWS host on port 80 by visiting http://`<host public ip>`:80 or running:
```
curl http://<host public ip>:80
```
