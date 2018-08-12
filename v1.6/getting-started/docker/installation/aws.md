---
title: # Running the Calico tutorials on AWS
sitemap: false 
---

Calico is designed to provide high performance massively scalable virtual
networking for private data centers. But you can also run Calico within a
public cloud such as Amazon Web Services (AWS).  The following instructions
show how to network containers using Calico routing and the Calico security
model on AWS.

## 1. Getting started with AWS
These instructions describe how to set up two CoreOS hosts on AWS.  For more general background, see
[the CoreOS on AWS EC2 documentation](https://coreos.com/os/docs/latest/booting-on-ec2.html).

Download and install AWS Command Line Interface:

```shell
curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
unzip awscli-bundle.zip
sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
```

For more information, see Amazon's [Installing the AWS Command Line Interface][install-aws-cli].

Run the AWS configure command, which will prompt you to set your User keys.

```shell
aws configure
#>  AWS Access Key ID: <User Access Key>
#>  AWS Secret Access Key: <User Secret Access Key>
#>  Default region name: <Region Name, eg. us-west-2>
#>  Default output format: <json, text, or table>
```

Note: Your `<Region Name>` can be found on the front page of the EC2 dashboard under the "Service Health" text.

Your AWS user needs to have the policy AmazonEC2FullAccess or be in a group with this policy in order to run the ec2
commands.  This can be set in the Services>IAM>Users User configuration page of the web console.
For more information on configuration and keys, see Amazon's
[Configuring the AWS Command Line Interface][configure-aws-cli].

## 2. Setting up AWS networking
Before you can use Calico to network your containers, you first need to configure AWS to allow your hosts to talk to
each other.

A Virtual Private Cloud (VPC) is required on AWS in order to configure Calico networking on EC2. Your AWS account should have a default VPC that instances
automatically attach to when they are created.

To check if you have a default VPC, run the following command, then save VPC ID as an environment variable to use later.

```shell
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true"

# Save VpcId from output as environment variable (without quotes)
VPC_ID=<VpcId>
```

If you do not have a default VPC or you would like to create a VPC specifically for your hosts that have Calico-networked containers, follow
the instructions below.

### 2.1 Creating an AWS VPC
> NOTE: This step is only required if you do not have a default VPC or if you would like
> to create a new VPC explicitly for your Calico hosts.  Skip to Configuring Key Pair and
> Security Group if this does not apply to you.

For SSH purposes on AWS, you will need to configure a Subnet, Internet Gateway, and Route Table on the VPC.

Create the VPC to use as the network for your hosts.  Set a `VPC_ID` environment variable to
make things a bit easier, replacing `<VpcId>` with the `VpcId` value returned from the command:

```shell
aws ec2 create-vpc --cidr-block 172.35.0.0/24
VPC_ID=<VpcId>
```

Create a subnet for your hosts, then save a `SUBNET_ID` environment variable, replacing `<SubnetId>` with the `SubnetId` output value of the command.

```shell
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 172.35.0.0/24
SUBNET_ID=<SubnetId>
```

Modify the Subnet to auto-assign public ip addresses:

```shell
aws ec2 modify-subnet-attribute --subnet-id $SUBNET_ID --map-public-ip-on-launch
```

Create an Internet Gateway.  Save the `InternetGatewayId` value as an environment variable.

```shell
aws ec2 create-internet-gateway
GATEWAY_ID=<InternetGatewayId>
```

Attach the gateway to the VPC.

```shell
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway $GATEWAY_ID
```

Create a Route Table on the VPC. Save the `RouteTableId` as an environment variable.

```shell
aws ec2 create-route-table --vpc-id $VPC_ID
ROUTE_TABLE_ID=<RouteTableId>
```

Associate the route table with the Subnet and add a route to the Internet.

```shell
aws ec2 associate-route-table --subnet-id $SUBNET_ID --route-table-id $ROUTE_TABLE_ID
aws ec2 create-route --route-table-id $ROUTE_TABLE_ID --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $GATEWAY_ID
```

### 2.2 Configuring Key Pair and Security Group
Create a Key Pair to use for ssh access to the instances. The following command will generate a key for you.

```shell
aws ec2 create-key-pair --key-name mykey --output text
```

Copy the output into a new file called mykey.pem.  The file should include ```-----BEGIN RSA PRIVATE KEY-----```,
```-----END RSA PRIVATE KEY-----```, and everything in between.  Then, set appropriate permissions for your key file.

```shell
chmod 400 mykey.pem
```

A Security Group is required on the instances to control allowed traffic.  Save the `GroupId` output from the first command as an environment variable.

```shell
# Create Security Group
aws ec2 create-security-group --group-name MySG \
  --description MySecurityGroup --vpc-id $VPC_ID

# Save environment variable of GroupId
SECURITY_GROUP_ID=<GroupId>
```

Allow SSH from the internet and allow all traffic between instances within the group.

```shell
# Allow SSH access
aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Allow all traffic within the VPC
aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID \
  --source-group $SECURITY_GROUP_ID  --protocol all --port all
```

## 3. Spinning up the VMs
Create the two Calico Docker hosts by passing in a `cloud-config` file.

A different file is used for the two servers.

- For the first server, use [`user-data-first`]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/cloud-config/user-data-first)
- For the second server, use the [`user-data-others`]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/cloud-config/user-data-others)

Copy these files onto your machine.

Before running the commands, note the following:
-  The `ami-########` represents the CoreOS alpha HVM image type for the `us-west-2` region
(version 976.0.0 as of the writing of this document). The alpha version is used because it
supports Docker 1.10. If you are using a region other than `us-west-2`, replace the
image name with the correct CoreOS alpha HVM image from the [CoreOS image
list](https://coreos.com/os/docs/latest/booting-on-ec2.html) for your zone.
Use `aws ec2 describe-availability-zones` to display your region if you do not remember.
-  It may take a couple of minutes for AWS to boot the machines after creating them.

For the first server run:

```shell
aws ec2 run-instances \
  --image-id ami-2b7d914b \
  --instance-type t2.micro \
  --key-name mykey \
  --security-group-ids $SECURITY_GROUP_ID \
  --user-data file://<PATH_TO_CLOUD_CONFIG>/user-data-first
#  --subnet $SUBNET_ID
#  Include the subnet param above if using a non-default VPC

# Save the InstanceId to an environment variable
INSTANCE_ID_1=<InstanceId>
```

replacing `<PATH_TO_CLOUD_CONFIG>` with the appropriate directory containing the cloud config.

Find the PrivateIpAddress value of the first server by checking the output of this command.
Open your `user-data-others` file and replace the instances of `172.17.8.101` with this private IP address.

After making this change, for the second server run:

```shell
aws ec2 run-instances \
  --image-id ami-99bfada9 \
  --instance-type t2.micro \
  --key-name mykey \
  --security-group-ids $SECURITY_GROUP_ID \
  --user-data file://<PATH_TO_CLOUD_CONFIG>/user-data-others
#  --subnet $SUBNET_ID
#  Include the subnet param above if using a non-default VPC

# Save the InstanceId to an environment variable
INSTANCE_ID_2=<InstanceId>
```

Finally, disable `Source/Dest. Check` to allow containers to talk between hosts.  You can disable this with the CLI, or right click the instance in the EC2 console, and `Change Source/Dest. Check` from the `Networking` submenu.

```shell
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID_1 --source-dest-check "{\"Value\": false}"
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID_2 --source-dest-check "{\"Value\": false}"
```

## 4. Running through the worked example
You can now run through the standard Calico worked example.  You will require
SSH access to the nodes.

SSH into a node with the mykey.pem and username core. The public IP addresses
of your instances can be found on your AWS EC2 dashboard.
```
ssh -i mykey.pem core@<PUBLIC IP>
```

Now that your environment is configured, you are ready to follow the [Calico with Docker networking walkthrough]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/basic) worked example.

> In the worked example, be sure to follow the additional instructions for
configuring `nat-outgoing`.

## (Optional) Enabling traffic from the internet to containers
Services running on a Calico host's containers in AWS can be exposed to the internet.  Since the containers have IP
addresses in the private IP range, traffic to the container must be routed using a NAT and an appropriate Calico
security profile.

Let's create a new security profile and look at the default rules.

```shell
calicoctl profile add WEB
calicoctl profile WEB rule show
```

You should see the following output.

```shell
Inbound rules:
   1 allow from tag WEB
Outbound rules:
   1 allow
```

Let's modify this profile to make it more appropriate for a public webserver by allowing TCP traffic on ports 80 and
443:

```shell
calicoctl profile WEB rule add inbound allow tcp to ports 80,443
```

Now, we can list the rules again and see the changes:

```shell
calicoctl profile WEB rule show
```

should print

```shell
Inbound rules:
   1 allow from tag WEB
   2 allow tcp to ports 80,443
Outbound rules:
   1 allow
```

On the same host, create a NAT that forwards port 80 traffic to a new container.

```shell
sudo iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT --to 192.168.2.1:80
```

Lastly, the AWS host's security group must be updated for any ports you want to expose.  Run this command from your
AWS CLI machine to allow incoming traffic to port 80:

```shell
aws ec2 authorize-security-group-ingress \
  --group-name MySG \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0
```

You should now be able to access the container using the public IP address of your AWS host on port 80 by visiting
`http://<host public ip>:80` or running:

```shell
curl http://<host public ip>:80
```

## (Optional) Modifying MTU for Performance Boost

Some [AWS instance types](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html#jumbo_frame_instances)
utilize a default [MTU](https://en.wikipedia.org/wiki/Maximum_transmission_unit)
of 9001, which is larger than the standard 1500 used by most of the Internet.

If you have a high traffic deployment and all of your host instances in your
AWS Calico cluster are using these instance types, you may be able to improve
performance for traffic between your Calico nodes. To do this, you need to
modify the MTU of the veth interfaces of your Calico containers.

> **WARNING**: You must run these commands on ALL of the hosts and containers in your
> deployment. If not all of your instances are jumbo frame instances or if you
> do not modify MTU on all containers and hosts, you may  experience unexpected
> behavior and/or packet loss.

#### Modify Calico interface MTU on hosts
First, modify the MTU on the `cali######`
interfaces on your host instances (use `ip link` or `ifconfig` to see the
interface names):

```shell
$ sudo ifconfig <interface> mtu 9001
```
Repeat for all relevant Calico interfaces and the tunl0 interface on the host.

If you're using IP-in-IP, instead use a value of 8981 throughout.
This is because Calico traffic will flow
through the IP-in-IP tunnel.  When packets enter the IP-in-IP tunnel, an IP
header of length 20 is added to the packet, summing to a total size of 9001.

#### Install nsenter
In order to modify the MTU of the Calico interface in your containers, you must
access the container's network namespace on your host, which manages the
container's interface. The [`nsenter`](https://github.com/jpetazzo/nsenter)
tool can be used to enter the namespace and make this change.

```shell
# Install nsenter
$ docker run -v /usr/local/bin:/target jpetazzo/nsenter
```

#### Modify container Calico interface MTU
For each container on your host, enter the namespace of the container,
replacing `<container_id>` with the name or ID of the container.

```shell
$ sudo nsenter -n -t $(sudo docker inspect --format {% raw %}'{{ .State.Pid }}'{% endraw %}' <container_id>) /bin/bash
```

Finally, modify the MTU of the Calico interface on the container. If you
specified an interface when adding the container to Calico, change `eth1` to be
the name of the interface you passed in.

```shell
$ sudo ifconfig eth1 mtu 8981
```

For high traffic deployments, this should increase the performance of
traffic between your Calico containers.

[install-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os
[configure-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-calico-with-docker.html
