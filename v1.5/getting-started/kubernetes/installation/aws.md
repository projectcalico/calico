---
title: Deploying Calico and Kubernetes on AWS
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/aws'
---

These instructions allow you to set up a Kubernetes cluster with Calico networking on AWS using the [Calico CNI plugin][calico-cni]. This guide does not setup TLS between Kubernetes components or on the Kubernetes API.

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
commands.  This can be set in the `Services>IAM>Users` User configuration page of the web console.
For more information on configuration and keys, see Amazon's
[Configuring the AWS Command Line Interface][configure-aws-cli].

## 2. Setting up AWS networking

You'll need to configure AWS to allow your hosts to talk to each other.

A Virtual Private Cloud (VPC) is required on AWS in order to configure Calico networking on EC2. Your AWS account should have a default VPC that instances
automatically attach to when they are created.

To check if you have a default VPC, run the following command, then save VPC ID as an environment variable to use later.

```
aws ec2 describe-vpcs --filters "Name=isDefault,Values=true"

# Save VpcId from output as environment variable (without quotes)
export VPC_ID=<VpcId>
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
export VPC_ID=<VpcId>
```

Create a subnet for your hosts, then save a `SUBNET_ID` environment variable, replacing `<SubnetId>` with the `SubnetId` output value of the command.

```shell
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 172.35.0.0/24
export SUBNET_ID=<SubnetId>
```

Modify the Subnet to auto-assign public ip addresses:

```shell
aws ec2 modify-subnet-attribute --subnet-id $SUBNET_ID --map-public-ip-on-launch
```

Create an Internet Gateway.  Save the `InternetGatewayId` value as an environment variable.

```shell
aws ec2 create-internet-gateway
export GATEWAY_ID=<InternetGatewayId>
```

Attach the gateway to the VPC.

```
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway $GATEWAY_ID
```

Create a Route Table on the VPC. Save the `RouteTableId` as an environment variable.

```shell
aws ec2 create-route-table --vpc-id $VPC_ID
export ROUTE_TABLE_ID=<RouteTableId>
```

Associate the route table with the Subnet and add a route to the Internet.

```shell
aws ec2 associate-route-table --subnet-id $SUBNET_ID --route-table-id $ROUTE_TABLE_ID
aws ec2 create-route --route-table-id $ROUTE_TABLE_ID --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $GATEWAY_ID
```

Enable DNS names on the VPC.

```shell
aws ec2 modify-vpc-attribute --vpc-id=$VPC_ID --enable-dns-support
```

### 2.2 Configuring Key Pair and Security Group

Create a Key Pair to use for ssh access to the instances. The following command will generate a key for you.

```shell
aws ec2 create-key-pair --key-name mykey --output text
```

Copy the output into a new file called mykey.pem.  The file must only include ```-----BEGIN RSA PRIVATE KEY-----```,
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
export SECURITY_GROUP_ID=<GroupId>
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

Create the Kubernetes master and at least one Kubernetes nodes by passing in appropriate `cloud-config` files.

To get the necessary 'cloud-config' files, clone the project:

    git clone https://github.com/projectcalico/calico.git

Then, change into the directory for this guide.

    cd calico/{{page.version}}/getting-started/kubernetes/installation

Find your CoreOS stable HVM image for your region and store it as an environment variable.  You can find the
full list of available images on [the CoreOS website](https://coreos.com/os/docs/latest/booting-on-ec2.html).

```shell
export IMAGE_ID=<ami-########>
```

> Use `aws ec2 describe-availability-zones` to display your region if you do not remember.

Deploy the Kubernetes master node using the following command:

```shell
aws ec2 run-instances \
  --image-id $IMAGE_ID \
  --instance-type t2.micro \
  --key-name mykey \
  --security-group-ids $SECURITY_GROUP_ID \
  --user-data file://cloud-config/master-config.yaml
#  --subnet $SUBNET_ID
#  Include the subnet param above if using a non-default VPC

# Save the instance id to an environment variable
INSTANCE_ID_MASTER=<InstanceId>
```

You may want to tag the instance so that you can distinguish it from the nodes later.  Tag it with "role=master".

```shell
aws ec2 create-tags --resources $INSTANCE_ID_MASTER --tags Key=role,Value=master
```

You can view tags with `aws ec2 describe-tags`.

Now, deploy at least one worker node.

First, edit `cloud-config/node-config.yaml` and replace all instances of `kubernetes-master` with your Master's private
DNS name.  This can be found in the output of the previous command, or the AWS portal. You can do this with a `sed`
command, replacing `<MASTER_PRIVATE_DNS>` with your master's private DNS name:

```
sed -i 's/kubernetes-master/<MASTER_PRIVATE_DNS>/g' cloud-config/node-config.yaml
```

Then, run the following command to start a node instance.

```
aws ec2 run-instances \
  --image-id $IMAGE_ID \
  --instance-type t2.micro \
  --key-name mykey \
  --security-group-ids $SECURITY_GROUP_ID \
  --user-data file://cloud-config/node-config.yaml
#  --subnet $SUBNET_ID
#  Include the subnet param above if using a non-default VPC

# Save the instance id to an environment variable
INSTANCE_ID_SLAVE_1=<InstanceId>
```

Finally, disable `Source/Dest. Check` on each instance (including the master) to allow routing between pods without needing IP in IP.  All instances must be in the same subnet.  You can do this with the CLI, or in the `Networking` part of the instances' right click menus.

```shell
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID_MASTER --source-dest-check "{\"Value\": false}"
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID_SLAVE_1 --source-dest-check "{\"Value\": false}"
...
```

## 4. Using your cluster

### 4.1 Configuring kubectl

The following steps configure remote kubectl access to your cluster.

Download `kubectl`
> The linux kubectl binary can be fetched with a command like:

```shell
wget https://storage.googleapis.com/kubernetes-release/release/v1.4.0/bin/linux/amd64/kubectl
chmod +x ./kubectl
```

> On an OS X workstation, replace linux in the URL above with darwin:

```shell
wget https://storage.googleapis.com/kubernetes-release/release/v1.4.0/bin/darwin/amd64/kubectl
```

Save the public DNS name for the master in an environment variable. Replace `ec2-###-##-##-###.compute-1.amazonaws.com` with the master public DNS name - you can find this in the AWS portal, or by running `aws ec2 describe-instances`.

```shell
export MASTER_DNS=<ec2-###-##-##-###.compute-1.amazonaws.com>
```

Make sure you can ssh to the master. Replace `~/mykey.pem` with the location of the keypair you generated earlier.

```shell
ssh -i ~/mykey.pem core@$MASTER_DNS
```

Close the SSH session, and forward port 8080 to your master.  The following command sets up SSH forwarding of port 8080 to your master node so that you can run `kubectl` commands on your local machine.

```shell
ssh -i ~/mykey.pem -N -L 8080:${MASTER_DNS}:8080 core@$MASTER_DNS &
```

Verify that you can access the Kubernetes API.  The following command should return a list of Kubernetes nodes.

```shell
./kubectl get nodes
```
### 4.2 Configure Outbound NAT

To enable connectivity to the internet for our Pods, we'll use `calicoctl`:

```shell
# Log into the master instance.
ssh -i ~/mykey.pem core@$MASTER_DNS

# Enable outgoing NAT on the Calico pool.
docker run --rm --net=host calico/ctl pool add 192.168.0.0/16 --nat-outgoing
```

## 5. Install Addons

{% include {{page.version}}/install-k8s-addons.md %}


[install-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os
[configure-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-calico-with-docker.html
[calico-cni]: https://github.com/projectcalico/calico-cni
