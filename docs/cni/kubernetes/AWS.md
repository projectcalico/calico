<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Deploying Calico and Kubernetes on AWS

These instructions allow you to set up a Kubernetes cluster with Calico networking on AWS using the [Calico CNI plugin][calico-cni]. This guide does not setup TLS between Kubernetes components or on the Kubernetes API.

## 1. Getting started with AWS
These instructions describe how to set up two CoreOS hosts on AWS.  For more general background, see
[the CoreOS on AWS EC2 documentation](https://coreos.com/docs/running-coreos/cloud-providers/ec2/).

Download and install AWS Command Line Interface:
```
curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
unzip awscli-bundle.zip
sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
```
For more information, see Amazon's [Installing the AWS Command Line Interface][install-aws-cli].

Run the AWS configure command, which will prompt you to set your User keys.
```
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
```
aws ec2 create-vpc --cidr-block 172.35.0.0/24
export VPC_ID=<VpcId>
```

Create a subnet for your hosts, then save a `SUBNET_ID` environment variable, replacing `<SubnetId>` with the `SubnetId` output value of the command.
```
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 172.35.0.0/24
export SUBNET_ID=<SubnetId>
```

Modify the Subnet to auto-assign public ip addresses:
```
aws ec2 modify-subnet-attribute --subnet-id $SUBNET_ID --map-public-ip-on-launch
```

Create an Internet Gateway.  Save the `InternetGatewayId` value as an environment variable.
```
aws ec2 create-internet-gateway
export GATEWAY_ID=<InternetGatewayId>
```

Attach the gateway to the VPC.
```
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway $GATEWAY_ID
```

Create a Route Table on the VPC. Save the `RouteTableId` as an environment variable.
```
aws ec2 create-route-table --vpc-id $VPC_ID
export ROUTE_TABLE_ID=<RouteTableId>
```

Associate the route table with the Subnet and add a route to the Internet.
```
aws ec2 associate-route-table --subnet-id $SUBNET_ID --route-table-id $ROUTE_TABLE_ID
aws ec2 create-route --route-table-id $ROUTE_TABLE_ID --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $GATEWAY_ID
```

Enable DNS names on the VPC.
```
aws ec2 modify-vpc-attribute --vpc-id=$VPC_ID --enable-dns-support
```

### 2.2 Configuring Key Pair and Security Group
Create a Key Pair to use for ssh access to the instances. The following command will generate a key for you.
```
aws ec2 create-key-pair --key-name mykey --output text
```

Copy the output into a new file called mykey.pem.  The file must only include ```-----BEGIN RSA PRIVATE KEY-----```,
```-----END RSA PRIVATE KEY-----```, and everything in between.  Then, set appropriate permissions for your key file.
```
chmod 400 mykey.pem
```

A Security Group is required on the instances to control allowed traffic.  Save the `GroupId` output from the first command as an environment variable.
```
# Create Security Group
aws ec2 create-security-group --group-name MySG \
  --description MySecurityGroup --vpc-id $VPC_ID

# Save environment variable of GroupId
export SECURITY_GROUP_ID=<GroupId>
```

Allow SSH from the internet and allow all traffic between instances within the group.
```
# Allow SSH access
aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Allow all traffic within the VPC
aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID \
  --source-group $SECURITY_GROUP_ID  --protocol all --port all
```

## 3. Spinning up the VMs
Create the Kubernetes master and at least one Kubernetes nodes by passing in appropriate `cloud-config` files.

<!--- master only -->
To get the necessary 'cloud-config' files, clone this project:

    git clone https://github.com/projectcalico/calico-containers.git
<!--- else
To get the necessary 'cloud-config' files, clone this project and checkout the **release** release:

    git clone https://github.com/projectcalico/calico-containers.git
    git checkout tags/**release**
<!--- end of master only -->

Then, change into the directory for this guide.
```
cd calico-containers/docs/cni/kubernetes/
```

Find your CoreOS stable HVM image for your region and store it as an environment variable.  You can find the
full list of available images on [the CoreOS website](https://coreos.com/os/docs/latest/booting-on-ec2.html).
```
export IMAGE_ID=<ami-########>
```
> Use `aws ec2 describe-availability-zones` to display your region if you do not remember.

Deploy the Kubernetes master node using the following command:

```
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
```
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
```
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID_MASTER --source-dest-check "{\"Value\": false}"
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID_SLAVE_1 --source-dest-check "{\"Value\": false}"
...
```

## 4. Using your cluster
### 4.1 Configuring kubectl
The following steps configure remote kubectl access to your cluster.

Download `kubectl`
```
wget https://storage.googleapis.com/kubernetes-release/release/v1.1.4/bin/linux/amd64/kubectl
chmod +x ./kubectl
```

Save the public DNS name for the master in an environment variable. Replace `ec2-###-##-##-###.compute-1.amazonaws.com` with the master public DNS name - you can find this in the AWS portal, or by running `aws ec2 describe-instances`.
```
export MASTER_DNS=<ec2-###-##-##-###.compute-1.amazonaws.com>
```

Make sure you can ssh to the master. Replace `~/mykey.pem` with the location of the keypair you generated earlier.
```
ssh -i ~/mykey.pem core@$MASTER_DNS
```

Close the SSH session, and forward port 8080 to your master.  The following command sets up SSH forwarding of port 8080 to your master node so that you can run `kubectl` commands on your local machine.
```
ssh -i ~/mykey.pem -N -L 8080:${MASTER_DNS}:8080 core@$MASTER_DNS &
```

Verify that you can access the Kubernetes API.  The following command should return a list of Kubernetes nodes.
```
./kubectl get nodes
```

### 4.2 Deploying SkyDNS
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

### 4.3 Deploying the guestbook application
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
aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID \
  --protocol tcp --port 30001 --cidr 0.0.0.0/0

```
> In a production deployment, it is recommended to use an AWS [LoadBalancer][loadbalancers] service which automatically deploys an AWS load-balancer and configures a public IP address for the service.

You should now be able to access the guestbook application from a browser at `http://<MASTER_DNS>:30001`.

### 4.4 Next Steps

Now that you have a verified working Kubernetes cluster with Calico, you can continue [deploying applications on Kubernetes][examples].

You can also take a look at how you can use Calico [network policy on Kubernetes](NetworkPolicy.md).


[install-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os
[configure-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-calico-with-docker.html
[calico-cni]: https://github.com/projectcalico/calico-cni
[guestbook]: https://github.com/kubernetes/kubernetes/blob/master/examples/guestbook/README.md
[loadbalancers]: http://kubernetes.io/v1.0/docs/user-guide/services.html#type-loadbalancer
[examples]: https://github.com/kubernetes/kubernetes/tree/master/examples

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/AWS.md?pixel)](https://github.com/igrigorik/ga-beacon)
