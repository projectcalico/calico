# Running calico-docker on AWS
Calico is designed to provide high performance massively scalable virtual networking for private data centers. But you 
can also run Calico within a public cloud such as Amazon Web Services (AWS).  The following instructions show how to 
network containers using Calico routing and the Calico security model on AWS.

## Getting started with AWS
These instructions describe how to set up two CoreOS hosts on AWS.  For more general background, see 
[the CoreOS on AWS documentation](https://coreos.com/docs/running-coreos/cloud-providers/ec2/).

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
>  AWS Access Key ID: <User Access Key>
>  AWS Secret Access Key: <User Secret Access Key>
>  Default region name: us-west-2
>  Default output format: <json, text, or table>
```
Your AWS user needs to have the policy AmazonEC2FullAccess or be in a group with this policy in order to run the ec2 
commands.  This can be set in the Services>IAM>Users User configuration page of the web console.
For more information on configuration and keys, see Amazon's 
[Configuring the AWS Command Line Interface][configure-aws-cli].

## Setting up AWS networking
Before you can use Calico to network your containers, you first need to configure AWS to allow your hosts to talk to 
each other.

Create a Key Pair to use for ssh access to the instances. The following command will generate a key for you.
```
aws ec2 create-key-pair --key-name mykey --output text
```

Copy the output into a new file called mykey.pem.  The file should include ```-----BEGIN RSA PRIVATE KEY-----```, 
```-----END RSA PRIVATE KEY-----```, and everything in between.  Then, set appropriate permissions for your key file.
```
chmod 400 mykey.pem
```

A Security Group is required on the instances to control allowed traffic.  Create a security group that allows all 
traffic between instances within the group but only SSH access from the internet.
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
Create the two Calico Docker hosts by passing in a `cloud-config` file. 

There are three demonstration options depending on whether you are running with libnetwork, Powerstrip or the 
default Docker networking.  Select the appropriate cloud-config based on the demonstration option.

- [User Data for Docker default networking](default-networking/cloud-config)
- [User Data for libnetwork](libnetwork/cloud-config)
- [User Data for Powerstrip](powerstrip/cloud-config)
  
A different file is used for the two servers.    
- For the first server, use the `user-data-first`
- For the second server, use the `user-data-others`

Copy these files onto your machine.

For the first server run:

```
aws ec2 run-instances \
  --image-id ami-29734819 \
  --instance-type t1.micro \
  --key-name mykey \
  --security-groups MySG \
  --user-data file://<PATH_TO_CLOUD_CONFIG>/user-data-first
```

replacing <PATH_TO_CLOUD_CONFIG> with the appropriate directory containing the cloud config.

Find the PrivateIpAddress value of the first server by checking the output of this command.  Open your `user-data-others` file and replace the instances of `172.17.8.101` with this private IP address.

Now, for the second server run:

```
aws ec2 run-instances \
  --image-id ami-29734819 \
  --instance-type t1.micro \
  --key-name mykey \
  --security-groups MySG \
  --user-data file://<PATH_TO_CLOUD_CONFIG>/user-data-others
```

Notes:
-  The "ami-########" represents the CoreOS alpha image type.
-  It may take a couple of minutes for AWS to boot the machines after creating them.


## Set up the IP Pool before running the demo
Run the following commands to SSH into each node and set up the IP pool

SSH into a node with the mykey.pem and username core. The public IP addresses of your instances can be found on your AWS EC2 dashboard.
```
ssh -i mykey.pem core@<PUBLIC IP>
```

On any one of the hosts, create the IP pool Calico will use for your containers:

```
calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing
```

# Running the demonstration
You can now run through the standard Calico demonstration.  There are three demonstration options depending on 
whether you are running with libnetwork, Powerstrip or the default Docker networking.

- [demonstration with Docker default networking](default-networking/Demonstration.md)
- [demonstration with libnetwork](libnetwork/Demonstration.md) 
- [demonstration with Powerstrip](powerstrip/Demonstration.md)

# (Optional) Enabling traffic from the internet to containers
Services running on a Calico host's containers in AWS can be exposed to the internet.  Since the containers have IP 
addresses in the private IP range, traffic to the container must be routed using a NAT and an appropriate Calico 
security profile.

Let's create a new security profile and look at the default rules.

```
calicoctl profile add WEB
calicoctl profile WEB rule show
```

You should see the following output.

```
Inbound rules:
   1 allow from tag WEB 
Outbound rules:
   1 allow
```

Let's modify this profile to make it more appropriate for a public webserver by allowing TCP traffic on ports 80 and 
443:
```
calicoctl profile WEB rule add inbound allow tcp to ports 80,443
```

Now, we can list the rules again and see the changes:

```
calicoctl profile WEB rule show
```

should print

```
Inbound rules:
   1 allow from tag WEB 
   2 allow tcp to ports 80,443
Outbound rules:
   1 allow
```

On the same host, create a NAT that forwards port 80 traffic to a new container.

```
sudo iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT --to 192.168.2.1:80
```

Lastly, the AWS host's security group must be updated for any ports you want to expose.  Run this command from your 
AWS CLI machine to allow incoming traffic to port 80:

```
aws ec2 authorize-security-group-ingress \
  --group-name MySG \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0
```

You should now be able to access the container using the public IP address of your AWS host on port 80 by visiting 
`http://<host public ip>:80` or running:

```
curl http://<host public ip>:80
```


[install-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/installing.html#install-bundle-other-os
[configure-aws-cli]: http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html