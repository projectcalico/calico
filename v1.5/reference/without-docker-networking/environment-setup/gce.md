---
title: # Running the Calico tutorials on GCE
sitemap: false 
---

Calico is designed to provide high performance massively scalable virtual networking for private data centers. But you
can also run Calico within a public cloud such as Google Compute Engine (GCE). The following instructions show how to
network containers using Calico routing and the Calico security model on GCE.

## 1. Getting started with GCE
These instructions describe how to set up two CoreOS hosts on GCE.  For more general background, see
[the CoreOS on GCE documentation][coreos-gce].

Download and install GCE, then restart your terminal:

```shell
$ curl https://sdk.cloud.google.com | bash
```

For more information, see Google's [gcloud install instructions][gcloud-instructions].

Log into your account:

```shell
$ gcloud auth login
```

In the GCE web console, create a project and enable the Compute Engine API.
Set the project as the default for gcloud:

```shell
$ gcloud config set project PROJECT_ID
```

And set a default zone

```shell
$ gcloud config set compute/zone us-central1-a
```

### 1.1 Setting up GCE networking
GCE blocks traffic between hosts by default; run the following command to allow Calico traffic to flow between
containers on different hosts:

```shell
gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.240.0.0/16"
```

You can verify the rule with this command:

```shell
$ gcloud compute firewall-rules list
```

## 2. Spinning up the VMs
Create the VMs by passing in a cloud-init file.

A different file is used for the two servers.

- For the first server, use [`user-data-first`]({{site.baseurl}}/{{page.version}}/reference/without-docker-networking/environment-setup/cloud-config/user-data-first)
- For the second server, use the [`user-data-others`]({{site.baseurl}}/{{page.version}}/reference/without-docker-networking/environment-setup/cloud-config/user-data-others)

For the first server run:

```shell
$ gcloud compute instances create \
  calico-1 \
  --image-project coreos-cloud \
  --image coreos-alpha-1109-1-0-v20160715 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=<PATH_TO_CLOUD_CONFIG>/user-data-first
```

Open your `user-data-others` file and replace the instances of `172.17.8.101` with the private IP address of the `calico-01` server you just created.  You can find this in the output of the previous command.

Then, for the second server, run:

```shell
$ gcloud compute instances create \
  calico-2 \
  --image-project coreos-cloud \
  --image coreos-alpha-1109-1-0-v20160715 \
  --machine-type n1-standard-1 \
  --metadata-from-file user-data=<PATH_TO_CLOUD_CONFIG>/user-data-others
```


## 3.  Running through the worked example
You can now run through the standard Calico worked example.  You will require
SSH access to the nodes.

SSH into each node using gcloud (names are calico-1 and calico-2):

```shell
$ gcloud compute ssh <instance name>
```

Sudo to user core on each node.  User core is the coreos default user and this is where the worked
example ETCD environment variables will exist.

```shell
$ sudo -u core -i
$ env | grep ETCD_AUTHORITY
```

Now that your environment is configured, you are ready to follow the [Calico without Docker networking walkthrough]({{site.baseurl}}/{{page.version}}/reference/without-docker-networking/installation) worked example.

## (Optional) Enabling traffic from the internet to containers
Services running on a Calico host's containers in GCE can be exposed to the internet.  Since the containers have IP
addresses in the private IP range, traffic to the container must be routed using a NAT and an appropriate Calico
security profile.

Let's create a new security profile and look at the default rules.

```shell
$ calicoctl profile add WEB
$ calicoctl profile WEB rule show
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
$ calicoctl profile WEB rule add inbound allow tcp to ports 80,443
```

Now, we can list the rules again and see the changes:

```shell
$ calicoctl profile WEB rule show
```

should print

```shell
Inbound rules:
   1 allow from tag WEB
   2 allow tcp to ports 80,443
Outbound rules:
   1 allow
```

On the same host, create a NAT that forwards port 80 traffic to the new container.

```shell
$ sudo iptables -A PREROUTING -t nat -i ens4v1 -p tcp --dport 80 -j DNAT  --to 192.168.2.1:80
```

Lastly, the GCE's firewall rules must be updated for any ports you want to expose. Run this gcloud command to allow
incoming traffic to port 80:

```shell
$ gcloud compute firewall-rules create allow-http \
  --description "Incoming http allowed." --allow tcp:80
```

You should now be able to access the container using the public IP address of your GCE host on port 80 by
visiting `http://<host public ip>:80` or running:

```shell
$ curl http://<host public ip>:80
```

[coreos-gce]: https://coreos.com/os/docs/latest/booting-on-google-compute-engine.html
[gcloud-instructions]: https://cloud.google.com/compute/docs/gcloud-compute/
