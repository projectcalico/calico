<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Running the Calico tutorials on DigitalOcean
Calico is designed to provide high performance massively scalable virtual networking for private data centers. But you 
can also run Calico within a public cloud such as DigitalOcean.  The following instructions show how to network 
containers using Calico routing and the Calico security model on DigitalOcean.

## Getting Started with Digital Ocean
These instructions assume a total of two DigitalOcean hosts running CoreOS. For more general background, see the 
[CoreOS on DigitalOcean documentation][coreos-digitalocean].

## 1. Spinning up the VMs
From the DigitalOcean Web Console, select the "Create Droplet" button in the top right corner.  

In the form that appears, give the machine a hostname, select a desired size (the smallest size should be fine for this 
demo), and choose a region.  You should see something similar to the following:

![alt tag](../images/Create_Droplet_1.png)

You will be creating two droplets.  We recommend you call the first calico-01 and the second
calico-02.

Next, select CoreOS alpha version as the image type.  Note that some regions may not have this image as an option so 
you may have to reselect a region that supports CoreOS alpha version. Check the Private Networking box and the User 
Data box under Available Settings.  Add your SSH public key to be able to log in to the instance without credentials.

You should now see something similar to the following:

![alt tag](../images/Create_Droplet_2.png)


Before selecting "Create Droplet", you will need to specify the User Data.  

There are two worked examples you can follow: Calico as a Docker network
plugin, or Calico without Docker networking.  Select the cloud-config based on 
the networking option that you choose.

- [User Data for Calico as a Docker network plugin](docker-network-plugin/cloud-config) 
- [User Data for Calico without Docker networking](without-docker-networking/cloud-config)  
  
For the first droplet `calico-01`, paste in the cloud config from
`user-data-first`.

When the first droplet is running, look at the settings to get its private IPv4
address.

Repeat this process for a second host `calico-02`, but this time use the
cloud config from `user-data-other`, making the following global changes before
pasting it in:
- Replace all instances of `172.17.8.101` with the private IPv4 address of `calico-01`.


## 2. Running through the worked example
You can now run through the standard Calico worked example.  You will require
SSH access to the nodes.

SSH into each Calico host you created using the IP addresses found in the 
Droplets section of the Web Console:
```
ssh core@<ip>
```

There are two worked examples you can follow: Calico as a Docker network
plugin, or Calico without Docker networking.  Select the instructions based on 
the networking option that you chose for the cloud config in step (1).

> In the worked example, be sure to follow the additional instructions for
configuring `ipip` and `nat-outgoing`. 

- [Calico as a Docker network plugin walkthrough](docker-network-plugin/README.md) 
- [Calico without Docker networking walkthrough](without-docker-networking/README.md)  

## (Optional) Enabling traffic from the internet to containers
Services running on a Calico host's containers in DigitalOcean can be exposed to the internet.  Since the containers 
have IP addresses in the private IP range, traffic to the container must be routed using a NAT on the host and an 
appropriate Calico security profile.

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

Notice that profiles define policy for inbound packets and outbound packets separately.  This profile allows inbound 
traffic from other endpoints with the tag `WEB`, and (implicitly) denies inbound traffic from all other addresses.  
It allows all outbound traffic regardless of destination.

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
sudo iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j DNAT  --to 192.168.2.1:80
```

You should now be able to access the container using the public IP address of your DigitalOcean host on port 80 by 
visiting `http://<host public ip>:80` or running:

```
curl http://<host public ip>:80
```

[coreos-digitalocean]: https://coreos.com/docs/running-coreos/cloud-providers/digitalocean/
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calico-with-docker/DigitalOcean.md?pixel)](https://github.com/igrigorik/ga-beacon)
