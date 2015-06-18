# Running calico-docker on DigitalOcean
Calico runs on the DigitalOcean virtualization platform.  The following instructions show the full power of the Calico routing and security model on DigitalOcean (and allow DigitalOcean to be used for testing).

## Getting Started
These instructions assume a total of three DigitalOcean hosts running CoreOS. For more general background, see the [CoreOS on DigitalOcean documentation](https://coreos.com/docs/running-coreos/cloud-providers/digitalocean/).

etcd needs to be running on the Calico hosts.  The easiest way to bootstrap etcd is with a discovery URL.  Choose an etcd cluster size that is equal to or less than the number of Calico nodes (an odd number in the range 3-9 works well).  We'll use 3 for the size of the etcd cluster and the Calico nodes in the instructions below.  
Use `curl` in your local machine's terminal to get a fresh discovery URL (replace size=3 with your cluster size if desired):
```
curl https://discovery.etcd.io/new?size=3
```
You need to grab a fresh URL each time you bootstrap a cluster.

Copy the following **cloud-config** contents into some local file or buffer to be used later. **Replace `<discovery URL>` with the URL retrieved above**:
```
#cloud-config
write_files:
  - path: /home/core/install-calico
    permissions: 0755
    owner: root
    content: |
      #!/bin/bash
      # Download calicoctl and make it executable:
      wget https://github.com/Metaswitch/calico-docker/releases/download/v0.4.5/calicoctl
      chmod +x ./calicoctl
      # Start the calico node service:
      sudo ./calicoctl node --ip=$private_ipv4
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
Keep this config handy, it will be used when creating the hosts.

## Spinning up the VMs
From the DigitalOcean Web Console, select the "Create Droplet" button in the top right corner.  

In the form that appears, give the machine a hostname, select a desired size (the smallest size should be fine for this demo), and choose a region.  You should see something similar to the following:

![alt tag](digitalocean/Create_Droplet_1.png)


Next, select CoreOS alpha version as the image type.  Note that some regions may not have this image as an option so you may have to choose a region that supports CoreOS alpha version.
Check the Private Networking box and the User Data box under Available Settings.  Add your SSH public key to be able to log in to the instance without credentials.

You should now see something similar to the following:

![alt tag](digitalocean/Create_Droplet_2.png)


Before selecting "Create Droplet", you will need to specify the User Data.  Paste the **cloud-config** from the Getting Started section into the text field that appears after selecting the User Data checkbox.

Repeat the instance creation steps until you have 3 Calico hosts (or however many hosts you chose as the size).  Use the same cloud-config as the User Data for each VM.

## Installing calicoctl on each node
On each node, there should be a script file called "install_calico" in the home directory.  Run the script on each node to set up Calico:
```
./install_calico
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
Services running on containers in DigitalOcean can be exposed to the internet using Calico using port mapping iptables NAT rules and an appropriate Calico security profile.  For example, you have a container that you've assigned the CALICO_IP of 192.168.7.4 to, and you have NGINX running on port 80 inside the container. If you want to expose this on port 8000, then you should follow the instructions at https://github.com/Metaswitch/calico-docker/blob/master/docs/AdvancedNetworkPolicy.md to expose port 80 on the container and then run the following command to add the port mapping:

```
iptables -A PREROUTING -t nat -i ens4v1 -p tcp --dport 8000 -j DNAT  --to 172.168.7.4:80
```
