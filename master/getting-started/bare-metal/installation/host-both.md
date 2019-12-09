---
title: Install Calico networking and policy on a host
canonical_url: 'https://docs.projectcalico.org/v3.9/getting-started/bare-metal/installation/binary-mgr'
---

### Big picture

Install Calico networking and network policy to protect host communications.

### Before you begin...

To install Calico networking and network policy on a host, verify and configure the following: 

- Hosts have **Docker** installed
- Hosts allow Calico to manage cali* interfaces and tunl* interfaces (if IP in IP is enabled for encapsulation).
- Disable **NetworkManager**
  Many Linux distributions include NetworkManager, which manipulates the routing table for host interfaces. For Calico to correctly route traffic, it must be able to manage the Linux host interfaces. Disable NetworkManager interface management by creating the following configuration file at: `/etc/NetworkManager/conf.d/calico.conf` 

  ```
  [keyfile]
  unmanaged-devices=interface-name:cali*;interface-name:tunl*
  ```
- Ensure that your hosts and firewalls allow the necessary traffic based on your configuration.

- Ensure that Calico has the CAP_SYS_ADMIN privilege.
  The simplest way to provide the necessary privilege is to run Calico as root or in a privileged container.

### How to...

#### Install Calico networking and network policy 

If your host needs to be aware of other pods on other Calico hosts (even if it is not directly managing pods), you must use one of the following options to install both Calico networking and network policy:

- [Run calico/node run command]()
- [Run calico/node in a Docker container]()

##### Run calico/node 

To run calico/node under Docker, use the calicoctl node run command. The command automatically pre-initializes the etcd database. 

```
ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> ./calicoctl node run --node-image=calico/node:master
```
Where you supply values (ETCD_ENDPOINTS Env, <ETCD_IP>:<ETCD_PORT>) if etcd is not running locally. See the calicoctl node run guide for details. 

##### Run calico/node in a Docker container

**Step 1: Create an EnvironmentFile**

Use the following guidelines and sample file to define the environment variables for starting Calico on the host. For more help, see [Node Resource]().

| **Variable**                                 | **Configuration guidance**                                   |
| -------------------------------------------- | ------------------------------------------------------------ |
| ETCD_ENDPOINTS=`http://localhost:2379`       | ETCD_ENDPOINTS must point to the correct etcd cluster endpoints. |
| ETCD_CA_CERT_FILEETCD_CERT_FILEETCD_KEY_FILE | For SSL/TLS with etcd, values are required. For a non-SSL version of etcd, not specifying values is standard. |
| CALICO_NODENAME                              | If a value is not specified, the compute server hostname is used to identify the Calico node. |
| CALICO_IP or CALICO_IP6                      | If values are not specified for both, Calico uses the currently-configured values for the next hop IP addresses for this node—these can be configured through the Node resource. If no next hop addresses are configured, Calico automatically determines an IPv4 next hop address by querying the host interfaces (and configures this value in the Node resource). You can set CALICO_IP to auto-detection of IP address every time the node starts. If you set IP addresses through these environment variables, it reconfigures any values currently set through the Node resource. |
| CALICO_AS                                    | If not specified, Calico uses the currently- configured value for the AS Number for the node BGP client—this can be configured through the node resource. If the Node resource value is not set, Calico inherits the AS Number from the global default value. If you set a value through this environment variable, it reconfigures any value currently set through the Node resource. |
| CALICO_NETWORKING_BACKEND                    | Defaults to BIRD as the routing daemon. If routing is handled by an alternative mechanism, you can set the value to none. |

**Sample EnvironmentFile - calico.env**

```
ETCD_ENDPOINTS=http://localhost:2379
ETCD_CA_CERT_FILE=""
ETCD_CERT_FILE=""
ETCD_KEY_FILE=""
CALICO_NODENAME=""
CALICO_NO_DEFAULT_POOLS=""
CALICO_IP=""
CALICO_IP6=""
CALICO_AS=""
CALICO_NETWORKING_BACKEND=bird
```
**Step 2: Create an init daemon**

Use an init daemon (like systemd or upstart) that starts the the calico/node image as a service using the EnvironmentFile values.

**Sample systemd service - calico-node.service**

```
[Unit]
Description=calico-node
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=/etc/calico/calico.env
ExecStartPre=-/usr/bin/docker rm -f calico-node
ExecStart=/usr/bin/docker run --net=host --privileged \
 --name=calico-node \
 -e NODENAME=${CALICO_NODENAME} \
 -e IP=${CALICO_IP} \
 -e IP6=${CALICO_IP6} \
 -e CALICO_NETWORKING_BACKEND=${CALICO_NETWORKING_BACKEND} \
 -e AS=${CALICO_AS} \
 -e NO_DEFAULT_POOLS=${CALICO_NO_DEFAULT_POOLS} \
 -e ETCD_ENDPOINTS=${ETCD_ENDPOINTS} \
 -e ETCD_CA_CERT_FILE=${ETCD_CA_CERT_FILE} \
 -e ETCD_CERT_FILE=${ETCD_CERT_FILE} \
 -e ETCD_KEY_FILE=${ETCD_KEY_FILE} \
 -v /var/log/calico:/var/log/calico \
 -v /run/docker/plugins:/run/docker/plugins \
 -v /lib/modules:/lib/modules \
 -v /var/run/calico:/var/run/calico \
 calico/node:master

ExecStop=-/usr/bin/docker stop calico-node

Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
```
Upon start, the systemd service:

- Confirms Docker is installed under the [Unit] section
- Gets environment variables from the environment file above
- Removes existing calico/node container (if it exists)
- Starts calico/node

The script also stops the calico/node container when the service is stopped.

>**Note**: Depending on how you’ve installed Docker, the name of the Docker service under the [Unit] section may be different (such as docker-engine.service). Be sure to check this before starting the service.

### Above and beyond

- [Determine your best networking option[()
- [Get started with Calico network policy]()
- [Protect hosts]()