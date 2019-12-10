---
title: Install Calico network policy on a host
canonical_url: 'https://docs.projectcalico.org/v3.9/getting-started/bare-metal/installation/binary-mgr'
---

### Big picture

Install only {{site.prodname}} network policy on a host to enforce security rules, using your own networking solution.

### Value

If your host does not use {{site.prodname}} networking, are not managing pods, and does not need to be aware of pods on other {{site.prodname}} hosts, you can install just {{site.prodname}} network policy. 

### Before you begin...

Review [Host Requirements]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/installation/overview).

### How to...

- [Install Calico network policy using a package manager](#install-calico-network-policy-using-a-package-manager])
- [Install Calico network policy, no package manager](#install-calico-network-policy-no-package-manager)

#### Install Calico network policy using a package manager

**PPA requires: Ubuntu 14.04 or 16.04**


 ```
  sudo add-apt-repository ppa:project-calico/master
  sudo apt-get update
  sudo apt-get upgrade
  sudo apt-get install calico-felix
 ```
**RPM requires: RedHat 7-derived distribution**

 ```
 cat > /etc/yum.repos.d/calico.repo <<EOF
 [calico]
 name=Calico Repository
 baseurl=http://binaries.projectcalico.org/rpm/master/
 enabled=1
 skip_if_unavailable=0
 gpgcheck=1
 gpgkey=http://binaries.projectcalico.org/rpm/master/key
 priority=97
 EOF

 yum install calico-felix
 ```
 A log is created in /var/log/calico/felix.log (default location) in the “wait-for-ready” state.

**Configure node resources**

Configure a node resource for each host that requires {{site.prodname}} network policy. A node resource requires only a node name; for most deployments this is the hostname. The etcd database is initialized after you create the first node resource. And the logs will change from the wait-for-ready state to initialization messages.

```
calicoctl create -f - <<EOF
apiVersion: projectcalico.org/v3
  kind: Node
  metadata:
    name: <node name or hostname>
EOF
```

#### Install Calico network policy, no package manager

1. Download and install the binary.
1. Use the following command to download the calico/node image.
  ```
  docker pull calico/node:master
  ```
1. Confirm that the image has loaded by typing docker images.
```
  REPOSITORY       TAG           IMAGE ID       CREATED         SIZE
  calico/node      master        e07d59b0eb8a   2 minutes ago   42MB
```
1. Create a temporary calico/node container.
   ```
   docker create --name container calico/node:master
   ```
1. Copy the calico-node binary from the container to the local file system.
   ```
   docker cp container:/bin/calico-node calico-node
   ```
1. Delete the temporary container.
   ```
   docker rm container
   ```
1. Set the extracted binary file to be executable.
   ```
   chmod +x calico-node
   ```
**Create a start-up script**

You must create a script to start and restart Felix (the component responsible for {{site.prodname}} enforcing network policy). You can use start-up scripts like systemd or upstart, or you can configure/start a **FelixConfiguration** file. 

**systemd sample**

```
[Unit]
Description=Calico Felix agent
After=syslog.target network.target

[Service]
User=root
ExecStartPre=/usr/bin/mkdir -p /var/run/calico
ExecStart=/usr/local/bin/calico-node -felix
KillMode=process
Restart=on-failure
LimitNOFILE=32000

[Install]
WantedBy=multi-user.target
```
**upstart sample**

```
description "Felix (Calico agent)"
author "Project Calico Maintainers <maintainers@projectcalico.org>"

start on stopped rc RUNLEVEL=[2345]
stop on runlevel [!2345]

limit nofile 32000 32000

respawn
respawn limit 5 10

chdir /var/run

pre-start script
  mkdir -p /var/run/calico
  chown root:root /var/run/calico
end script

exec /usr/local/bin/calico-node -felix

```
**Felix configuration file**

1. Create a Felix configuration file (/etc/calico/felix.cfg). 
   For help, see FelixConfiguration. Note the following:
   - If etcd is not running on the local machine, you must configure the EtcdAddr or EtcdEndpoints setting to tell Felix how to reach etcd.
   - Felix tries to detect if IPv6 is available on your platform. If Felix exits soon after startup with ipset or iptables errors try setting the Ipv6Support setting to false.
1. Start Felix using your init system.
   ```
   service calico-felix start
   ```
>**Tip**: For debugging, it can be useful to run Felix manually and output logs to a screen using the following command. If etcd is not running locally, replace the values shown with your etcd configuration. 
{: .alert .alert-info}

```
ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> FELIX_LOGSEVERITYSCREEN=INFO /usr/local/bin/calico-node -felix
```
### Above and beyond

- [Protect hosts using network policy]({{site.baseurl}}/{{page.version}}/security/protect-hosts)
