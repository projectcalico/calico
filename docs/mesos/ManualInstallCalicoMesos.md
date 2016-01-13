<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.14.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Manually Install Calico and Mesos on Agent
This tutorial will walk you through installing Mesos, Netmodules, and Calico onto a Centos host to create a Mesos agent compatible with Calico.

## Prerequisites
The sections below ensure that your Mesos agent is properly configured to allow Calico networking.

### Set & verify fully qualified domain name
These instructions assume each host can reach other hosts using their fully qualified domain names (FQDN).  To check the FQDN on a host use

```
hostname -f
```
Then attempt to ping that name from other hosts.

It is also important that Calico and Mesos have the same view of the (non-fully-qualified) hostname.  Ensure that the value returned by `hostname` is unique for each host in your cluster.

### Configure firewall
You will either need to configure the firewalls on each node in your cluster (recommended) to allow access to the cluster services or disable them completely.  This section contains configuration examples for `firewalld`.  If you use a different firewall, check your documentation for how to open the listed ports.

Agent (compute/slave) nodes require

| Service Name | Port/protocol     |
|--------------|-------------------|
| BIRD (BGP)   | 179/tcp           |
| mesos-agent  | 5051/tcp          |

Example `firewalld` config:

```
sudo firewall-cmd --zone=public --add-port=179/tcp --permanent
sudo firewall-cmd --zone=public --add-port=5051/tcp --permanent
sudo systemctl restart firewalld
```

## 1. Download the Calico Mesos Plugin
The Calico-Mesos plugin is available for download from the [calico-mesos repository releases](https://github.com/projectcalico/calico-mesos/releases). In this example, we will install the binary to the `/calico` directory.

```
wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.3/calico_mesos
chmod +x calico_mesos
sudo mkdir /calico
sudo mv calico_mesos /calico/calico_mesos
```
## 2. Create the modules.json Configuration File
To enable Calico networking in Mesos, you must create a `modules.json` file. When provided to the Mesos Agent process, this file will connect Mesos with the Net-Modules libraries as well as the Calico networking plugin, thus allowing Calico to 
receive networking events from Mesos.

```
wget https://raw.githubusercontent.com/projectcalico/calico-mesos/master/packages/sources/modules.json
sudo mv modules.json /calico/modules.json
```
## 3. Install Docker

**Docker must be installed on each Mesos Agent** that is:
- deploying calico via the packaged Calico container (recommended). Users who prefer to run Calico as a baremetal service (coming soon!) do not need to install Docker on each Agent, or...
- that will be launching Docker containers through Mesos.

Run the following commands to install Docker:

```
sudo yum update
sudo yum install -y docker docker-selinux
sudo systemctl enable docker.service
sudo systemctl start docker.service
```
### Verify Docker installation

```
sudo docker run hello-world
```

### Add user to Docker Group (Optional)
You may also want to create a `docker` group and add your local user to the group.  This means you can drop the `sudo` in the `docker ...` commands that follow.

```
sudo groupadd docker
sudo usermod -aG docker `whoami`
sudo systemctl restart docker.service
```

Then log out (`exit`) and log back in to pick up your new group association.  Verify your user has access to Docker without sudo

```
docker ps
```

## 4. Run Calico Node
The last Calico component required for Calico networking in Mesos is `calico-node`, a Docker image containing Calico's core routing processes.
 
`calico-node` can easily be launched via `calicoctl`, Calico's command line tool. When doing so, we must point `calicoctl` to our running instance of etcd, by setting the `ECTD_AUTHORITY` environment variable.

> Follow our [Mesos Cluster Preparation guide](MesosClusterPreparation.md#Install) if you do not already have an instance of etcd running to walk through installing etcd with Docker.

```
sudo yum install -y wget
wget https://github.com/projectcalico/calico-docker/releases/download/v0.9.0/calicoctl
chmod +x calicoctl
sudo ETCD_AUTHORITY=<IP of host with etcd>:4001 ./calicoctl node
```

## 5. Install Mesos / Netmodules Dependencies
Netmodules and Mesos both make use of the `protobuf`, `boost`, and `glog` libraries. To function correctly, Mesos and Netmodules must be built with identical compilations of these libraries. A standard Mesos installation will include bundled versions, so we'll compile Mesos with unbundled versions to ensure that netmodules is using precisely the same library as Mesos. First, download the libraries:

```
sudo yum update
sudo yum groupinstall -y 'Development Tools'

sudo yum update
sudo yum install -y wget docker git autoconf automake libcurl-devel \
apr-devel subversion-devel java java-devel protobuf-devel protobuf-python \
boost-devel zlib-devel maven libapr-devel cyrus-sasl-md5 python-devel

# Modify this value if your java home is different.
export JAVA_HOME=/usr/lib/jvm/java
```

At the time of this writing, the `glog-devel` rpm package (available after installing and updating `epel-release`) does not satisfy Mesos' glog dependency.

Run the following to manually compile and install glog v0.3.3:
```
git clone https://github.com/google/glog.git -b v0.3.3
cd glog
sudo ./configure --prefix=/usr --libdir=/usr/lib64 && sudo make && sudo make install
```
Next, install the picojson headers and protobuf.jar file:

```
sudo wget https://raw.githubusercontent.com/kazuho/picojson/v1.3.0/picojson.h -O /usr/local/include/picojson.h

sudo wget http://search.maven.org/remotecontent?filepath=com/google/protobuf/protobuf-java/2.5.0/protobuf-java-2.5.0.jar -O /usr/share/java/protobuf.jar
```

## 6. Build and Install Mesos
Next we'll follow the standard Mesos installation instructions, but pass a few flags to configure to use our installed libraries instead of the mesos bundled ones:

```
# Download Mesos source
git clone git://git.apache.org/mesos.git -b 0.26.0
cd mesos

# Configure and build.
./bootstrap
mkdir build
cd build
../configure --with-protobuf=/usr --with-boost=/usr --with-glog=/usr
make
sudo make install
```

## 7. Build and Install Netmodules
We install netmodules as a plugin to allow Calico to interface with Mesos.

```
# Download netmodules source
git clone https://github.com/mesosphere/net-modules.git
cd net-modules/isolator

# Configure and build
./bootstrap
mkdir build
cd build
../configure --with-mesos=/usr/local --with-protobuf=/usr
make
sudo make install
```

## 8. Launch Mesos-Slave

```
sudo ETCD_AUTHORITY=<ETCD-IP:PORT> /usr/local/sbin/mesos-slave \
--master=<MASTER-IP:PORT> \
--modules=file:///calico/modules.json \
--isolation=com_mesosphere_mesos_NetworkIsolator \
--hooks=com_mesosphere_mesos_NetworkHook
```
We provide the `ETCD_AUTHORITY` environment variable here to allow the  `calico_mesos` plugin to function properly when called by `mesos-slave`. Be sure to replace it with the address of your running etcd server.

## 9. Launch Tasks
With your cluster up and running, you can now [Launch Tasks with Calico Networking using Marathon](README.md#3-launching-tasks).

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/ManualInstallCalicoMesos.md?pixel)](https://github.com/igrigorik/ga-beacon)
