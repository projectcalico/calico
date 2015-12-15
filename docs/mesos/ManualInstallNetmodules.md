<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Manually Install Mesos + Netmodules
This tutorial will walk you through building and installing Mesos + Net-Modules from source. It assumes that you already have seperately installed and started your Mesos Masters (which don't require any modifications for compatibility with Calico).

## 1. Install Dependencies
Netmodules and Mesos both make use of the `protobuf`, `boost`, and `glog` libraries. To function correctly, Mesos and Netmodules must be built with identical compilations of these libraries. A standard Mesos installation will include bundled versions, so we'll compile Mesos with unbundled versions to ensure that netmodules is using precisely the same library as Mesos. First, download the libraries:
```
$ sudo yum install -y protobuf-devel protobuf-python boost-devel glog-devel
```
> Alternative to using the epel-release packages, you can manually compile these libraries yourself.

>A note on Glog: At the time of this writing, the `glog-devel` rpm package does not satisfy Mesos' glog dependency. If you encounter this issue, try manually compiling and installing glog instead. 

Next, install the picojson headers:

    $ wget https://raw.githubusercontent.com/kazuho/picojson/v1.3.0/picojson.h -O /usr/local/include/picojson.h

## 2. Build and Install Mesos
Next we'll follow the standard Mesos installation instructions, but pass a few flags to configure to use our installed libraries instead of the mesos bundled ones:

```
# Download Mesos source
$ git clone git://git.apache.org/mesos.git -b 0.26.0
$ cd mesos

# Configure and build.
$ ./bootstrap
$ mkdir build
$ cd build
$ ../configure --with-protobuf=/usr --with-boost=/usr --with-glog=/usr
$ make
$ sudo make install
```

## 3. Build and Install Netmodules
```
# Download netmodules source
$ git clone https://github.com/mesosphere/net-modules.git -b integration/0.26
$ cd net-modules/isolator

# Configure and build
$ ./bootstrap
$ mkdir build
$ cd build
$ ../configure --with-mesos=/usr/local --with-protobuf=/usr
$ make
$ sudo make install
```

## 4. Launch Mesos-Slave 
```
$ sudo ETCD_AUTHORITY=<ETCD-IP:PORT> /usr/local/sbin/mesos-slave \
--master=<MASTER-IP:PORT> \
--modules=file:///calico/modules.json \
--isolation=com_mesosphere_mesos_NetworkIsolator \
--hooks=com_mesosphere_mesos_NetworkHook
```
We provide the `ETCD_AUTHORITY` environment to variable here to allow the  `calico_mesos` plugin to function properly when called by `mesos-slave`. Be sure to replace it with the address of your running etcd server. See our [Prepare Core Services for Mesos + Calico Deployment tutorial](PrepareCoreServices.md#3-launch-etcd) for info on how to launch etcd. 

Be sure to direct Mesos to the correct path of your `modules.json` file, or [create one if you haven't already done so](ManualInstallCalico.md#create-the-modulesjson-configuration-file).

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/ManualInstallNetmodules.md?pixel)](https://github.com/igrigorik/ga-beacon)
