# Manually Add Calico Networking to Mesos
This guide will walk you through manually adding Calico networking to your Mesos deployment. You must follow these steps on *each Agent in your cluster*. 

## Download the Calico Mesos Plugin
The Calico-Mesos plugin is available for download from the [calico-mesos repository releases](https://github.com/projectcalico/calico-mesos/releases). In this example, we will install the binary in the `/calico` directory.

    $ wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.1/calico_mesos
    $ chmod +x calico_mesos
    $ sudo mkdir /calico
    $ sudo mv calico_mesos /calico/calico_mesos

## Create the modules.json Configuration File
To enable Calico networking in Mesos, you must create a `modules.json` file. When provided to the Mesos Agent process, this file will connect Mesos with the Net-Modules libraries as well as the Calico networking plugin, thus allowing Calico to receive networking events from Mesos.

    $ cat > /calico/modules.json <<EOF
    {
      "libraries": [
        {
          "file": "/opt/net-modules/libmesos_network_isolator.so", 
          "modules": [
            {
              "name": "com_mesosphere_mesos_NetworkIsolator", 
              "parameters": [
                {
                  "key": "isolator_command", 
                  "value": "/calico/calico_mesos"
                },
                {
                  "key": "ipam_command", 
                  "value": "/calico/calico_mesos"
                }
              ]
            },
            {
              "name": "com_mesosphere_mesos_NetworkHook" 
            }
          ]
        }
      ]
    }
    EOF

## Run Calico Node
The last component required for Calico networking in Mesos is `calico-node`, a Docker image containing Calico's core routing processes.
 
`calico-node` can easily be launched via `calicoctl`, Calico's command line tool. When doing so, we must point `calicoctl` to our running instance of etcd, by setting the `ECTD_AUTHORITY` environment variable.

> Follow our [Core Services Preparation Guide](PrepareCoreServices.md) if you do not already have an instance of etcd running.

    $ wget https://github.com/projectcalico/calico-docker/releases/download/v0.9.0/calicoctl
    $ chmod +x calicoctl
    $ sudo ETCD_AUTHORITY=<IP of host with etcd>:4001 ./calicoctl node
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/ManualInstallCalico.md?pixel)](https://github.com/igrigorik/ga-beacon)