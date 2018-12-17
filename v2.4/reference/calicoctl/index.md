---
title: calicoctl user reference
canonical_url: 'https://docs.projectcalico.org/v3.4/reference/calicoctl/'
---

The command line tool, `calicoctl`, makes it easy to manage Calico network
and security policy.  

It can be downloaded from the [releases page of the 
calicoctl repository](https://github.com/projectcalico/calicoctl/releases/latest/). 

Alternatively, you can run it as a docker container if you want to - the image 
is `calico/ctl` on Dockerhub and Quay but note that due to limitations imposed 
by running in a container, this will not have the full functionality of the 
binary running directly on the host (notably the `calicoctl node ...` commands 
do not work in a container).

Follow the setup in the [Configuring calicoctl]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) section.
This section describes how to do the initial setup of calicoctl, configuring
the connection information for your Calico datastore.

The calicoctl command line interface provides a number of resource management
commands to allow you to create, modify, delete and view the different Calico
resources.

The full list of commands is described in the 
[Command Reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/)
section.

The full list of resources that can be managed, including a description of each,
is described in the [Resource Definitions]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/)
section.
