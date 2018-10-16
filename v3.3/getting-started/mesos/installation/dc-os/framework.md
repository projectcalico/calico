---
title: Calico DC/OS Installation Guide
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/installation/dc-os/framework'
---

The following guide walks through installing {{site.prodname}} for DC/OS using the Universe
package repository.

#### Installing etcd

To get started, first install etcd from Universe:

![Installing etcd from Universe]({{site.baseurl}}/images/dcos-install-etcd.gif)

#### Installing Calico

Then install {{site.prodname}} from Universe.

![Installing {{site.prodname}} from Universe]({{site.baseurl}}/images/dcos-install-calico.gif)

It will take a few minutes for {{site.prodname}} to finish
installing on your cluster. You can check the status of the installation by
visiting {{site.prodname}}'s web status interface:

 - Go to the **Services** tab
 - Select "calico-install-framework" in the list of running services
   (note that it may take a few minutes for {{site.prodname}}
    to appear).
 - Once the {{site.prodname}} service is `Healthy`,
   Select the "calico-install-framework" task.
 - Click the Endpoint URL to open the {{site.prodname}} status page in a new tab.

![sample demonstrating how to locate the framework service page]({{site.baseurl}}/images/dcos-calico-status.gif)

## Further Reading

This concludes the installation of {{site.prodname}} for DC/OS! Before you start
launching IP-per-container applications with {{site.prodname}} policy,
review the following information which may apply to your deployment.

#### Amazon Web Services

DC/OS users on Amazon Web Services should view [AWS configuration guide](../../../../reference/public-cloud/aws) for information on how to configure AWS networking for use with {{site.prodname}}.

#### Note on Cluster Impact

The Installation method detailed above will affect availability of all agents
in the cluster in order to work around two limitations in DC/OS 1.8:

1. [Mesos-Agents require a restart to detect newly added CNI networks](https://issues.apache.org/jira/browse/MESOS-6567).
2. [DC/OS does not configure Docker with a Cluster-Store](https://dcosjira.atlassian.net/browse/DCOS-155)
a requirement for Multi-host docker networking.

Because of these two limitations, {{site.prodname}}-DC/OS will restart each agent process
and restart each docker daemon. Learn how to handle this installation steps manually
and prevent cluster availability impact by viewing the [Custom Install Guide](custom).

#### Deploying Applications

Once installed, see the [standard usage guides]({{site.baseurl}}/{{page.version}}/getting-started/mesos#tutorials)
