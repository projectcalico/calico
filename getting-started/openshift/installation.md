---
title: Install an OpenShift v4 cluster with Calico
description: Install Calico on an OpenShift v4 cluster.
canonical_url: '/getting-started/openshift/installation'
---

### Big picture

Install an OpenShift v4 cluster with {{site.prodname}}.

### Value

Augments the applicable steps in the {% include open-new-window.html text='OpenShift documentation' url='https://cloud.redhat.com/openshift/install' %}
to install {{site.prodname}}.

### How to

#### Before you begin

- Ensure that your environment meets the {{site.prodname}} [system requirements]({{site.baseurl}}/getting-started/openshift/requirements).

- **If installing on AWS**, ensure that you have {% include open-new-window.html text='configured an AWS account' url='https://docs.openshift.com/container-platform/4.2/installing/installing_aws/installing-aws-account.html' %} appropriate for OpenShift v4,
  and have {% include open-new-window.html text='set up your AWS credentials' url='https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html' %}.
  Note that the OpenShift installer supports a subset of {% include open-new-window.html text='AWS regions' url='https://docs.openshift.com/container-platform/4.2/installing/installing_aws/installing-aws-account.html#installation-aws-regions_installing-aws-account' %}.

- Ensure that you have a {% include open-new-window.html text='RedHat account' url='https://cloud.redhat.com/' %}. A RedHat account is required to obtain the pull secret necessary to provision an OpenShift cluster.

- Ensure that you have installed the OpenShift installer **v4.2 or later** and OpenShift command line interface from {% include open-new-window.html text='cloud.redhat.com' url='https://cloud.redhat.com/openshift/install/aws/installer-provisioned' %}.

- Ensure that you have {% include open-new-window.html text='generated a local SSH private key' url='https://docs.openshift.com/container-platform/4.1/installing/installing_aws/installing-aws-default.html#ssh-agent-using_installing-aws-default' %} and have added it to your ssh-agent

#### Create a configuration file for the OpenShift installer

First, create a staging directory for the installation. This directory will contain the configuration file, along with cluster state files, that OpenShift installer will create:

```
mkdir openshift-tigera-install && cd openshift-tigera-install
```

Now run OpenShift installer to create a default configuration file:

```
openshift-install create install-config
```

> **Note**: Refer to the {% include open-new-window.html text='OpenShift installer documentation' url='https://cloud.redhat.com/openshift/install' %} for more information
> about the installer and any configuration changes required for your platform.
{: .alert .alert-info}

Once the installer has finished, your staging directory will contain the configuration file `install-config.yaml`.

#### Update the configuration file to use {{site.prodname}}

Override the OpenShift networking to use Calico and update the AWS instance types to meet the [system requirements]({{site.baseurl}}/getting-started/openshift/requirements):

```bash
sed -i 's/OpenShiftSDN/Calico/' install-config.yaml
```

#### Generate the install manifests

Now generate the Kubernetes manifests using your configuration file:

```bash
openshift-install create manifests
```

Download the {{site.prodname}} manifests for OpenShift and add them to the generated manifests directory:

```bash
curl {{ "/manifests/ocp/crds/01-crd-installation.yaml" | absolute_url }} -o manifests/01-crd-installation.yaml
curl {{ "/manifests/ocp/crds/01-crd-tigerastatus.yaml" | absolute_url }} -o manifests/01-crd-tigerastatus.yaml
{%- for data in site.static_files %}
{%- if data.path contains '/manifests/ocp/crds/calico' %}
curl {{ data.path | absolute_url }} -o manifests/{{data.name}}
{%- endif -%}
{% endfor %}
curl {{ "/manifests/ocp/tigera-operator/00-namespace-tigera-operator.yaml" | absolute_url }} -o manifests/00-namespace-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-rolebinding-tigera-operator.yaml" | absolute_url }} -o manifests/02-rolebinding-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-role-tigera-operator.yaml" | absolute_url }} -o manifests/02-role-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-serviceaccount-tigera-operator.yaml" | absolute_url }} -o manifests/02-serviceaccount-tigera-operator.yaml
curl {{ "/manifests/ocp/tigera-operator/02-configmap-calicoctl-resources.yaml" | absolute_url }} -o manifests/02-configmap-calicoctl-resources.yaml
curl {{ "/manifests/ocp/tigera-operator/02-configmap-tigera-install-script.yaml" | absolute_url }} -o manifests/02-configmap-tigera-install-script.yaml
curl {{ "/manifests/ocp/tigera-operator/02-tigera-operator.yaml" | absolute_url }} -o manifests/02-tigera-operator.yaml
curl {{ "/manifests/ocp/01-cr-installation.yaml" | absolute_url }} -o manifests/01-cr-installation.yaml
```

#### Create the cluster

Start the cluster creation with the following command and wait for it to complete.

```bash
openshift-install create cluster
```

Once the above command is complete, you can verify {{site.prodname}} is installed by verifying the components are available with the following command.

```
oc get tigerastatus
```

> **Note**: To get more information, add `-o yaml` to the above command.

### Above and beyond

- [Get started with Kubernetes network policy]({{site.baseurl}}/security/kubernetes-network-policy)
- [Get started with Calico network policy]({{site.baseurl}}/security/calico-network-policy)
- [Enable default deny for Kubernetes pods]({{site.baseurl}}/security/kubernetes-default-deny)
