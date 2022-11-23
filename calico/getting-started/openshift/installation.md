---
title: Install an OpenShift 4 cluster with Calico
description: Install Calico on an OpenShift 4 cluster.
canonical_url: '/getting-started/openshift/installation'
---

### Big picture

Install an OpenShift 4 cluster with {{site.prodname}}.

### Value

Augments the applicable steps in the {% include open-new-window.html text='OpenShift documentation' url='https://cloud.redhat.com/openshift/install' %}
to install {{site.prodname}}.

### How to

#### Before you begin

- Ensure that your environment meets the {{site.prodname}} [system requirements]({{site.baseurl}}/getting-started/openshift/requirements).

- **If installing on AWS**, ensure that you have {% include open-new-window.html text='configured an AWS account' url='https://docs.openshift.com/container-platform/4.3/installing/installing_aws/installing-aws-account.html' %} appropriate for OpenShift 4,
  and have {% include open-new-window.html text='set up your AWS credentials' url='https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html' %}.
  Note that the OpenShift installer supports a subset of {% include open-new-window.html text='AWS regions' url='https://docs.openshift.com/container-platform/4.3/installing/installing_aws/installing-aws-account.html#installation-aws-regions_installing-aws-account' %}.

- Ensure that you have a {% include open-new-window.html text='RedHat account' url='https://cloud.redhat.com/' %}. A RedHat account is required to obtain the pull secret necessary to provision an OpenShift cluster.

- Ensure that you have installed the OpenShift installer **v4.3 or later** and OpenShift command line interface from {% include open-new-window.html text='cloud.redhat.com' url='https://cloud.redhat.com/openshift/install/aws/installer-provisioned' %}.

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

{% include content/install-openshift-manifests.md %}

#### Optionally provide additional configuration

You may want to provide Calico with additional configuration at install-time. For example, BGP configuration or peers.
You can use a Kubernetes ConfigMap with your desired Calico resources in order to set configuration as part of the installation.
If you do not need to provide additional configuration, you can skip this section.

To include [Calico resources]({{site.baseurl}}/reference/resources) during installation, edit `manifests/02-configmap-calico-resources.yaml` in order to add your own configuration.

> **Note**: If you have a directory with the Calico resources, you can create the file with the command:
> ```
> oc create configmap -n tigera-operator calico-resources \
>   --from-file=<resource-directory> --dry-run -o yaml \
>   > manifests/02-configmap-calico-resources.yaml
> ```
> With recent versions of oc it is necessary to have a kubeconfig configured or add `--server='127.0.0.1:443'`
> even though it is not used.
{: .alert .alert-info}

> **Note**: If you have provided a `calico-resources` configmap and the tigera-operator pod fails to come up with `Init:CrashLoopBackOff`,
> check the output of the init-container with `oc logs -n tigera-operator -l k8s-app=tigera-operator -c create-initial-resources`.
{: .alert .alert-info}

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

#### Optionally integrate with Operator Lifecycle Manager (OLM)

In OpenShift Container Platform, the [Operator Lifecycle Manager](https://docs.openshift.com/container-platform/4.4/operators/understanding_olm/olm-understanding-olm.html#olm-overview_olm-understanding-olm){:target="_blank"} helps
cluster administrators manage the lifecycle of operators in their cluster. Managing the {{site.prodname}}
operator with OLM gives administrators a single place to manage operators.

In order to register the running {{site.prodname}} operator with OLM, first you will need to create an OperatorGroup for the operator:

```bash
oc apply -f - <<EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: tigera-operator
  namespace: tigera-operator
spec:
  targetNamespaces:
    - tigera-operator
EOF
```

Next, you will create a Subscription to the operator. By subscribing to the operator package, the {{site.prodname}} operator will be managed by OLM.
{% assign operator_version = site.data.versions.first.tigera-operator.version %}
{% assign operator_version_parts = operator_version | split: "." %}

```bash
oc apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: tigera-operator
  namespace: tigera-operator
spec:
  channel: release-{{operator_version_parts[0]}}.{{operator_version_parts[1]}}
  installPlanApproval: Manual
  name: tigera-operator
  source: certified-operators
  sourceNamespace: openshift-marketplace
  startingCSV: tigera-operator.{{operator_version}}
EOF
```

Finally, log in to the OpenShift console, navigate to the Installed Operators section and approve the Install Plan for the operator.

> **Note**: This may trigger the operator deployment and all of its resources (pods, deployments, etc.) to be recreated.

The OpenShift console provides an interface for editing the operator installation, viewing the operator's status, and more.

### Next steps 

**Required**

- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended - Networking**

- If you are using the default BGP networking with full-mesh node-to-node peering with no encapsulation, go to [Configure BGP peering]({{site.baseurl}}/networking/bgp) to get traffic flowing between pods.
- If you are unsure about networking options, or want to implement encapsulation (overlay networking), see [Determine best networking option]({{site.baseurl}}/networking/determine-best-networking).

**Recommended - Security**

- [Secure Calico component communications]({{site.baseurl}}/security/comms/crypto-auth)
- [Secure hosts by installing Calico on hosts]({{site.baseurl}}/getting-started/bare-metal/about)
- [Secure pods with Calico network policy]({{site.baseurl}}/security/calico-network-policy)
- If you are using {{site.prodname}} with Istio service mesh, get started here: [Enable application layer policy]({{site.baseurl}}/security/app-layer-policy)
