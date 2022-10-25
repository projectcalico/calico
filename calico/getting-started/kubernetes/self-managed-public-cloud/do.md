---
title: Self-managed Kubernetes in DigitalOcean (DO)
description: Use Calico with a self-managed Kubernetes cluster in DigitalOcean (DO).
---

### Big picture

This tutorial creates a self-managed Kubernetes cluster (1 Master, 2 Worker nodes) using {{site.prodname}} networking in DigitalOcean.

### Value

Managing your own Kubernetes cluster (as opposed to using a managed-Kubernetes service like EKS), gives you the most flexibility in configuring {{site.prodname}} and Kubernetes. {{site.prodname}} combines flexible networking capabilities with "run-anywhere" security enforcement to provide a solution with native Linux kernel performance and true cloud-native scalability.

### Concepts

Kubernetes Operations (kops) is a cluster management tool that handles provisioning cluster VMs and installing Kubernetes. It has built-in support for using {{site.prodname}} as the Kubernetes networking provider.

> **Note**: Kops support for DigitalOcean is currently in the early stages of development and subject to change.
>
> More information can be viewed {% include open-new-window.html text='at this link.' url='https://kops.sigs.k8s.io/getting_started/digitalocean/' %}
{: .alert .alert-info}

### Before you begin...

- Install {% include open-new-window.html text='kubectl' url='https://kubernetes.io/docs/tasks/tools/install-kubectl/' %}
- Install {% include open-new-window.html text='kops' url='https://kops.sigs.k8s.io/install/' %}

### How to

There are many ways to install and manage Kubernetes in DO. Using Kubernetes Operations (kops) is a good default choice for most people, as it gives you access to all of {{site.prodname}}’s [flexible and powerful networking features]({{site.baseurl}}/networking). However, there are other options that may work better for your environment.

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:IPIP,Routing:BGP,Datastore:kubernetes' %}

#### Generate your DigitalOcean API token

An API token is needed by kops for the CRUD (Create, Read, Update and Delete) operations necessary for resources in your DigitalOcean account.
Use {% include open-new-window.html text='this link' url='https://www.digitalocean.com/docs/apis-clis/api/create-personal-access-token/' %} to generate your API token and then export it as an environment variable. 

```bash
export DIGITALOCEAN_ACCESS_TOKEN=<API_ACCESS_TOKEN>
```

#### Create an object storage

DigitalOcean provides an S3 compatible storage API that Kops uses object storage to save your cluster status.
You should create a Space using {% include open-new-window.html text='this link' url='https://www.digitalocean.com/docs/spaces/how-to/create/' %} and export it.

```bash
export KOPS_STATE_STORE=do://<your-space-name>
export S3_ENDPOINT=<ENDPOINT>
```
> **Note**: Using FQDN for `S3_ENDPOINT` causes an error.
> If your Space FQDN is `my-test-space.nyc3.digitaloceanspaces.com` just export `my-test-space` as `<your-space-name>` .
{: .alert .alert-info }

#### Generate an API key for object storage

Access to object storage requires an API key.
Follow this {% include open-new-window.html text='tutorial' url='https://www.digitalocean.com/docs/spaces/how-to/manage-access/' %} and generate your keys then export them as environment variables.

```bash
export S3_ACCESS_KEY_ID=<ACCESS_KEY_ID>
export S3_SECRET_ACCESS_KEY=<SECRET_ACCESS_KEY>
```

#### Enable kops alpha feature

Enable alpha feature support using `KOPS_FEATURE_FLAGS` environment variable.

```bash
    export KOPS_FEATURE_FLAGS="AlphaAllowDO"
```

#### Create your cluster

Kops supports various options that enables you to customize your cluster the way you like.

1. Add Calico to your cluster using `--networking=calico`.
1. Kops requires an external DNS server in order to create a cluster, by adding `.k8s.local` suffix to `--name=` option
you generate a {% include open-new-window.html text='gossip' url='https://kops.sigs.k8s.io/gossip/' %} DNS to bypass this requirement.

> You can view a complete list of options supported by kops
> {% include open-new-window.html text='in this link.' url='https://kops.sigs.k8s.io/cli/kops_create_cluster/#options' %}
{: .alert .alert-info }

```bash
    kops create cluster --cloud=digitalocean --name=calico-demo.k8s.local \
    --networking=calico --master-zones=nyc1 --zones=nyc1 \
    --master-count=1 --api-loadbalancer-type=public \
    --node-size=s-1vcpu-2gb --image=ubuntu-20-04-x64 --yes
```

You can further customize the {{site.prodname}} install with {% include open-new-window.html text='options listed in the kops documentation' url='https://kops.sigs.k8s.io/networking/calico' %}. 

### Cleanup

If you wish to remove resources created by this tutorial

```bash
kops delete cluster calico-demo.k8s.local --yes
```

Use the DigitalOcean web UI to remove the API tokens and Space you created.

### Next steps

**Required**
- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)

**Recommended**
- [Try out {{site.prodname}} network policy]({{site.baseurl}}/security/calico-network-policy)
