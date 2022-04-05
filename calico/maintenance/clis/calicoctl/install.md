---
title: Install calicoctl
description: Install the CLI for Calico.
canonical_url: '/maintenance/clis/calicoctl/install'
---

### Big picture

This guide helps you install the `calicoctl` command line tool to manage {{site.prodname}} resources 
and perform administrative functions.

### Value 

The `calicoctl` command line tool is required in order to use many of {{site.prodname}}'s features. It 
is used to manage {{site.prodname}} policies and configuration, as well as view detailed cluster status.

### Concepts

#### API groups

All Kubernetes resources belong to an API group. The API group is indicated by the resource's `apiVersion`. For example, {{site.prodname}}
uses resources in the `projectcalico.org/v3` API group for configuration, and the operator uses resources in the `operator.tigera.io/v1` API group.

You can read more about API groups in [the Kubernetes documentation](https://kubernetes.io/docs/reference/using-api/#api-groups).

#### calicoctl and kubectl

In order to manage {{site.prodname}} APIs in the `projectcalico.org/v3` API group, you should use `calicoctl`. This is because
`calicoctl` provides important validation and defaulting for these resources that is not available in `kubectl`. However, `kubectl`
should still be used to manage other Kubernetes resources.

> **Note**: If you would like to use `kubectl` to manage `projectcalico.org/v3` API resources, you can use the 
>           [Calico API server]({{site.baseurl}}/maintenance/install-apiserver).
{: .alert .alert-info}

> **Warning**: Never modify resources in the `crd.projectcalico.org` API group directly. These are internal data representations 
>              and modifying them directly may result in unexpected behavior.
{: .alert .alert-warning}

In addition to resource management, `calicoctl` also enables other {{site.prodname}} administrative tasks such as viewing IP pool utilization
and BGP status.

#### Datastore

{{site.prodname}} objects are stored in one of two datastores, either etcd or Kubernetes. The choice of datastore is determined at the time {{site.prodname}}
is installed. Typically for Kubernetes installations the Kubernetes datastore is the default.

You can run `calicoctl` on any host with network access to the {{site.prodname}} datastore as either a binary or a container.
For step-by-step instructions, refer to the section that corresponds to your desired deployment.

<!--- Change download URL to latest release if user browsing master branch.  --->
<!--- For master, we hard-code a version since we don't host master releases of calicoctl.  --->
{%- if page.version == "master" -%}
{% assign url = "https://github.com/projectcalico/calico/releases/latest/download" %}
{% else %}
{% assign url = "https://github.com/projectcalico/calico/releases/download/" | append: site.data.versions.first.components.calicoctl.version %}
{% endif %}


### How to

> **Note**: Make sure you always install the version of `calicoctl` that matches the version of {{site.prodname}} running on your cluster.
{: .alert .alert-info}

- [Install calicoctl as a binary on a single host](#install-calicoctl-as-a-binary-on-a-single-host)
- [Install calicoctl as a kubectl plugin on a single host](#install-calicoctl-as-a-kubectl-plugin-on-a-single-host)
- [Install calicoctl as a container on a single host](#install-calicoctl-as-a-container-on-a-single-host)
- [Install calicoctl as a Kubernetes pod](#install-calicoctl-as-a-kubernetes-pod)

#### Install calicoctl as a binary on a single host

{% tabs %}
<label:Linux,active:true>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-linux-amd64 -o calicoctl
   ```

1. Set the file to be executable.

   ```bash
   chmod +x ./calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}

%>
<label:Mac OSX>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-darwin-amd64 -o calicoctl
   ```

1. Set the file to be executable.

   ```bash
   chmod +x calicoctl
   ```

   > **Note**: If you are faced with `cannot be opened because the developer cannot be verified` error when using `caicoctl` for the first time.
   > go to `Applications > System Prefences > Security & Privacy` in the `General` tab at the bottom of the window click `Allow anyway`.
   >
   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
%>
<label:Windows>
<%

1. Use the following PowerShell command to download the `calicoctl` binary.

   > **Tip**: Consider running PowerShell as administrator and navigating
   > to a location that's in your `PATH`. For example, `C:\Windows`.
   {: .alert .alert-success}

```
Invoke-WebRequest -Uri "{{ url }}/calicoctl-windows-amd64.exe -OutFile "calicoctl.exe" 
```

%>
<label:Linux PPC64le>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-linux-ppc64le -o calicoctl
   ```

1. Set the file to be executable.

   ```bash
   chmod +x calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
%>
<label:Linux arm64>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-linux-arm64 -o calicoctl
   ```

1. Set the file to be executable.

   ```bash
   chmod +x calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
%>
{% endtabs %}

#### Install calicoctl as a kubectl plugin on a single host

{% tabs %}
<label:Linux,active:true>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-linux-amd64 -o kubectl-calico
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
<label:Mac OSX>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-darwin-amd64 -o kubectl-calico
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If you are faced with `cannot be opened because the developer cannot be verified` error when using `caicoctl` for the first time.
   > go to `Applications > System Prefences > Security & Privacy` in the `General` tab at the bottom of the window click `Allow anyway`.
   >
   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
<label:Windows>
<%

1. Use the following PowerShell command to download the `calicoctl` binary.

   > **Tip**: Consider running PowerShell as administrator and navigating
   > to a location that's in your `PATH`. For example, `C:\Windows`.
   {: .alert .alert-success}

```
Invoke-WebRequest -Uri "{{ url }}/calicoctl-windows-amd64.exe -OutFile "kubectl-calico.exe" 
```

%>
<label:Linux PPC64le>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-linux-ppc64le -o kubectl-calico
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
<label:Linux arm64>
<%
1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -L {{ url }}/calicoctl-linux-arm64 -o kubectl-calico
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

%>
{% endtabs %}

Verify the plugin works.

   ```
   kubectl calico -h
   ```

You can now run any `calicoctl` subcommands through `kubectl calico`.

> **Note**: If you run these commands from your local machine (instead of a host node), some of
> the node related subcommands will not work (like node status).
{: .alert .alert-info}

#### Install calicoctl as a container on a single host

To install `calicoctl` as a container on a single host, log into the
target host and issue the following command.

```bash
docker pull {{page.registry}}{{page.imageNames["calicoctl"]}}:{{site.data.versions.first.title}}
```

#### Install calicoctl as a Kubernetes pod


Use the YAML that matches your datastore type to deploy the `calicoctl` container to your nodes.

- **etcd**

  ```bash
  kubectl apply -f {{ "/manifests/calicoctl-etcd.yaml" | absolute_url }}
  ```

  > **Note**: You can also
  > [view the YAML in a new tab]({{ "/manifests/calicoctl-etcd.yaml" | absolute_url }}){:target="_blank"}.
  {: .alert .alert-info}

- **Kubernetes API datastore**

  ```bash
  kubectl apply -f {{ "/manifests/calicoctl.yaml" | absolute_url }}
  ```

  > **Note**: You can also
  > [view the YAML in a new tab]({{ "/manifests/calicoctl.yaml" | absolute_url }}){:target="_blank"}.
  {: .alert .alert-info}

You can then run commands using kubectl as shown below.

```bash
kubectl exec -ti -n kube-system calicoctl -- /calicoctl get profiles -o wide
```

An example response follows.

```
NAME                 TAGS
kns.default          kns.default
kns.kube-system      kns.kube-system
```
{: .no-select-button}

We recommend setting an alias as follows.

```bash
alias calicoctl="kubectl exec -i -n kube-system calicoctl -- /calicoctl"
```

   > **Note**: In order to use the `calicoctl` alias
   > when reading manifests, redirect the file into stdin, for example:
   > ```bash
   > calicoctl create -f - < my_manifest.yaml
   > ```
   {: .alert .alert-info}

**Next step**:

[Configure `calicoctl` to connect to your datastore](configure).
